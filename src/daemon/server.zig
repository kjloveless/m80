const std = @import("std");
const net = @import("../util/net.zig");
const sync = @import("../util/sync.zig");
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const core = @import("../core.zig");
const config = @import("../core/config.zig");
const dns = @import("../net/dns.zig");
const log = @import("../util/log.zig");
const protocol = @import("protocol.zig");

const SocketKind = enum {
    control,
    register,
    guest,
};

const VmRecord = struct {
    name: []const u8,
    guest_cid: u32,
    guest_socket_path: []const u8,
    memory_mb: u32,
    cpu_cores: u16,
    started_at: i64,
    network_mode: config.NetworkMode,
    network_services: []const config.Service,
    network_metadata_file: ?[]const u8,
    network_allowed_domains: []const []const u8,
    network_allowed_ips: []const []const u8,
    mounts: []const []const u8,
    shutdown_requested: bool = false,
};

const TcpStream = struct {
    guest_cid: u32,
    stream: std.Io.net.Stream,
};

const PosixIpAddress = extern union {
    any: std.posix.sockaddr,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,
};

const DaemonState = struct {
    allocator: std.mem.Allocator,
    mutex: sync.Mutex = .{},
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    next_cid: u32 = 16,
    next_tcp_stream_id: u64 = 1,
    start_guest_listeners: bool = false,
    vms: std.StringHashMap(VmRecord),
    tcp_streams: std.AutoHashMap(u64, TcpStream),
    dns_ip_allowances: std.StringHashMap(i64),

    fn init(allocator: std.mem.Allocator) DaemonState {
        return .{
            .allocator = allocator,
            .vms = std.StringHashMap(VmRecord).init(allocator),
            .tcp_streams = std.AutoHashMap(u64, TcpStream).init(allocator),
            .dns_ip_allowances = std.StringHashMap(i64).init(allocator),
        };
    }

    fn deinit(self: *DaemonState) void {
        var allowance_it = self.dns_ip_allowances.iterator();
        while (allowance_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.dns_ip_allowances.deinit();

        var stream_it = self.tcp_streams.iterator();
        while (stream_it.next()) |entry| {
            closeTcpStream(entry.value_ptr.stream);
        }
        self.tcp_streams.deinit();

        var it = self.vms.iterator();
        while (it.next()) |entry| {
            freeVmRecord(self.allocator, entry.value_ptr.*);
        }
        self.vms.deinit();
    }

    fn hasGuestCid(self: *DaemonState, guest_cid: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.vms.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.guest_cid == guest_cid) return true;
        }
        return false;
    }

    fn cloneByCid(self: *DaemonState, guest_cid: u32, allocator: std.mem.Allocator) !?VmRecord {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.vms.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.guest_cid == guest_cid) {
                return try cloneVmRecord(allocator, entry.value_ptr.*);
            }
        }
        return null;
    }

    fn dnsAllowanceKeyAlloc(self: *DaemonState, guest_cid: u32, ip: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{d}|{s}", .{ guest_cid, ip });
    }

    fn purgeExpiredDnsAllowancesLocked(self: *DaemonState, now_ms: i64) void {
        var expired: std.ArrayList([]const u8) = .empty;
        defer expired.deinit(self.allocator);

        var it = self.dns_ip_allowances.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* <= now_ms) {
                expired.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }

        for (expired.items) |key| {
            if (self.dns_ip_allowances.fetchRemove(key)) |entry| {
                self.allocator.free(entry.key);
            }
        }
    }

    fn rememberDnsIp(self: *DaemonState, guest_cid: u32, ip: []const u8, ttl_secs: u32) !void {
        const ttl_clamped = @max(@as(u32, 1), @min(ttl_secs, @as(u32, 300)));
        const expires_at_ms = sync.milliTimestamp() + (@as(i64, ttl_clamped) * std.time.ms_per_s);
        const key = try self.dnsAllowanceKeyAlloc(guest_cid, ip);
        errdefer self.allocator.free(key);

        self.mutex.lock();
        defer self.mutex.unlock();
        self.purgeExpiredDnsAllowancesLocked(sync.milliTimestamp());
        const result = try self.dns_ip_allowances.getOrPut(key);
        if (result.found_existing) {
            self.allocator.free(key);
        }
        result.value_ptr.* = expires_at_ms;
    }

    fn hasDnsIpAllowance(self: *DaemonState, guest_cid: u32, ip: []const u8) bool {
        var ip_buf: [64]u8 = undefined;
        const canonical_ip = canonicalIpText(ip, &ip_buf) orelse return false;
        const key = self.dnsAllowanceKeyAlloc(guest_cid, canonical_ip) catch return false;
        defer self.allocator.free(key);

        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = sync.milliTimestamp();
        if (self.dns_ip_allowances.get(key)) |expires_at_ms| {
            return expires_at_ms > now_ms;
        }
        return false;
    }
};

const SocketServerCtx = struct {
    state: *DaemonState,
    kind: SocketKind,
    path: []const u8,
    guest_cid: ?u32 = null,
    unlink_on_exit: bool = false,
    owned_path: bool = false,
};

const ConnectionCtx = struct {
    state: *DaemonState,
    kind: SocketKind,
    guest_cid: ?u32,
    stream: net.Stream,
};

fn freeStringList(allocator: std.mem.Allocator, list: []const []const u8) void {
    for (list) |value| allocator.free(value);
    if (list.len > 0) allocator.free(list);
}

fn cloneStringList(allocator: std.mem.Allocator, list: []const []const u8) ![]const []const u8 {
    if (list.len == 0) return &[_][]const u8{};
    const result = try allocator.alloc([]const u8, list.len);
    var filled: usize = 0;
    errdefer {
        for (result[0..filled]) |value| allocator.free(value);
        allocator.free(result);
    }
    for (list, 0..) |value, i| {
        result[i] = try allocator.dupe(u8, value);
        filled += 1;
    }
    return result;
}

fn cloneServiceList(allocator: std.mem.Allocator, list: []const config.Service) ![]const config.Service {
    if (list.len == 0) return &[_]config.Service{};
    const result = try allocator.alloc(config.Service, list.len);
    @memcpy(result, list);
    return result;
}

fn freeVmRecord(allocator: std.mem.Allocator, record: VmRecord) void {
    allocator.free(record.name);
    allocator.free(record.guest_socket_path);
    if (record.network_metadata_file) |path| allocator.free(path);
    if (record.network_services.len > 0) allocator.free(record.network_services);
    freeStringList(allocator, record.network_allowed_domains);
    freeStringList(allocator, record.network_allowed_ips);
    freeStringList(allocator, record.mounts);
}

fn cloneVmRecord(allocator: std.mem.Allocator, record: VmRecord) !VmRecord {
    var cloned = VmRecord{
        .name = try allocator.dupe(u8, record.name),
        .guest_cid = record.guest_cid,
        .guest_socket_path = "",
        .memory_mb = record.memory_mb,
        .cpu_cores = record.cpu_cores,
        .started_at = record.started_at,
        .network_mode = record.network_mode,
        .network_services = &[_]config.Service{},
        .network_metadata_file = null,
        .network_allowed_domains = &[_][]const u8{},
        .network_allowed_ips = &[_][]const u8{},
        .mounts = &[_][]const u8{},
        .shutdown_requested = record.shutdown_requested,
    };
    errdefer freeVmRecord(allocator, cloned);
    cloned.guest_socket_path = try allocator.dupe(u8, record.guest_socket_path);
    cloned.network_services = try cloneServiceList(allocator, record.network_services);
    cloned.network_metadata_file = if (record.network_metadata_file) |path| try allocator.dupe(u8, path) else null;
    cloned.network_allowed_domains = try cloneStringList(allocator, record.network_allowed_domains);
    cloned.network_allowed_ips = try cloneStringList(allocator, record.network_allowed_ips);
    cloned.mounts = try cloneStringList(allocator, record.mounts);
    return cloned;
}

fn writePidFile(path: []const u8) !void {
    const pid = if (builtin.os.tag == .windows) 0 else std.c.getpid();
    var file = if (fs.path.isAbsolute(path))
        try fs.createFileAbsolute(path, .{ .truncate = true })
    else
        try fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buf: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    try file.writeAll(text);
}

fn chmodPath(path: []const u8, mode: std.posix.mode_t) void {
    if (builtin.os.tag == .windows) return;
    fs.chmodAt(std.posix.AT.FDCWD, path, mode, 0) catch |e| {
        log.warn("chmod failed path={s}: {s}", .{ path, @errorName(e) });
    };
}

fn jsonObject(value: std.json.Value) ?std.json.ObjectMap {
    return switch (value) {
        .object => |obj| obj,
        else => null,
    };
}

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

fn jsonInt(comptime T: type, obj: std.json.ObjectMap, key: []const u8) ?T {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .integer => |i| std.math.cast(T, i),
        else => null,
    };
}

fn jsonStringArray(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const []const u8 {
    const value = obj.get(key) orelse return &[_][]const u8{};
    return switch (value) {
        .array => |items| blk: {
            const result = try allocator.alloc([]const u8, items.items.len);
            errdefer allocator.free(result);
            var filled: usize = 0;
            errdefer {
                for (result[0..filled]) |entry| allocator.free(entry);
            }
            for (items.items, 0..) |item, i| {
                const str = switch (item) {
                    .string => |s| s,
                    else => return error.InvalidRequest,
                };
                result[i] = try allocator.dupe(u8, str);
                filled += 1;
            }
            break :blk result;
        },
        else => error.InvalidRequest,
    };
}

fn jsonServiceArray(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const config.Service {
    const value = obj.get(key) orelse return &[_]config.Service{};
    return switch (value) {
        .array => |items| blk: {
            const result = try allocator.alloc(config.Service, items.items.len);
            errdefer allocator.free(result);
            var count: usize = 0;
            for (items.items) |item| {
                const raw = switch (item) {
                    .string => |s| s,
                    else => return error.InvalidRequest,
                };
                const service = config.Service.fromString(raw) orelse return error.InvalidRequest;
                var duplicate = false;
                for (result[0..count]) |existing| {
                    if (existing == service) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;
                result[count] = service;
                count += 1;
            }
            if (count == result.len) break :blk result;
            const trimmed = try allocator.alloc(config.Service, count);
            @memcpy(trimmed, result[0..count]);
            allocator.free(result);
            break :blk trimmed;
        },
        else => error.InvalidRequest,
    };
}

fn jsonNetworkMode(obj: std.json.ObjectMap) !config.NetworkMode {
    const raw = jsonString(obj, "network_mode") orelse return .locked_down;
    return config.NetworkMode.fromString(raw) orelse error.InvalidRequest;
}

fn openFileReadAll(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    var file = if (fs.path.isAbsolute(path))
        try fs.openFileAbsolute(path, .{})
    else
        try fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, max_bytes);
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }
    return out;
}

fn hexDecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidRequest;
    const out = try allocator.alloc(u8, text.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, text) catch return error.InvalidRequest;
    return out;
}

fn waitForWritable(fd: std.posix.fd_t) !void {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = @intCast(std.c.POLL.OUT),
        .revents = 0,
    }};
    const ready = try std.posix.poll(&fds, 5000);
    if (ready == 0) return error.Timeout;
    if ((fds[0].revents & @as(i16, @intCast(std.c.POLL.ERR | std.c.POLL.HUP | std.c.POLL.NVAL))) != 0) {
        return error.BrokenPipe;
    }
}

fn writeFullFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = fs.writeFd(fd, bytes[offset..]) catch |e| switch (e) {
            error.WouldBlock => {
                try waitForWritable(fd);
                continue;
            },
            else => return e,
        };
        if (n == 0) return error.BrokenPipe;
        offset += n;
    }
}

fn removeTcpStreamsForCidLocked(state: *DaemonState, guest_cid: u32) void {
    while (true) {
        var found: ?u64 = null;
        var it = state.tcp_streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.guest_cid == guest_cid) {
                found = entry.key_ptr.*;
                break;
            }
        }
        const stream_id = found orelse return;
        if (state.tcp_streams.fetchRemove(stream_id)) |entry| {
            closeTcpStream(entry.value.stream);
        }
    }
}

fn removeDnsAllowancesForCidLocked(state: *DaemonState, guest_cid: u32) void {
    var prefix_buf: [32]u8 = undefined;
    const prefix = std.fmt.bufPrint(&prefix_buf, "{d}|", .{guest_cid}) catch return;
    var doomed: std.ArrayList([]const u8) = .empty;
    defer doomed.deinit(state.allocator);

    var it = state.dns_ip_allowances.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
            doomed.append(state.allocator, entry.key_ptr.*) catch break;
        }
    }

    for (doomed.items) |key| {
        if (state.dns_ip_allowances.fetchRemove(key)) |entry| {
            state.allocator.free(entry.key);
        }
    }
}

fn hasService(record: *const VmRecord, service: config.Service) bool {
    for (record.network_services) |candidate| {
        if (candidate == service) return true;
    }
    return false;
}

fn serviceNames(allocator: std.mem.Allocator, services: []const config.Service) ![]const []const u8 {
    const names = try allocator.alloc([]const u8, services.len);
    errdefer allocator.free(names);
    for (services, 0..) |service, i| {
        names[i] = service.toString();
    }
    return names;
}

fn buildRuntimeBody(allocator: std.mem.Allocator, record: VmRecord) ![]u8 {
    const service_names = try serviceNames(allocator, record.network_services);
    defer allocator.free(service_names);

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(.{
        .name = record.name,
        .guest_cid = record.guest_cid,
        .memory_mb = record.memory_mb,
        .cpu_cores = record.cpu_cores,
        .mounts = record.mounts,
        .network_mode = record.network_mode.toString(),
        .network_services = service_names,
        .started_at = record.started_at,
    }, .{}, &out.writer);
    return out.toOwnedSlice();
}

fn parseRequestDomain(allocator: std.mem.Allocator, request_hex: []const u8) ![]u8 {
    if (request_hex.len % 2 != 0) return error.InvalidRequest;
    const query = try allocator.alloc(u8, request_hex.len / 2);
    defer allocator.free(query);
    const decoded = std.fmt.hexToBytes(query, request_hex) catch return error.InvalidRequest;
    var domain_buf: [256]u8 = undefined;
    const domain = dns.parseQueryDomain(decoded, &domain_buf) catch return error.InvalidRequest;
    return try allocator.dupe(u8, domain);
}

fn dnsSkipName(message: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < message.len) {
        const len = message[pos];
        if (len == 0) return pos + 1;
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= message.len) return null;
            return pos + 2;
        }
        const step = 1 + @as(usize, len);
        if (pos + step > message.len) return null;
        pos += step;
    }
    return null;
}

fn dnsSkipQuestion(message: []const u8, start: usize) ?usize {
    const name_end = dnsSkipName(message, start) orelse return null;
    if (name_end + 4 > message.len) return null;
    return name_end + 4;
}

fn formatIpv6Bytes(buf: []u8, bytes: [16]u8) ?[]const u8 {
    return std.fmt.bufPrint(
        buf,
        "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
        .{
            (@as(u16, bytes[0]) << 8) | bytes[1],
            (@as(u16, bytes[2]) << 8) | bytes[3],
            (@as(u16, bytes[4]) << 8) | bytes[5],
            (@as(u16, bytes[6]) << 8) | bytes[7],
            (@as(u16, bytes[8]) << 8) | bytes[9],
            (@as(u16, bytes[10]) << 8) | bytes[11],
            (@as(u16, bytes[12]) << 8) | bytes[13],
            (@as(u16, bytes[14]) << 8) | bytes[15],
        },
    ) catch null;
}

fn canonicalIpText(ip: []const u8, buf: []u8) ?[]const u8 {
    const parsed = std.Io.net.IpAddress.parse(ip, 0) catch return null;
    return switch (parsed) {
        .ip4 => |ip4| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            ip4.bytes[0],
            ip4.bytes[1],
            ip4.bytes[2],
            ip4.bytes[3],
        }) catch null,
        .ip6 => |ip6| formatIpv6Bytes(buf, ip6.bytes),
    };
}

fn rememberDnsResponseIps(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, response_hex: []const u8) void {
    const response = hexDecodeAlloc(allocator, response_hex) catch return;
    defer allocator.free(response);
    if (response.len < 12) return;

    const answer_count = std.mem.readInt(u16, response[6..][0..2], .big);
    var pos = dnsSkipQuestion(response, 12) orelse return;
    var i: u16 = 0;
    while (i < answer_count) : (i += 1) {
        pos = dnsSkipName(response, pos) orelse return;
        if (pos + 10 > response.len) return;
        const rtype = std.mem.readInt(u16, response[pos..][0..2], .big);
        pos += 2;
        pos += 2;
        const ttl = std.mem.readInt(u32, response[pos..][0..4], .big);
        pos += 4;
        const rdlength = std.mem.readInt(u16, response[pos..][0..2], .big);
        pos += 2;
        if (pos + rdlength > response.len) return;

        var ip_buf: [64]u8 = undefined;
        if (rtype == @intFromEnum(dns.DnsRecordType.A) and rdlength == 4) {
            const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            }) catch null;
            if (ip) |value| state.rememberDnsIp(guest_cid, value, ttl) catch {};
        } else if (rtype == @intFromEnum(dns.DnsRecordType.AAAA) and rdlength == 16) {
            const bytes = response[pos..][0..16].*;
            if (formatIpv6Bytes(&ip_buf, bytes)) |value| state.rememberDnsIp(guest_cid, value, ttl) catch {};
        }
        pos += rdlength;
    }
}

fn domainAllowlistMatches(pattern: []const u8, domain: []const u8, port: ?u16) bool {
    var pattern_host = pattern;
    var pattern_port: ?u16 = null;
    if (std.mem.lastIndexOfScalar(u8, pattern, ':')) |idx| {
        pattern_host = pattern[0..idx];
        pattern_port = std.fmt.parseInt(u16, pattern[idx + 1 ..], 10) catch return false;
    }
    if (pattern_port) |allowed_port| {
        if (port == null or port.? != allowed_port) return false;
    }
    return dns.matchesDomainWildcard(pattern_host, domain);
}

fn isDomainAllowed(record: *const VmRecord, domain: []const u8, port: ?u16) bool {
    return switch (record.network_mode) {
        .locked_down => false,
        .open => true,
        .allowlist => blk: {
            for (record.network_allowed_domains) |pattern| {
                if (domainAllowlistMatches(pattern, domain, port)) break :blk true;
            }
            break :blk false;
        },
    };
}

fn ipv4ToU32(value: []const u8) ?u32 {
    var it = std.mem.splitScalar(u8, value, '.');
    var result: u32 = 0;
    var count: usize = 0;
    while (it.next()) |part| {
        const octet = std.fmt.parseInt(u8, part, 10) catch return null;
        result = (result << 8) | octet;
        count += 1;
    }
    if (count != 4) return null;
    return result;
}

fn ipAddressBitLen(addr: std.Io.net.IpAddress) u8 {
    return switch (addr) {
        .ip4 => 32,
        .ip6 => 128,
    };
}

fn ipAddressesEqual(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes),
        },
    };
}

fn ipPrefixMatches(network: std.Io.net.IpAddress, actual: std.Io.net.IpAddress, prefix: u8) bool {
    return switch (network) {
        .ip4 => |network4| switch (actual) {
            .ip4 => |actual4| bytesPrefixMatches(&network4.bytes, &actual4.bytes, prefix),
            .ip6 => false,
        },
        .ip6 => |network6| switch (actual) {
            .ip4 => false,
            .ip6 => |actual6| bytesPrefixMatches(&network6.bytes, &actual6.bytes, prefix),
        },
    };
}

fn bytesPrefixMatches(network: []const u8, actual: []const u8, prefix: u8) bool {
    const full_bytes = @as(usize, prefix / 8);
    const remaining_bits = prefix % 8;
    if (!std.mem.eql(u8, network[0..full_bytes], actual[0..full_bytes])) return false;
    if (remaining_bits == 0) return true;
    const shift: u3 = @intCast(8 - remaining_bits);
    const mask: u8 = @as(u8, 0xff) << shift;
    return (network[full_bytes] & mask) == (actual[full_bytes] & mask);
}

fn ipAllowlistMatches(pattern: []const u8, ip: []const u8) bool {
    const actual = std.Io.net.IpAddress.parse(ip, 0) catch return false;
    if (std.mem.indexOfScalar(u8, pattern, '/')) |idx| {
        const network = std.Io.net.IpAddress.parse(pattern[0..idx], 0) catch return false;
        const prefix = std.fmt.parseInt(u8, pattern[idx + 1 ..], 10) catch return false;
        if (prefix > ipAddressBitLen(network)) return false;
        return ipPrefixMatches(network, actual, prefix);
    }
    const allowed = std.Io.net.IpAddress.parse(pattern, 0) catch return false;
    return ipAddressesEqual(allowed, actual);
}

fn isIpAllowed(record: *const VmRecord, ip: []const u8) bool {
    return switch (record.network_mode) {
        .locked_down => false,
        .open => true,
        .allowlist => blk: {
            for (record.network_allowed_ips) |pattern| {
                if (ipAllowlistMatches(pattern, ip)) break :blk true;
            }
            break :blk false;
        },
    };
}

fn isIcmpIpAllowed(state: *DaemonState, record: *const VmRecord, ip: []const u8) bool {
    if (isIpAllowed(record, ip)) return true;
    return record.network_mode == .allowlist and state.hasDnsIpAllowance(record.guest_cid, ip);
}

fn isIpLiteral(host: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(host, 0) catch return false;
    return true;
}

fn isTcpTargetAllowed(record: *const VmRecord, host: []const u8, port: u16) bool {
    if (isIpLiteral(host)) return isIpAllowed(record, host);
    return isDomainAllowed(record, host, port);
}

fn closeTcpStream(stream: std.Io.net.Stream) void {
    stream.close(fs.io());
}

fn closeSocket(socket: std.Io.net.Socket) void {
    socket.close(fs.io());
}

const tcp_connect_timeout_ms: i64 = 5000;

fn shortTimeout(ms: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

fn ipAddressFamily(address: std.Io.net.IpAddress) std.posix.sa_family_t {
    return switch (address) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
}

fn ipAddressToPosix(address: std.Io.net.IpAddress, storage: *PosixIpAddress) std.posix.socklen_t {
    return switch (address) {
        .ip4 => |ip4| {
            storage.in = .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            return @sizeOf(std.posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return @sizeOf(std.posix.sockaddr.in6);
        },
    };
}

fn waitForTcpConnect(fd: std.posix.fd_t) !void {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = @intCast(std.c.POLL.OUT),
        .revents = 0,
    }};
    const ready = try std.posix.poll(&fds, tcp_connect_timeout_ms);
    if (ready == 0) return error.Timeout;

    var socket_error: c_int = 0;
    var socket_error_len: std.c.socklen_t = @sizeOf(c_int);
    const rc = std.c.getsockopt(fd, std.c.SOL.SOCKET, std.c.SO.ERROR, &socket_error, &socket_error_len);
    if (rc != 0 or socket_error != 0) return error.ConnectFailed;
}

fn connectIpAddressPosix(address: std.Io.net.IpAddress) !std.Io.net.Stream {
    var storage: PosixIpAddress = undefined;
    const address_len = ipAddressToPosix(address, &storage);

    const fd_rc = std.c.socket(@intCast(ipAddressFamily(address)), @intCast(std.posix.SOCK.STREAM), @intCast(std.posix.IPPROTO.TCP));
    switch (std.c.errno(fd_rc)) {
        .SUCCESS => {},
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => return error.ConnectFailed,
    }
    const fd: std.posix.fd_t = @intCast(fd_rc);
    errdefer fs.closeFd(fd);

    try net.setNonblocking(fd, true);
    const rc = std.c.connect(fd, &storage.any, address_len);
    switch (std.c.errno(rc)) {
        .SUCCESS => {},
        .INPROGRESS => try waitForTcpConnect(fd),
        .ISCONN => {},
        else => return error.ConnectFailed,
    }
    return .{ .socket = .{
        .handle = fd,
        .address = address,
    } };
}

fn connectIpAddress(address: std.Io.net.IpAddress) !std.Io.net.Stream {
    if (builtin.os.tag == .windows) {
        return address.connect(fs.io(), .{
            .mode = .stream,
            .protocol = .tcp,
            .timeout = shortTimeout(tcp_connect_timeout_ms),
        });
    }
    return connectIpAddressPosix(address);
}

const TcpReadResult = struct {
    len: usize = 0,
    eof: bool = false,
};

fn tcpStreamReadAvailable(stream: std.Io.net.Stream, buffer: []u8) !TcpReadResult {
    if (buffer.len == 0) return .{};
    return switch (builtin.os.tag) {
        .windows => tcpStreamReadAvailableWindows(stream, buffer),
        else => tcpStreamReadAvailablePosix(stream, buffer),
    };
}

fn tcpStreamReadAvailablePosix(stream: std.Io.net.Stream, buffer: []u8) !TcpReadResult {
    var fds = [_]std.posix.pollfd{.{
        .fd = stream.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(fds[0..], 1);
    if (ready == 0) return .{};

    const revents = fds[0].revents;
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) return error.SocketUnconnected;
    if ((revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) == 0) return .{};

    const n = std.posix.read(stream.socket.handle, buffer) catch |e| switch (e) {
        error.WouldBlock => return .{},
        else => return e,
    };
    if (n == 0) return .{ .eof = true };
    return .{ .len = n };
}

fn tcpStreamReadAvailableWindows(stream: std.Io.net.Stream, buffer: []u8) !TcpReadResult {
    const windows = std.os.windows;
    var afd_buffer = [_]windows.AFD.WSABUF(.@"var"){.{
        .len = @intCast(buffer.len),
        .buf = buffer.ptr,
    }};
    var recv_info = windows.AFD.RECV_INFO{
        .BufferArray = &afd_buffer,
        .BufferCount = afd_buffer.len,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };

    const io_handle = fs.io();
    var storage: [1]std.Io.Operation.Storage = undefined;
    var batch = std.Io.Batch.init(&storage);
    defer batch.cancel(io_handle);

    _ = batch.add(.{ .device_io_control = .{
        .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.RECEIVE,
        .in = std.mem.asBytes(&recv_info),
    } });
    batch.awaitConcurrent(io_handle, shortTimeout(1)) catch |e| switch (e) {
        error.Timeout => return .{},
        else => return e,
    };

    const completion = batch.next() orelse return .{};
    const iosb = completion.result.device_io_control;
    switch (iosb.u.Status) {
        .SUCCESS => {
            const n: usize = @intCast(iosb.Information);
            if (n == 0) return .{ .eof = true };
            return .{ .len = n };
        },
        .CANCELLED => return .{},
        .END_OF_FILE,
        .PIPE_BROKEN,
        .LOCAL_DISCONNECT,
        .REMOTE_DISCONNECT,
        .GRACEFUL_DISCONNECT,
        .CONNECTION_DISCONNECTED,
        => return .{ .eof = true },
        .CONNECTION_RESET => return error.ConnectionResetByPeer,
        .INVALID_CONNECTION,
        .DEVICE_NOT_CONNECTED,
        .ADDRESS_CLOSED,
        => return error.SocketUnconnected,
        .TIMEOUT,
        .IO_TIMEOUT,
        => return .{},
        .INSUFFICIENT_RESOURCES,
        .INVALID_USER_BUFFER,
        .NO_MEMORY,
        .QUOTA_EXCEEDED,
        .WORKING_SET_QUOTA,
        => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
}

fn unspecifiedFor(address: std.Io.net.IpAddress) std.Io.net.IpAddress {
    return switch (address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
}

fn addressText(address: std.Io.net.IpAddress, buf: []u8) ?[]const u8 {
    return switch (address) {
        .ip4 => |ip4| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            ip4.bytes[0],
            ip4.bytes[1],
            ip4.bytes[2],
            ip4.bytes[3],
        }) catch null,
        .ip6 => |ip6| formatIpv6Bytes(buf, ip6.bytes),
    };
}

fn ipv6IsSensitiveBytes(bytes: [16]u8) bool {
    const all_zero = blk: {
        for (bytes) |byte| {
            if (byte != 0) break :blk false;
        }
        break :blk true;
    };
    const loopback = blk: {
        for (bytes[0..15]) |byte| {
            if (byte != 0) break :blk false;
        }
        break :blk bytes[15] == 1;
    };
    return all_zero or loopback or bytes[0] == 0xff or (bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0x80) or (bytes[0] & 0xfe) == 0xfc;
}

fn resolvedAddressAllowed(record: *const VmRecord, host_is_ip_literal: bool, address: std.Io.net.IpAddress) bool {
    if (host_is_ip_literal or record.network_mode != .allowlist) return true;

    var ip_buf: [64]u8 = undefined;
    const ip = addressText(address, &ip_buf) orelse return false;
    return switch (address) {
        .ip4 => if (!ipv4IsSensitive(ip)) true else isIpAllowed(record, ip),
        .ip6 => |ip6| if (!ipv6IsSensitiveBytes(ip6.bytes)) true else isIpAllowed(record, ip),
    };
}

fn lookupAddresses(
    host: []const u8,
    port: u16,
    family: ?std.Io.net.IpAddress.Family,
    results: *std.ArrayList(std.Io.net.IpAddress),
    allocator: std.mem.Allocator,
) !void {
    const host_name = std.Io.net.HostName.init(host) catch return error.InvalidRequest;
    var lookup_buffer: [32]std.Io.net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_buffer);
    std.Io.net.HostName.lookup(host_name, fs.io(), &lookup_queue, .{
        .port = port,
        .family = family,
    }) catch return error.NameResolutionFailed;

    while (true) {
        const result = lookup_queue.getOne(fs.io()) catch |e| switch (e) {
            error.Closed => break,
            else => return e,
        };
        switch (result) {
            .address => |address| try results.append(allocator, address),
            .canonical_name => {},
        }
    }
    if (results.items.len == 0) return error.NameResolutionFailed;
}

fn collectTargetAddresses(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    family: ?std.Io.net.IpAddress.Family,
) !std.ArrayList(std.Io.net.IpAddress) {
    var addresses: std.ArrayList(std.Io.net.IpAddress) = .empty;
    errdefer addresses.deinit(allocator);

    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        if (family) |required| {
            if (std.meta.activeTag(address) != required) return error.NameResolutionFailed;
        }
        try addresses.append(allocator, address);
    } else |_| {
        try lookupAddresses(host, port, family, &addresses, allocator);
    }
    return addresses;
}

fn ipv4IsSensitive(value: []const u8) bool {
    const ip = ipv4ToU32(value) orelse return true;
    return (ip & 0xff000000) == 0x00000000 or // 0.0.0.0/8
        (ip & 0xff000000) == 0x0a000000 or // 10.0.0.0/8
        (ip & 0xff000000) == 0x7f000000 or // 127.0.0.0/8
        (ip & 0xffc00000) == 0x64400000 or // 100.64.0.0/10
        (ip & 0xfff00000) == 0xac100000 or // 172.16.0.0/12
        (ip & 0xffff0000) == 0xa9fe0000 or // 169.254.0.0/16
        (ip & 0xffff0000) == 0xc0a80000 or // 192.168.0.0/16
        (ip & 0xffff0000) == 0xc6120000 or // 198.18.0.0/15
        (ip & 0xf0000000) == 0xe0000000; // multicast and reserved
}

fn openTcpConnection(allocator: std.mem.Allocator, record: *const VmRecord, host: []const u8, port: u16) !std.Io.net.Stream {
    if (host.len == 0 or host.len > 253 or std.mem.indexOfScalar(u8, host, 0) != null) {
        return error.InvalidRequest;
    }
    const host_is_ip_literal = isIpLiteral(host);

    var addresses = try collectTargetAddresses(allocator, host, port, null);
    defer addresses.deinit(allocator);

    var last_error: anyerror = error.ConnectFailed;
    for (addresses.items) |address| {
        if (!resolvedAddressAllowed(record, host_is_ip_literal, address)) {
            last_error = error.BlockedResolvedAddress;
            continue;
        }
        const stream = connectIpAddress(address) catch |e| {
            last_error = e;
            continue;
        };
        return stream;
    }
    return last_error;
}

fn udpExchangeAddress(address: std.Io.net.IpAddress, payload: []const u8, response: []u8, timeout_ms: i64) !usize {
    const bind_address = unspecifiedFor(address);
    var socket = try bind_address.bind(fs.io(), .{ .mode = .dgram, .protocol = .udp });
    defer closeSocket(socket);

    try socket.send(fs.io(), &address, payload);
    const deadline = sync.nanoTimestamp() + @as(i128, timeout_ms) * std.time.ns_per_ms;
    while (true) {
        const remaining_ns = deadline - sync.nanoTimestamp();
        if (remaining_ns <= 0) return error.Timeout;
        const remaining_ms: i64 = @intCast(@max(@as(i128, 1), @divTrunc(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
        const message = try socket.receiveTimeout(fs.io(), response, shortTimeout(remaining_ms));
        if (!message.from.eql(&address)) continue;
        return message.data.len;
    }
}

fn udpExchange(allocator: std.mem.Allocator, record: *const VmRecord, host: []const u8, port: u16, payload: []const u8, response: []u8) !usize {
    if (host.len == 0 or host.len > 253 or std.mem.indexOfScalar(u8, host, 0) != null or port == 0) {
        return error.InvalidRequest;
    }
    if (payload.len == 0 or payload.len > 4096) return error.InvalidRequest;

    const host_is_ip_literal = isIpLiteral(host);
    var addresses = try collectTargetAddresses(allocator, host, port, null);
    defer addresses.deinit(allocator);

    var last_error: anyerror = error.NetworkError;
    for (addresses.items) |address| {
        if (!resolvedAddressAllowed(record, host_is_ip_literal, address)) {
            last_error = error.BlockedResolvedAddress;
            continue;
        }

        const received = udpExchangeAddress(address, payload, response, 2000) catch |e| {
            last_error = e;
            continue;
        };
        return received;
    }
    return last_error;
}

fn icmpIdentifier() u16 {
    if (builtin.os.tag == .windows) {
        const now_bits: u128 = @bitCast(sync.nanoTimestamp());
        return @truncate(now_bits);
    }
    return @truncate(@as(u32, @intCast(std.c.getpid())));
}

fn internetChecksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @as(u16, @intCast(~sum & 0xffff));
}

fn icmpEchoIp4(ip: []const u8, payload: []const u8, response: []u8) !usize {
    if (payload.len > 1024) return error.InvalidRequest;
    const parsed = std.Io.net.IpAddress.parseIp4(ip, 0) catch return error.InvalidRequest;
    const bind_address = std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
    var socket = try bind_address.bind(fs.io(), .{
        .mode = .dgram,
        .protocol = .icmp,
    });
    defer closeSocket(socket);

    var packet: [1032]u8 = undefined;
    const packet_len = 8 + payload.len;
    packet[0] = 8; // echo request
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 0;
    const ident = icmpIdentifier();
    packet[4] = @intCast(ident >> 8);
    packet[5] = @intCast(ident & 0xff);
    packet[6] = 0;
    packet[7] = 1;
    @memcpy(packet[8..packet_len], payload);
    const checksum = internetChecksum(packet[0..packet_len]);
    packet[2] = @intCast(checksum >> 8);
    packet[3] = @intCast(checksum & 0xff);

    try socket.send(fs.io(), &parsed, packet[0..packet_len]);
    const message = try socket.receiveTimeout(fs.io(), response, shortTimeout(2000));
    return message.data.len;
}

fn icmpEchoIp6(ip: []const u8, payload: []const u8, response: []u8) !usize {
    if (payload.len > 1024) return error.InvalidRequest;
    const parsed = std.Io.net.IpAddress.parseIp6(ip, 0) catch return error.InvalidRequest;
    const bind_address = std.Io.net.IpAddress{ .ip6 = .unspecified(0) };
    var socket = try bind_address.bind(fs.io(), .{
        .mode = .dgram,
        .protocol = .icmpv6,
    });
    defer closeSocket(socket);

    var packet: [1032]u8 = undefined;
    const packet_len = 8 + payload.len;
    packet[0] = 128; // ICMPv6 echo request
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 0;
    const ident = icmpIdentifier();
    packet[4] = @intCast(ident >> 8);
    packet[5] = @intCast(ident & 0xff);
    packet[6] = 0;
    packet[7] = 1;
    @memcpy(packet[8..packet_len], payload);

    try socket.send(fs.io(), &parsed, packet[0..packet_len]);
    const message = try socket.receiveTimeout(fs.io(), response, shortTimeout(2000));
    return message.data.len;
}

fn icmpEcho(ip: []const u8, payload: []const u8, response: []u8) !usize {
    const parsed = std.Io.net.IpAddress.parse(ip, 0) catch return error.InvalidRequest;
    return switch (parsed) {
        .ip4 => icmpEchoIp4(ip, payload, response),
        .ip6 => icmpEchoIp6(ip, payload, response),
    };
}

fn copyResolverServer(target: *[16]u8, value: []const u8) bool {
    if (value.len == 0 or value.len >= target.len or ipv4ToU32(value) == null) return false;
    @memset(target, 0);
    @memcpy(target[0..value.len], value);
    return true;
}

fn addResolverServer(servers: *[4][16]u8, count: *usize, value: []const u8) void {
    if (count.* >= servers.len) return;
    if (copyResolverServer(&servers[count.*], value)) count.* += 1;
}

fn loadResolverServers(allocator: std.mem.Allocator, servers: *[4][16]u8) usize {
    var count: usize = 0;
    const body = openFileReadAll(allocator, "/etc/resolv.conf", 64 * 1024) catch null;
    if (body) |text| {
        defer allocator.free(text);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (!std.mem.startsWith(u8, line, "nameserver")) continue;
            const rest = std.mem.trim(u8, line["nameserver".len..], " \t");
            const end = std.mem.indexOfAny(u8, rest, " \t#") orelse rest.len;
            addResolverServer(servers, &count, rest[0..end]);
        }
    }
    if (count == 0) {
        addResolverServer(servers, &count, "1.1.1.1");
        addResolverServer(servers, &count, "8.8.8.8");
    }
    return count;
}

fn sendDnsQuery(server: []const u8, query: []const u8, response: []u8) !usize {
    const ip = std.Io.net.IpAddress.parseIp4(server, 53) catch return error.InvalidRequest;
    return udpExchangeAddress(ip, query, response, 2000);
}

fn forwardDnsQueryHex(allocator: std.mem.Allocator, request_hex: []const u8) ![]u8 {
    const query = try hexDecodeAlloc(allocator, request_hex);
    defer allocator.free(query);

    var servers: [4][16]u8 = undefined;
    const server_count = loadResolverServers(allocator, &servers);
    var response_buf: [4096]u8 = undefined;

    var last_error: anyerror = error.NetworkError;
    for (servers[0..server_count]) |server_buf| {
        const server = std.mem.sliceTo(server_buf[0..], 0);
        const response_len = sendDnsQuery(server, query, &response_buf) catch |e| {
            last_error = e;
            continue;
        };
        return try hexEncodeAlloc(allocator, response_buf[0..response_len]);
    }
    return last_error;
}

fn startGuestSocketServer(state: *DaemonState, guest_cid: u32, socket_path: []const u8) !void {
    if (!state.start_guest_listeners) return;
    const path_owned = try std.heap.page_allocator.dupe(u8, socket_path);
    errdefer std.heap.page_allocator.free(path_owned);
    const ctx = SocketServerCtx{
        .state = state,
        .kind = .guest,
        .path = path_owned,
        .guest_cid = guest_cid,
        .unlink_on_exit = true,
        .owned_path = true,
    };
    const thread = try std.Thread.spawn(.{}, socketServerLoop, .{ctx});
    thread.detach();
}

fn handleControlRequest(state: *DaemonState, allocator: std.mem.Allocator, id: u64, method: []const u8, params: std.json.ObjectMap) ![]u8 {
    if (std.mem.eql(u8, method, "daemon.ping")) {
        return protocol.buildSuccessPayload(allocator, id, .{ .status = "ok" });
    }
    if (std.mem.eql(u8, method, "daemon.shutdown")) {
        state.shutting_down.store(true, .seq_cst);
        return protocol.buildSuccessPayload(allocator, id, .{ .status = "shutting_down" });
    }
    if (std.mem.eql(u8, method, "vm.list")) {
        var items = std.ArrayList(struct { name: []const u8, guest_cid: u32, started_at: i64, network_mode: []const u8 }).empty;
        defer items.deinit(allocator);

        state.mutex.lock();
        defer state.mutex.unlock();
        var it = state.vms.iterator();
        while (it.next()) |entry| {
            const record = entry.value_ptr.*;
            try items.append(allocator, .{
                .name = record.name,
                .guest_cid = record.guest_cid,
                .started_at = record.started_at,
                .network_mode = record.network_mode.toString(),
            });
        }
        return protocol.buildSuccessPayload(allocator, id, .{ .vms = items.items });
    }
    if (std.mem.eql(u8, method, "vm.inspect")) {
        const name = jsonString(params, "name") orelse return protocol.buildErrorPayload(allocator, id, "missing vm name");
        const maybe_record = blk: {
            state.mutex.lock();
            defer state.mutex.unlock();
            break :blk if (state.vms.get(name)) |record| try cloneVmRecord(allocator, record) else null;
        };
        var record = maybe_record orelse return protocol.buildErrorPayload(allocator, id, "vm not found");
        defer freeVmRecord(allocator, record);
        const services = try serviceNames(allocator, record.network_services);
        defer allocator.free(services);
        return protocol.buildSuccessPayload(allocator, id, .{
            .name = record.name,
            .guest_cid = record.guest_cid,
            .memory_mb = record.memory_mb,
            .cpu_cores = record.cpu_cores,
            .started_at = record.started_at,
            .mounts = record.mounts,
            .network_mode = record.network_mode.toString(),
            .network_services = services,
        });
    }
    return protocol.buildErrorPayload(allocator, id, "unknown control method");
}

fn handleRegisterVm(state: *DaemonState, allocator: std.mem.Allocator, id: u64, params: std.json.ObjectMap) ![]u8 {
    const name = jsonString(params, "name") orelse return protocol.buildErrorPayload(allocator, id, "missing vm name");
    if (!core.paths.validateVmName(name)) return protocol.buildErrorPayload(allocator, id, "invalid vm name");
    const memory_mb = jsonInt(u32, params, "memory_mb") orelse return protocol.buildErrorPayload(allocator, id, "missing memory_mb");
    const cpu_cores = jsonInt(u16, params, "cpu_cores") orelse return protocol.buildErrorPayload(allocator, id, "missing cpu_cores");
    const started_at = jsonInt(i64, params, "started_at") orelse sync.timestamp();
    const network_mode = jsonNetworkMode(params) catch return protocol.buildErrorPayload(allocator, id, "invalid network_mode");
    const metadata_file_raw = jsonString(params, "network_metadata_file");

    const network_services = jsonServiceArray(allocator, params, "network_services") catch return protocol.buildErrorPayload(allocator, id, "invalid network_services");
    const network_allowed_domains = jsonStringArray(allocator, params, "network_allowed_domains") catch {
        if (network_services.len > 0) allocator.free(network_services);
        return protocol.buildErrorPayload(allocator, id, "invalid network_allowed_domains");
    };
    const network_allowed_ips = jsonStringArray(allocator, params, "network_allowed_ips") catch {
        if (network_services.len > 0) allocator.free(network_services);
        freeStringList(allocator, network_allowed_domains);
        return protocol.buildErrorPayload(allocator, id, "invalid network_allowed_ips");
    };
    const mounts = jsonStringArray(allocator, params, "mounts") catch {
        if (network_services.len > 0) allocator.free(network_services);
        freeStringList(allocator, network_allowed_domains);
        freeStringList(allocator, network_allowed_ips);
        return protocol.buildErrorPayload(allocator, id, "invalid mounts");
    };
    const name_owned = allocator.dupe(u8, name) catch |e| {
        if (network_services.len > 0) allocator.free(network_services);
        freeStringList(allocator, network_allowed_domains);
        freeStringList(allocator, network_allowed_ips);
        freeStringList(allocator, mounts);
        return e;
    };
    const metadata_file = if (metadata_file_raw) |path| allocator.dupe(u8, path) catch |e| {
        allocator.free(name_owned);
        if (network_services.len > 0) allocator.free(network_services);
        freeStringList(allocator, network_allowed_domains);
        freeStringList(allocator, network_allowed_ips);
        freeStringList(allocator, mounts);
        return e;
    } else null;

    var guest_socket_path: ?[]u8 = null;
    var replaced_guest_socket_path: ?[]u8 = null;
    var ownership_moved = false;
    defer if (replaced_guest_socket_path) |path| allocator.free(path);
    errdefer if (!ownership_moved) {
        allocator.free(name_owned);
        if (metadata_file) |path| allocator.free(path);
        if (network_services.len > 0) allocator.free(network_services);
        freeStringList(allocator, network_allowed_domains);
        freeStringList(allocator, network_allowed_ips);
        freeStringList(allocator, mounts);
        if (guest_socket_path) |path| allocator.free(path);
    };

    state.mutex.lock();
    if (state.vms.fetchRemove(name)) |entry| {
        removeTcpStreamsForCidLocked(state, entry.value.guest_cid);
        removeDnsAllowancesForCidLocked(state, entry.value.guest_cid);
        fs.cwd().deleteFile(entry.value.guest_socket_path) catch {};
        replaced_guest_socket_path = allocator.dupe(u8, entry.value.guest_socket_path) catch null;
        freeVmRecord(allocator, entry.value);
    }
    const cid = state.next_cid;
    state.next_cid += 1;
    guest_socket_path = core.paths.daemonGuestSocketPath(allocator, cid) catch |e| {
        state.mutex.unlock();
        return e;
    };

    const record = VmRecord{
        .name = name_owned,
        .guest_cid = cid,
        .guest_socket_path = guest_socket_path.?,
        .memory_mb = memory_mb,
        .cpu_cores = cpu_cores,
        .started_at = started_at,
        .network_mode = network_mode,
        .network_services = network_services,
        .network_metadata_file = metadata_file,
        .network_allowed_domains = network_allowed_domains,
        .network_allowed_ips = network_allowed_ips,
        .mounts = mounts,
        .shutdown_requested = false,
    };

    state.vms.put(name_owned, record) catch |e| {
        state.mutex.unlock();
        return e;
    };
    state.mutex.unlock();
    if (replaced_guest_socket_path) |path| net.wakeLocalSocket(path);
    ownership_moved = true;

    startGuestSocketServer(state, cid, guest_socket_path.?) catch |e| {
        state.mutex.lock();
        if (state.vms.fetchRemove(name_owned)) |entry| {
            freeVmRecord(allocator, entry.value);
        }
        state.mutex.unlock();
        return e;
    };

    return protocol.buildSuccessPayload(allocator, id, .{
        .guest_cid = cid,
        .host_cid = 2,
        .guest_socket_path = guest_socket_path.?,
    });
}

fn handleUnregisterVm(state: *DaemonState, allocator: std.mem.Allocator, id: u64, params: std.json.ObjectMap) ![]u8 {
    const name = jsonString(params, "name") orelse return protocol.buildErrorPayload(allocator, id, "missing vm name");
    var removed_guest_socket_path: ?[]u8 = null;
    defer if (removed_guest_socket_path) |path| allocator.free(path);

    state.mutex.lock();
    if (state.vms.fetchRemove(name)) |entry| {
        removeTcpStreamsForCidLocked(state, entry.value.guest_cid);
        removeDnsAllowancesForCidLocked(state, entry.value.guest_cid);
        fs.cwd().deleteFile(entry.value.guest_socket_path) catch {};
        removed_guest_socket_path = allocator.dupe(u8, entry.value.guest_socket_path) catch null;
        freeVmRecord(allocator, entry.value);
    }
    state.mutex.unlock();

    if (removed_guest_socket_path) |path| net.wakeLocalSocket(path);
    return protocol.buildSuccessPayload(allocator, id, .{ .removed = true });
}

fn handleRequestVmShutdown(state: *DaemonState, allocator: std.mem.Allocator, id: u64, params: std.json.ObjectMap) ![]u8 {
    const name = jsonString(params, "name") orelse return protocol.buildErrorPayload(allocator, id, "missing vm name");
    state.mutex.lock();
    defer state.mutex.unlock();
    if (state.vms.getPtr(name)) |record| {
        record.shutdown_requested = true;
        return protocol.buildSuccessPayload(allocator, id, .{ .requested = true });
    }
    return protocol.buildErrorPayload(allocator, id, "vm not registered");
}

fn handleRegisterRequest(state: *DaemonState, allocator: std.mem.Allocator, id: u64, method: []const u8, params: std.json.ObjectMap) ![]u8 {
    if (std.mem.eql(u8, method, "vm.register")) {
        return handleRegisterVm(state, allocator, id, params);
    }
    if (std.mem.eql(u8, method, "vm.unregister")) {
        return handleUnregisterVm(state, allocator, id, params);
    }
    if (std.mem.eql(u8, method, "vm.request_shutdown")) {
        return handleRequestVmShutdown(state, allocator, id, params);
    }
    return protocol.buildErrorPayload(allocator, id, "unknown registration method");
}

fn rejectGuestVmIdentity(allocator: std.mem.Allocator, id: u64, params: std.json.ObjectMap) ?[]u8 {
    if (params.get("vm") != null) {
        return protocol.buildErrorPayload(allocator, id, "guest vm identity is not accepted") catch null;
    }
    return null;
}

fn handleTcpOpenTarget(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, record: *const VmRecord, host: []const u8, port: u16) ![]u8 {
    if (port == 0) return protocol.buildErrorPayload(allocator, id, "invalid port");
    if (!isTcpTargetAllowed(record, host, port)) {
        return protocol.buildErrorPayload(allocator, id, "tcp blocked by network policy");
    }

    const stream = openTcpConnection(allocator, record, host, port) catch |e| {
        if (e == error.BlockedResolvedAddress) {
            return protocol.buildErrorPayload(allocator, id, "tcp blocked by network policy");
        }
        return protocol.buildErrorPayload(allocator, id, "tcp connect failed");
    };
    errdefer closeTcpStream(stream);

    state.mutex.lock();
    var registered = false;
    var it = state.vms.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.guest_cid == guest_cid) {
            registered = true;
            break;
        }
    }
    if (!registered) {
        state.mutex.unlock();
        return protocol.buildErrorPayload(allocator, id, "vm not registered");
    }
    const stream_id = state.next_tcp_stream_id;
    state.next_tcp_stream_id += 1;
    state.tcp_streams.put(stream_id, .{ .guest_cid = guest_cid, .stream = stream }) catch |e| {
        state.mutex.unlock();
        return e;
    };
    state.mutex.unlock();

    return protocol.buildSuccessPayload(allocator, id, .{ .stream_id = stream_id });
}

fn handleTcpOpen(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, record: *const VmRecord, params: std.json.ObjectMap) ![]u8 {
    const host = jsonString(params, "host") orelse return protocol.buildErrorPayload(allocator, id, "missing host");
    const port = jsonInt(u16, params, "port") orelse return protocol.buildErrorPayload(allocator, id, "missing port");
    return handleTcpOpenTarget(state, allocator, guest_cid, id, record, host, port);
}

fn handleTcpConnect(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, record: *const VmRecord, params: std.json.ObjectMap) ![]u8 {
    const ip = jsonString(params, "ip") orelse return protocol.buildErrorPayload(allocator, id, "missing ip");
    const port = jsonInt(u16, params, "port") orelse return protocol.buildErrorPayload(allocator, id, "missing port");
    if (!isIpLiteral(ip)) return protocol.buildErrorPayload(allocator, id, "invalid tcp target");
    return handleTcpOpenTarget(state, allocator, guest_cid, id, record, ip, port);
}

fn handleTcpWrite(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, params: std.json.ObjectMap) ![]u8 {
    const stream_id = jsonInt(u64, params, "stream_id") orelse return protocol.buildErrorPayload(allocator, id, "missing stream_id");
    const data_hex = jsonString(params, "data_hex") orelse return protocol.buildErrorPayload(allocator, id, "missing data_hex");
    const data = hexDecodeAlloc(allocator, data_hex) catch return protocol.buildErrorPayload(allocator, id, "invalid data_hex");
    defer allocator.free(data);

    var result: enum { ok, not_found, write_failed } = .ok;
    var stream: ?TcpStream = null;
    state.mutex.lock();
    if (state.tcp_streams.fetchRemove(stream_id)) |entry| {
        if (entry.value.guest_cid != guest_cid) {
            state.tcp_streams.put(stream_id, entry.value) catch closeTcpStream(entry.value.stream);
            result = .not_found;
        } else {
            stream = entry.value;
        }
    } else {
        result = .not_found;
    }
    state.mutex.unlock();

    if (stream) |entry| {
        var write_buf: [4096]u8 = undefined;
        var writer = entry.stream.writer(fs.io(), &write_buf);
        writer.interface.writeAll(data) catch {
            closeTcpStream(entry.stream);
            return protocol.buildErrorPayload(allocator, id, "tcp write failed");
        };
        writer.interface.flush() catch {
            closeTcpStream(entry.stream);
            return protocol.buildErrorPayload(allocator, id, "tcp write failed");
        };

        state.mutex.lock();
        state.tcp_streams.put(stream_id, entry) catch {
            state.mutex.unlock();
            closeTcpStream(entry.stream);
            return protocol.buildErrorPayload(allocator, id, "tcp write failed");
        };
        state.mutex.unlock();
    }

    return switch (result) {
        .ok => protocol.buildSuccessPayload(allocator, id, .{ .written = data.len }),
        .not_found => protocol.buildErrorPayload(allocator, id, "tcp stream not found"),
        .write_failed => protocol.buildErrorPayload(allocator, id, "tcp write failed"),
    };
}

fn handleTcpRead(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, params: std.json.ObjectMap) ![]u8 {
    const stream_id = jsonInt(u64, params, "stream_id") orelse return protocol.buildErrorPayload(allocator, id, "missing stream_id");
    const requested = jsonInt(usize, params, "max_bytes") orelse 4096;
    const max_bytes = @max(@as(usize, 1), @min(requested, 8192));
    var read_buf: [8192]u8 = undefined;
    var read_len: usize = 0;
    var eof = false;
    var result: enum { ok, not_found, read_failed } = .ok;
    var stream: ?TcpStream = null;

    state.mutex.lock();
    if (state.tcp_streams.fetchRemove(stream_id)) |entry| {
        if (entry.value.guest_cid != guest_cid) {
            state.tcp_streams.put(stream_id, entry.value) catch closeTcpStream(entry.value.stream);
            result = .not_found;
        } else {
            stream = entry.value;
        }
    } else {
        result = .not_found;
    }
    state.mutex.unlock();

    if (stream) |entry| {
        const read = tcpStreamReadAvailable(entry.stream, read_buf[0..max_bytes]) catch {
            closeTcpStream(entry.stream);
            result = .read_failed;
            return protocol.buildErrorPayload(allocator, id, "tcp read failed");
        };
        read_len = read.len;
        if (read.eof) {
            closeTcpStream(entry.stream);
            eof = true;
        } else {
            state.mutex.lock();
            state.tcp_streams.put(stream_id, entry) catch {
                state.mutex.unlock();
                closeTcpStream(entry.stream);
                return protocol.buildErrorPayload(allocator, id, "tcp read failed");
            };
            state.mutex.unlock();
        }
    }

    if (result == .not_found) return protocol.buildErrorPayload(allocator, id, "tcp stream not found");
    if (result == .read_failed) return protocol.buildErrorPayload(allocator, id, "tcp read failed");

    const data_hex = try hexEncodeAlloc(allocator, read_buf[0..read_len]);
    defer allocator.free(data_hex);
    return protocol.buildSuccessPayload(allocator, id, .{ .data_hex = data_hex, .eof = eof });
}

fn handleTcpClose(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, params: std.json.ObjectMap) ![]u8 {
    const stream_id = jsonInt(u64, params, "stream_id") orelse return protocol.buildErrorPayload(allocator, id, "missing stream_id");
    var closed = false;
    state.mutex.lock();
    if (state.tcp_streams.get(stream_id)) |stream| {
        if (stream.guest_cid == guest_cid) {
            if (state.tcp_streams.fetchRemove(stream_id)) |entry| {
                closeTcpStream(entry.value.stream);
                closed = true;
            }
        }
    }
    state.mutex.unlock();
    return protocol.buildSuccessPayload(allocator, id, .{ .closed = closed });
}

fn handleUdpExchange(allocator: std.mem.Allocator, id: u64, record: *const VmRecord, params: std.json.ObjectMap) ![]u8 {
    const host = jsonString(params, "host") orelse return protocol.buildErrorPayload(allocator, id, "missing host");
    const port = jsonInt(u16, params, "port") orelse return protocol.buildErrorPayload(allocator, id, "missing port");
    const data_hex = jsonString(params, "data_hex") orelse return protocol.buildErrorPayload(allocator, id, "missing data_hex");
    if (port == 0) return protocol.buildErrorPayload(allocator, id, "invalid port");
    if (!isTcpTargetAllowed(record, host, port)) {
        return protocol.buildErrorPayload(allocator, id, "udp blocked by network policy");
    }

    const payload = hexDecodeAlloc(allocator, data_hex) catch return protocol.buildErrorPayload(allocator, id, "invalid data_hex");
    defer allocator.free(payload);
    var response_buf: [4096]u8 = undefined;
    const response_len = udpExchange(allocator, record, host, port, payload, &response_buf) catch |e| {
        if (e == error.BlockedResolvedAddress) {
            return protocol.buildErrorPayload(allocator, id, "udp blocked by network policy");
        }
        return protocol.buildErrorPayload(allocator, id, "udp exchange failed");
    };
    const response_hex = try hexEncodeAlloc(allocator, response_buf[0..response_len]);
    defer allocator.free(response_hex);
    return protocol.buildSuccessPayload(allocator, id, .{ .response_hex = response_hex });
}

fn handleIcmpEcho(state: *DaemonState, allocator: std.mem.Allocator, id: u64, record: *const VmRecord, params: std.json.ObjectMap) ![]u8 {
    const ip = jsonString(params, "ip") orelse return protocol.buildErrorPayload(allocator, id, "missing ip");
    const payload_hex = jsonString(params, "payload_hex") orelse "6d3830";
    if (!isIcmpIpAllowed(state, record, ip)) return protocol.buildErrorPayload(allocator, id, "icmp blocked by network policy");
    const payload = hexDecodeAlloc(allocator, payload_hex) catch return protocol.buildErrorPayload(allocator, id, "invalid payload_hex");
    defer allocator.free(payload);

    var response_buf: [1500]u8 = undefined;
    const response_len = icmpEcho(ip, payload, &response_buf) catch |e| switch (e) {
        error.InvalidRequest => return protocol.buildErrorPayload(allocator, id, "invalid icmp target"),
        error.AccessDenied => return protocol.buildErrorPayload(allocator, id, "icmp echo requires host permission"),
        else => return protocol.buildErrorPayload(allocator, id, "icmp echo failed"),
    };
    const response_hex = try hexEncodeAlloc(allocator, response_buf[0..response_len]);
    defer allocator.free(response_hex);
    return protocol.buildSuccessPayload(allocator, id, .{ .response_hex = response_hex });
}

fn handleGuestRequest(state: *DaemonState, allocator: std.mem.Allocator, guest_cid: u32, id: u64, method: []const u8, params: std.json.ObjectMap) ![]u8 {
    if (rejectGuestVmIdentity(allocator, id, params)) |response| return response;

    const maybe_record = try state.cloneByCid(guest_cid, allocator);
    var record = maybe_record orelse return protocol.buildErrorPayload(allocator, id, "vm not registered");
    defer freeVmRecord(allocator, record);

    if (std.mem.eql(u8, method, "agent.heartbeat")) {
        return protocol.buildSuccessPayload(allocator, id, .{
            .status = "ok",
            .shutdown_requested = record.shutdown_requested,
        });
    }

    if (std.mem.eql(u8, method, "dns.query")) {
        if (!hasService(&record, .dns)) return protocol.buildErrorPayload(allocator, id, "dns service disabled");
        const request_hex = jsonString(params, "request_hex") orelse return protocol.buildErrorPayload(allocator, id, "missing request_hex");
        const domain = parseRequestDomain(allocator, request_hex) catch return protocol.buildErrorPayload(allocator, id, "invalid dns query");
        defer allocator.free(domain);
        if (!std.mem.eql(u8, domain, dns.internal_metadata_name) and !isDomainAllowed(&record, domain, null)) {
            const blocked_hex = try dns.buildInternalResponseHex(allocator, request_hex);
            defer allocator.free(blocked_hex);
            return protocol.buildSuccessPayload(allocator, id, .{ .response_hex = blocked_hex });
        }
        if (std.mem.eql(u8, domain, dns.internal_metadata_name)) {
            const response_hex = try dns.buildInternalResponseHex(allocator, request_hex);
            defer allocator.free(response_hex);
            return protocol.buildSuccessPayload(allocator, id, .{ .response_hex = response_hex });
        }
        const response_hex = forwardDnsQueryHex(allocator, request_hex) catch {
            return protocol.buildErrorPayload(allocator, id, "external dns transport failed");
        };
        defer allocator.free(response_hex);
        rememberDnsResponseIps(state, allocator, guest_cid, response_hex);
        return protocol.buildSuccessPayload(allocator, id, .{ .response_hex = response_hex });
    }

    if (std.mem.eql(u8, method, "metadata.get")) {
        if (!hasService(&record, .metadata)) return protocol.buildErrorPayload(allocator, id, "metadata service disabled");
        const path = jsonString(params, "path") orelse return protocol.buildErrorPayload(allocator, id, "missing path");

        if (std.mem.eql(u8, path, "/v1/runtime")) {
            const body = try buildRuntimeBody(allocator, record);
            defer allocator.free(body);
            return protocol.buildSuccessPayload(allocator, id, .{
                .status = 200,
                .content_type = "application/json",
                .body = body,
            });
        }

        if (std.mem.eql(u8, path, "/v1/user")) {
            if (record.network_metadata_file) |metadata_path| {
                const body = try openFileReadAll(allocator, metadata_path, 1024 * 1024);
                defer allocator.free(body);
                return protocol.buildSuccessPayload(allocator, id, .{
                    .status = 200,
                    .content_type = "application/json",
                    .body = body,
                });
            }
            return protocol.buildSuccessPayload(allocator, id, .{
                .status = 404,
                .content_type = "application/json",
                .body = "{}",
            });
        }

        return protocol.buildSuccessPayload(allocator, id, .{
            .status = 404,
            .content_type = "application/json",
            .body = "{}",
        });
    }

    if (std.mem.eql(u8, method, "tcp.open")) {
        return handleTcpOpen(state, allocator, guest_cid, id, &record, params);
    }

    if (std.mem.eql(u8, method, "tcp.write")) {
        return handleTcpWrite(state, allocator, guest_cid, id, params);
    }

    if (std.mem.eql(u8, method, "tcp.read")) {
        return handleTcpRead(state, allocator, guest_cid, id, params);
    }

    if (std.mem.eql(u8, method, "tcp.close")) {
        return handleTcpClose(state, allocator, guest_cid, id, params);
    }

    if (std.mem.eql(u8, method, "tcp.connect")) {
        return handleTcpConnect(state, allocator, guest_cid, id, &record, params);
    }

    if (std.mem.eql(u8, method, "udp.exchange") or std.mem.eql(u8, method, "udp.send")) {
        return handleUdpExchange(allocator, id, &record, params);
    }

    if (std.mem.eql(u8, method, "udp.associate")) {
        if (record.network_mode == .locked_down) return protocol.buildErrorPayload(allocator, id, "udp blocked by network policy");
        return protocol.buildSuccessPayload(allocator, id, .{ .association_id = 0, .max_datagram_bytes = 4096 });
    }

    if (std.mem.eql(u8, method, "icmp.echo")) {
        return handleIcmpEcho(state, allocator, id, &record, params);
    }

    return protocol.buildErrorPayload(allocator, id, "unknown guest method");
}

fn dispatchRequest(
    state: *DaemonState,
    allocator: std.mem.Allocator,
    kind: SocketKind,
    guest_cid: ?u32,
    payload: []const u8,
) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch {
        return protocol.buildErrorPayload(allocator, 0, "invalid json payload");
    };
    defer parsed.deinit();

    const root = jsonObject(parsed.value) orelse return protocol.buildErrorPayload(allocator, 0, "payload must be a json object");
    const version = jsonInt(u32, root, "version") orelse 0;
    const id = jsonInt(u64, root, "id") orelse 0;
    const method = jsonString(root, "method") orelse return protocol.buildErrorPayload(allocator, id, "missing method");
    if (version != protocol.api_version) {
        return protocol.buildErrorPayload(allocator, id, "unsupported api version");
    }

    const params_value = root.get("params") orelse return protocol.buildErrorPayload(allocator, id, "missing params");
    const params = jsonObject(params_value) orelse return protocol.buildErrorPayload(allocator, id, "params must be an object");

    return switch (kind) {
        .control => handleControlRequest(state, allocator, id, method, params),
        .register => handleRegisterRequest(state, allocator, id, method, params),
        .guest => handleGuestRequest(state, allocator, guest_cid orelse return protocol.buildErrorPayload(allocator, id, "missing guest cid"), id, method, params),
    };
}

fn handleConnection(state: *DaemonState, kind: SocketKind, guest_cid: ?u32, stream: *net.Stream) !void {
    const allocator = state.allocator;
    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var reader = stream.reader(&read_buf);
    var writer = stream.writer(&write_buf);
    while (true) {
        {
            const request_payload = protocol.readFrameAlloc(allocator, &reader.interface) catch |e| switch (e) {
                error.EndOfStream => return,
                else => return e,
            };
            defer allocator.free(request_payload);

            const response_payload = try dispatchRequest(state, allocator, kind, guest_cid, request_payload);
            defer allocator.free(response_payload);
            try protocol.writeFrame(&writer.interface, response_payload);
            try writer.interface.flush();
        }
    }
}

fn handleConnectionThread(ctx: *ConnectionCtx) void {
    defer {
        ctx.stream.close();
        std.heap.page_allocator.destroy(ctx);
    }
    handleConnection(ctx.state, ctx.kind, ctx.guest_cid, &ctx.stream) catch |e| {
        log.warn("daemon request handling failed: {s}", .{@errorName(e)});
    };
}

fn socketServerLoop(ctx: SocketServerCtx) void {
    defer {
        if (ctx.unlink_on_exit) fs.cwd().deleteFile(ctx.path) catch {};
        if (ctx.owned_path) std.heap.page_allocator.free(ctx.path);
    }

    if (ctx.kind == .guest) {
        const cid = ctx.guest_cid orelse return;
        if (!ctx.state.hasGuestCid(cid)) return;
    }

    if (builtin.os.tag != .windows) fs.cwd().deleteFile(ctx.path) catch {};
    var server = net.listenLocalSocket(ctx.path, .{
        .kernel_backlog = 8,
        .reuse_address = false,
        .force_nonblocking = true,
    }) catch |e| {
        log.err("daemon socket listen failed path={s}: {s}", .{ ctx.path, @errorName(e) });
        return;
    };
    defer server.deinit();
    chmodPath(ctx.path, 0o600);

    while (!ctx.state.shutting_down.load(.seq_cst)) {
        if (ctx.kind == .guest) {
            const cid = ctx.guest_cid orelse break;
            if (!ctx.state.hasGuestCid(cid)) break;
        }

        const conn = server.accept() catch |e| switch (e) {
            error.WouldBlock => {
                sync.sleep(50 * std.time.ns_per_ms);
                continue;
            },
            else => {
                log.warn("daemon accept failed: {s}", .{@errorName(e)});
                sync.sleep(50 * std.time.ns_per_ms);
                continue;
            },
        };
        if (builtin.os.tag != .windows) {
            net.setNonblocking(conn.stream.handle, false) catch {};
        }

        const conn_ctx = std.heap.page_allocator.create(ConnectionCtx) catch {
            conn.stream.close();
            log.warn("daemon connection alloc failed", .{});
            continue;
        };
        conn_ctx.* = .{
            .state = ctx.state,
            .kind = ctx.kind,
            .guest_cid = ctx.guest_cid,
            .stream = conn.stream,
        };
        const thread = std.Thread.spawn(.{}, handleConnectionThread, .{conn_ctx}) catch |e| {
            conn.stream.close();
            std.heap.page_allocator.destroy(conn_ctx);
            log.warn("daemon connection thread failed: {s}", .{@errorName(e)});
            continue;
        };
        thread.detach();
    }
}

pub fn run(allocator: std.mem.Allocator) !void {
    const daemon_dir = try core.paths.daemonDir(allocator);
    defer allocator.free(daemon_dir);
    try fs.cwd().makePath(daemon_dir);
    chmodPath(daemon_dir, 0o700);

    const guests_dir = try core.paths.daemonGuestsDir(allocator);
    defer allocator.free(guests_dir);
    try fs.cwd().makePath(guests_dir);
    chmodPath(guests_dir, 0o700);

    const control_path = try core.paths.daemonControlSocketPath(allocator);
    defer allocator.free(control_path);
    const register_path = try core.paths.daemonRegisterSocketPath(allocator);
    defer allocator.free(register_path);
    const pid_path = try core.paths.daemonPidPath(allocator);
    defer allocator.free(pid_path);

    fs.cwd().deleteFile(control_path) catch {};
    fs.cwd().deleteFile(register_path) catch {};
    defer fs.cwd().deleteFile(control_path) catch {};
    defer fs.cwd().deleteFile(register_path) catch {};
    defer fs.cwd().deleteFile(pid_path) catch {};

    try writePidFile(pid_path);

    var state = DaemonState.init(allocator);
    state.start_guest_listeners = true;
    defer state.deinit();

    const control_ctx = SocketServerCtx{
        .state = &state,
        .kind = .control,
        .path = control_path,
    };
    const register_ctx = SocketServerCtx{
        .state = &state,
        .kind = .register,
        .path = register_path,
    };

    const control_thread = try std.Thread.spawn(.{}, socketServerLoop, .{control_ctx});
    const register_thread = try std.Thread.spawn(.{}, socketServerLoop, .{register_ctx});

    while (!state.shutting_down.load(.seq_cst)) {
        sync.sleep(100 * std.time.ns_per_ms);
    }

    net.wakeLocalSocket(control_path);
    net.wakeLocalSocket(register_path);

    control_thread.join();
    register_thread.join();
}

fn responseErrorString(allocator: std.mem.Allocator, response: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer parsed.deinit();
    const ok = parsed.value.object.get("ok").?.bool;
    if (ok) return null;
    return try allocator.dupe(u8, parsed.value.object.get("error").?.string);
}

fn closeTcpStreamsForTest(state: *DaemonState) void {
    state.mutex.lock();
    defer state.mutex.unlock();

    var stream_it = state.tcp_streams.iterator();
    while (stream_it.next()) |entry| {
        closeTcpStream(entry.value_ptr.stream);
    }
    state.tcp_streams.clearRetainingCapacity();
}

fn wakeTcpServer(port: u16) void {
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var stream = address.connect(fs.io(), .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = .none,
    }) catch return;
    stream.close(fs.io());
}

fn wakeUdpSocket(port: u16) void {
    const bind_addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    var socket = bind_addr.bind(fs.io(), .{ .mode = .dgram, .protocol = .udp }) catch return;
    defer socket.close(fs.io());

    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    socket.send(fs.io(), &address, "wake") catch {};
}

fn readFdWithTimeout(fd: std.posix.fd_t, buf: []u8, timeout_ms: i32) !usize {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(fds[0..], timeout_ms);
    if (ready == 0) return error.Timeout;
    const revents = fds[0].revents;
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) return error.SocketUnconnected;
    if ((revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) == 0) return error.Timeout;
    return fs.readFd(fd, buf);
}

test "daemon server: control ping succeeds" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const payload =
        \\{"version":1,"id":1,"method":"daemon.ping","params":{}}
    ;
    const response = try dispatchRequest(&state, std.testing.allocator, .control, null, payload);
    defer std.testing.allocator.free(response);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("ok").?.bool);
}

test "daemon server: register allocates sequential guest cids and session sockets" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const first =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["dns"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":["/mnt/host"],"started_at":1}}
    ;
    const second =
        \\{"version":1,"id":2,"method":"vm.register","params":{"name":"beta","memory_mb":1024,"cpu_cores":2,"network_mode":"allowlist","network_services":["metadata"],"network_allowed_domains":["example.com"],"network_allowed_ips":["192.0.2.0/24"],"mounts":[],"started_at":2}}
    ;

    const response1 = try dispatchRequest(&state, std.testing.allocator, .register, null, first);
    defer std.testing.allocator.free(response1);
    const response2 = try dispatchRequest(&state, std.testing.allocator, .register, null, second);
    defer std.testing.allocator.free(response2);

    var parsed1 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response1, .{});
    defer parsed1.deinit();
    var parsed2 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response2, .{});
    defer parsed2.deinit();

    const cid1 = parsed1.value.object.get("result").?.object.get("guest_cid").?.integer;
    const cid2 = parsed2.value.object.get("result").?.object.get("guest_cid").?.integer;
    try std.testing.expectEqual(@as(i64, 16), cid1);
    try std.testing.expectEqual(@as(i64, 17), cid2);
    try std.testing.expect(parsed1.value.object.get("result").?.object.get("guest_socket_path").?.string.len > 0);
    try std.testing.expectEqual(@as(usize, 2), state.vms.count());
}

test "daemon server: metadata runtime is cid bound" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["dns","metadata"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":["/mnt/data"],"started_at":1234}}
    ;
    const runtime_req =
        \\{"version":1,"id":2,"method":"metadata.get","params":{"path":"/v1/runtime"}}
    ;

    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    const runtime_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, runtime_req);
    defer std.testing.allocator.free(runtime_response);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, runtime_response, .{});
    defer parsed.deinit();
    const result = parsed.value.object.get("result").?.object;
    try std.testing.expectEqual(@as(i64, 200), result.get("status").?.integer);
    try std.testing.expect(std.mem.indexOf(u8, result.get("body").?.string, "\"guest_cid\":16") != null);
}

test "daemon server: guest cannot call registration methods" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["metadata"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const payload =
        \\{"version":1,"id":2,"method":"vm.unregister","params":{"name":"alpha"}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, payload);
    defer std.testing.allocator.free(response);

    const err = (try responseErrorString(std.testing.allocator, response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("unknown guest method", err);
}

test "daemon server: guest vm identity field is rejected" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["metadata"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const spoof =
        \\{"version":1,"id":2,"method":"metadata.get","params":{"vm":"beta","path":"/v1/runtime"}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, spoof);
    defer std.testing.allocator.free(response);

    const err = (try responseErrorString(std.testing.allocator, response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("guest vm identity is not accepted", err);
}

test "daemon server: metadata requires metadata service" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["dns"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const req =
        \\{"version":1,"id":2,"method":"metadata.get","params":{"path":"/v1/runtime"}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, req);
    defer std.testing.allocator.free(response);

    const err = (try responseErrorString(std.testing.allocator, response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("metadata service disabled", err);
}

test "daemon server: registered shutdown request is exposed only on cid heartbeat" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":[],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const request_shutdown =
        \\{"version":1,"id":2,"method":"vm.request_shutdown","params":{"name":"alpha"}}
    ;
    const heartbeat =
        \\{"version":1,"id":3,"method":"agent.heartbeat","params":{}}
    ;
    const spoofed_heartbeat =
        \\{"version":1,"id":4,"method":"agent.heartbeat","params":{"vm":"alpha"}}
    ;

    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    const before_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, heartbeat);
    defer std.testing.allocator.free(before_response);
    var before = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, before_response, .{});
    defer before.deinit();
    try std.testing.expect(!before.value.object.get("result").?.object.get("shutdown_requested").?.bool);

    const request_response = try dispatchRequest(&state, std.testing.allocator, .register, null, request_shutdown);
    defer std.testing.allocator.free(request_response);
    try std.testing.expect((try responseErrorString(std.testing.allocator, request_response)) == null);

    const after_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, heartbeat);
    defer std.testing.allocator.free(after_response);
    var after = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, after_response, .{});
    defer after.deinit();
    try std.testing.expect(after.value.object.get("result").?.object.get("shutdown_requested").?.bool);

    const spoofed_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, spoofed_heartbeat);
    defer std.testing.allocator.free(spoofed_response);
    const err = (try responseErrorString(std.testing.allocator, spoofed_response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("guest vm identity is not accepted", err);
}

test "daemon server: repeated registration replaces record safely" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const first =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"locked_down","network_services":["dns"],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1}}
    ;
    const second =
        \\{"version":1,"id":2,"method":"vm.register","params":{"name":"alpha","memory_mb":1024,"cpu_cores":2,"network_mode":"allowlist","network_services":["metadata"],"network_allowed_domains":["example.com"],"network_allowed_ips":["192.0.2.0/24"],"mounts":[],"started_at":2}}
    ;

    const response1 = try dispatchRequest(&state, std.testing.allocator, .register, null, first);
    defer std.testing.allocator.free(response1);
    const response2 = try dispatchRequest(&state, std.testing.allocator, .register, null, second);
    defer std.testing.allocator.free(response2);

    try std.testing.expectEqual(@as(usize, 1), state.vms.count());
    var record = (try state.cloneByCid(17, std.testing.allocator)).?;
    defer freeVmRecord(std.testing.allocator, record);
    try std.testing.expectEqual(@as(u32, 17), record.guest_cid);
    try std.testing.expectEqual(@as(u32, 1024), record.memory_mb);
    try std.testing.expect(hasService(&record, .metadata));
}

fn tcpEchoOnce(server: *std.Io.net.Server) void {
    var stream = server.accept(fs.io()) catch return;
    defer stream.close(fs.io());
    var buf: [32]u8 = undefined;
    const n = readFdWithTimeout(stream.socket.handle, &buf, 2000) catch return;
    if (n == 0) return;
    writeFullFd(stream.socket.handle, buf[0..n]) catch {};
}

fn tcpAcceptCloseOnce(server: *std.Io.net.Server) void {
    var stream = server.accept(fs.io()) catch return;
    stream.close(fs.io());
}

fn udpEchoOnce(fd: std.posix.fd_t) void {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = std.posix.poll(fds[0..], 2000) catch return;
    if (ready == 0) return;
    const revents = fds[0].revents;
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) return;
    if ((revents & std.posix.POLL.IN) == 0) return;

    var buf: [128]u8 = undefined;
    var peer: std.c.sockaddr.storage = undefined;
    var peer_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
    const n = std.c.recvfrom(fd, &buf, buf.len, 0, @ptrCast(&peer), &peer_len);
    switch (std.c.errno(n)) {
        .SUCCESS => _ = std.c.sendto(fd, &buf, @intCast(n), 0, @ptrCast(&peer), peer_len),
        else => {},
    }
}

test "daemon server: tcp streams are cid-bound and enforce ip allowlist" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":[],"network_allowed_domains":[],"network_allowed_ips":["127.0.0.1"],"mounts":[],"started_at":1234}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    const blocked =
        \\{"version":1,"id":2,"method":"tcp.open","params":{"host":"192.0.2.1","port":80}}
    ;
    const blocked_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, blocked);
    defer std.testing.allocator.free(blocked_response);
    const blocked_err = (try responseErrorString(std.testing.allocator, blocked_response)).?;
    defer std.testing.allocator.free(blocked_err);
    try std.testing.expectEqualStrings("tcp blocked by network policy", blocked_err);

    const listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_addr.listen(fs.io(), .{ .kernel_backlog = 1, .reuse_address = true });
    const port = server.socket.address.getPort();
    const thread = try std.Thread.spawn(.{}, tcpEchoOnce, .{&server});
    defer {
        closeTcpStreamsForTest(&state);
        wakeTcpServer(port);
        server.deinit(fs.io());
        thread.join();
    }

    const open_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":1,\"id\":3,\"method\":\"tcp.open\",\"params\":{{\"host\":\"127.0.0.1\",\"port\":{d}}}}}",
        .{port},
    );
    defer std.testing.allocator.free(open_payload);
    const open_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, open_payload);
    defer std.testing.allocator.free(open_response);
    var open_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, open_response, .{});
    defer open_parsed.deinit();
    const stream_id: u64 = @intCast(open_parsed.value.object.get("result").?.object.get("stream_id").?.integer);

    const write_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":1,\"id\":4,\"method\":\"tcp.write\",\"params\":{{\"stream_id\":{d},\"data_hex\":\"70696e67\"}}}}",
        .{stream_id},
    );
    defer std.testing.allocator.free(write_payload);
    const write_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, write_payload);
    defer std.testing.allocator.free(write_response);
    try std.testing.expect((try responseErrorString(std.testing.allocator, write_response)) == null);

    var received = false;
    for (0..50) |_| {
        const read_payload = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"version\":1,\"id\":5,\"method\":\"tcp.read\",\"params\":{{\"stream_id\":{d},\"max_bytes\":16}}}}",
            .{stream_id},
        );
        defer std.testing.allocator.free(read_payload);
        const read_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, read_payload);
        defer std.testing.allocator.free(read_response);
        var read_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, read_response, .{});
        defer read_parsed.deinit();
        const data_hex = read_parsed.value.object.get("result").?.object.get("data_hex").?.string;
        if (std.mem.eql(u8, data_hex, "70696e67")) {
            received = true;
            break;
        }
        sync.sleep(10 * std.time.ns_per_ms);
    }
    try std.testing.expect(received);
}

test "daemon server: tcp connect aliases tcp open stream registration" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":[],"network_allowed_domains":[],"network_allowed_ips":["127.0.0.1"],"mounts":[],"started_at":1234}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    const listen_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try listen_addr.listen(fs.io(), .{ .kernel_backlog = 1, .reuse_address = true });
    const port = server.socket.address.getPort();
    const thread = try std.Thread.spawn(.{}, tcpAcceptCloseOnce, .{&server});
    defer {
        closeTcpStreamsForTest(&state);
        wakeTcpServer(port);
        server.deinit(fs.io());
        thread.join();
    }

    const connect_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":1,\"id\":2,\"method\":\"tcp.connect\",\"params\":{{\"ip\":\"127.0.0.1\",\"port\":{d}}}}}",
        .{port},
    );
    defer std.testing.allocator.free(connect_payload);
    const connect_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, connect_payload);
    defer std.testing.allocator.free(connect_response);
    var connect_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, connect_response, .{});
    defer connect_parsed.deinit();
    const stream_id: u64 = @intCast(connect_parsed.value.object.get("result").?.object.get("stream_id").?.integer);

    const close_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":1,\"id\":3,\"method\":\"tcp.close\",\"params\":{{\"stream_id\":{d}}}}}",
        .{stream_id},
    );
    defer std.testing.allocator.free(close_payload);
    const close_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, close_payload);
    defer std.testing.allocator.free(close_response);
    try std.testing.expect((try responseErrorString(std.testing.allocator, close_response)) == null);
}

test "daemon server: udp exchange enforces policy before host socket use" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":[],"network_allowed_domains":[],"network_allowed_ips":["127.0.0.1"],"mounts":[],"started_at":1234}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    const blocked =
        \\{"version":1,"id":2,"method":"udp.exchange","params":{"host":"192.0.2.1","port":53,"data_hex":"70696e67"}}
    ;
    const blocked_response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, blocked);
    defer std.testing.allocator.free(blocked_response);
    const blocked_err = (try responseErrorString(std.testing.allocator, blocked_response)).?;
    defer std.testing.allocator.free(blocked_err);
    try std.testing.expectEqualStrings("udp blocked by network policy", blocked_err);

    const bind_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var socket = try bind_addr.bind(fs.io(), .{ .mode = .dgram, .protocol = .udp });
    const port = socket.address.getPort();
    const thread = try std.Thread.spawn(.{}, udpEchoOnce, .{socket.handle});
    defer {
        wakeUdpSocket(port);
        socket.close(fs.io());
        thread.join();
    }

    const payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"version\":1,\"id\":3,\"method\":\"udp.exchange\",\"params\":{{\"host\":\"127.0.0.1\",\"port\":{d},\"data_hex\":\"70696e67\"}}}}",
        .{port},
    );
    defer std.testing.allocator.free(payload);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, payload);
    defer std.testing.allocator.free(response);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response, .{});
    defer parsed.deinit();
    const response_hex = parsed.value.object.get("result").?.object.get("response_hex").?.string;
    try std.testing.expectEqualStrings("70696e67", response_hex);
}

test "daemon server: icmp echo enforces ip allowlist before host socket use" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":[],"network_allowed_domains":[],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const payload =
        \\{"version":1,"id":2,"method":"icmp.echo","params":{"ip":"192.0.2.1","payload_hex":"70696e67"}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, payload);
    defer std.testing.allocator.free(response);
    const err = (try responseErrorString(std.testing.allocator, response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("icmp blocked by network policy", err);
}

test "daemon server: ip allowlist supports ipv6 exact and cidr entries" {
    try std.testing.expect(ipAllowlistMatches("2001:db8::1", "2001:db8::1"));
    try std.testing.expect(!ipAllowlistMatches("2001:db8::1", "2001:db8::2"));
    try std.testing.expect(ipAllowlistMatches("2001:db8:abcd::/48", "2001:db8:abcd:1::1234"));
    try std.testing.expect(!ipAllowlistMatches("2001:db8:abcd::/48", "2001:db8:abce::1"));
    try std.testing.expect(!ipAllowlistMatches("2001:db8::/129", "2001:db8::1"));
}

test "daemon server: dns result cache can authorize icmp to resolved allowlisted domain ip" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":["dns"],"network_allowed_domains":["example.com"],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);

    var record = (try state.cloneByCid(16, std.testing.allocator)).?;
    defer freeVmRecord(std.testing.allocator, record);
    try std.testing.expect(!isIcmpIpAllowed(&state, &record, "93.184.216.34"));

    try state.rememberDnsIp(16, "93.184.216.34", 60);
    try std.testing.expect(isIcmpIpAllowed(&state, &record, "93.184.216.34"));
    try std.testing.expect(!isIcmpIpAllowed(&state, &record, "93.184.216.35"));

    try state.rememberDnsIp(16, "2001:db8:0:0:0:0:0:1", 60);
    try std.testing.expect(isIcmpIpAllowed(&state, &record, "2001:db8::1"));
}

test "daemon server: domain allowlist cannot rebind to local host addresses" {
    var state = DaemonState.init(std.testing.allocator);
    defer state.deinit();

    const register =
        \\{"version":1,"id":1,"method":"vm.register","params":{"name":"alpha","memory_mb":512,"cpu_cores":1,"network_mode":"allowlist","network_services":[],"network_allowed_domains":["localhost"],"network_allowed_ips":[],"mounts":[],"started_at":1234}}
    ;
    const open_localhost =
        \\{"version":1,"id":2,"method":"tcp.open","params":{"host":"localhost","port":80}}
    ;
    const register_response = try dispatchRequest(&state, std.testing.allocator, .register, null, register);
    defer std.testing.allocator.free(register_response);
    const response = try dispatchRequest(&state, std.testing.allocator, .guest, 16, open_localhost);
    defer std.testing.allocator.free(response);
    const err = (try responseErrorString(std.testing.allocator, response)).?;
    defer std.testing.allocator.free(err);
    try std.testing.expectEqualStrings("tcp blocked by network policy", err);
}

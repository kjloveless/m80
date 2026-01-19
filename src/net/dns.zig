const std = @import("std");
const builtin = @import("builtin");
const policy = @import("policy.zig");

pub const DnsError = error{
    DomainNotAllowed,
    ResolutionFailed,
    InvalidResponse,
    NetworkError,
    Timeout,
    OutOfMemory,
    NoServers,
};

pub const DnsRecordType = enum(u16) {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    NS = 2,
    SOA = 6,
};

pub const DnsClass = enum(u16) {
    IN = 1,
};

pub const DnsHeader = extern struct {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,

    pub fn init(id: u16) DnsHeader {
        return .{
            .id = std.mem.nativeToBig(u16, id),
            .flags = std.mem.nativeToBig(u16, 0x0100), // Standard query, recursion desired
            .qd_count = std.mem.nativeToBig(u16, 1),
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        };
    }

    pub fn isResponse(self: *const DnsHeader) bool {
        const flags = std.mem.bigToNative(u16, self.flags);
        return (flags & 0x8000) != 0;
    }

    pub fn getResponseCode(self: *const DnsHeader) u4 {
        const flags = std.mem.bigToNative(u16, self.flags);
        return @intCast(flags & 0x000F);
    }

    pub fn getAnswerCount(self: *const DnsHeader) u16 {
        return std.mem.bigToNative(u16, self.an_count);
    }
};

pub const DnsRecord = struct {
    ip: [4]u8,
    ttl: u32,
};

pub const DnsResolver = struct {
    allocator: std.mem.Allocator,
    servers: std.ArrayList([4]u8),
    timeout_ms: u32,
    max_retries: u8,

    pub fn init(allocator: std.mem.Allocator) DnsResolver {
        return .{
            .allocator = allocator,
            .servers = .empty,
            .timeout_ms = 5000,
            .max_retries = 3,
        };
    }

    pub fn deinit(self: *DnsResolver) void {
        self.servers.deinit(self.allocator);
    }

    pub fn addServer(self: *DnsResolver, ip: [4]u8) !void {
        try self.servers.append(self.allocator, ip);
    }

    pub fn addDefaultServers(self: *DnsResolver) !void {
        try self.addServer([4]u8{ 8, 8, 8, 8 }); // Google
        try self.addServer([4]u8{ 1, 1, 1, 1 }); // Cloudflare
    }

    pub fn resolve(
        self: *DnsResolver,
        domain: []const u8,
        net_policy: ?*const policy.NetworkPolicy,
    ) DnsError![]DnsRecord {
        if (net_policy) |p| {
            if (!p.isDomainAllowed(domain)) {
                return DnsError.DomainNotAllowed;
            }
        }

        if (self.servers.items.len == 0) {
            return DnsError.NoServers;
        }

        var query_buf: [512]u8 = undefined;
        const query_len = buildQuery(&query_buf, domain, @truncate(@as(u64, @bitCast(std.time.milliTimestamp())))) catch return DnsError.OutOfMemory;

        var response_buf: [512]u8 = undefined;

        for (self.servers.items) |server| {
            for (0..self.max_retries) |_| {
                const response_len = self.sendQuery(server, query_buf[0..query_len], &response_buf) catch continue;

                if (response_len < @sizeOf(DnsHeader)) continue;

                const records = parseResponse(self.allocator, response_buf[0..response_len]) catch continue;
                return records;
            }
        }

        return DnsError.ResolutionFailed;
    }

    fn sendQuery(self: *DnsResolver, server: [4]u8, query: []const u8, response: []u8) !usize {
        _ = self;

        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return error.NetworkError;
        defer std.posix.close(sock);

        const addr = std.net.Address.initIp4(server, 53);

        std.posix.sendto(sock, query, 0, &addr.any, addr.getOsSockLen()) catch return error.NetworkError;

        var from_addr: std.posix.sockaddr.storage = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));

        const n = std.posix.recvfrom(sock, response, 0, @ptrCast(&from_addr), &from_len) catch return error.NetworkError;
        return n;
    }
};

fn buildQuery(buf: []u8, domain: []const u8, id: u16) !usize {
    if (buf.len < @sizeOf(DnsHeader) + domain.len + 6) {
        return error.BufferTooSmall;
    }

    const header = DnsHeader.init(id);
    @memcpy(buf[0..@sizeOf(DnsHeader)], std.mem.asBytes(&header));

    var pos: usize = @sizeOf(DnsHeader);

    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |label| {
        if (label.len > 63) return error.LabelTooLong;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos..][0..label.len], label);
        pos += label.len;
    }
    buf[pos] = 0;
    pos += 1;

    const qtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
    const qclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));

    @memcpy(buf[pos..][0..2], std.mem.asBytes(&qtype));
    pos += 2;
    @memcpy(buf[pos..][0..2], std.mem.asBytes(&qclass));
    pos += 2;

    return pos;
}

fn parseResponse(allocator: std.mem.Allocator, response: []const u8) ![]DnsRecord {
    if (response.len < @sizeOf(DnsHeader)) {
        return error.InvalidResponse;
    }

    const header: *const DnsHeader = @ptrCast(@alignCast(response.ptr));

    if (!header.isResponse()) {
        return error.InvalidResponse;
    }

    if (header.getResponseCode() != 0) {
        return error.ResolutionFailed;
    }

    const answer_count = header.getAnswerCount();
    if (answer_count == 0) {
        return error.ResolutionFailed;
    }

    var records: std.ArrayList(DnsRecord) = .empty;
    errdefer records.deinit(allocator);

    var pos: usize = @sizeOf(DnsHeader);

    pos = skipQuestion(response, pos) catch return error.InvalidResponse;

    var i: u16 = 0;
    while (i < answer_count) : (i += 1) {
        if (pos >= response.len) break;

        pos = skipName(response, pos) catch break;

        if (pos + 10 > response.len) break;

        const rtype = std.mem.bigToNative(u16, @as(*const u16, @ptrCast(@alignCast(response.ptr + pos))).*);
        pos += 2;

        pos += 2;

        const ttl = std.mem.bigToNative(u32, @as(*const u32, @ptrCast(@alignCast(response.ptr + pos))).*);
        pos += 4;

        const rdlength = std.mem.bigToNative(u16, @as(*const u16, @ptrCast(@alignCast(response.ptr + pos))).*);
        pos += 2;

        if (rtype == @intFromEnum(DnsRecordType.A) and rdlength == 4) {
            if (pos + 4 <= response.len) {
                try records.append(allocator, .{
                    .ip = response[pos..][0..4].*,
                    .ttl = ttl,
                });
            }
        }

        pos += rdlength;
    }

    return try records.toOwnedSlice(allocator);
}

fn skipQuestion(response: []const u8, start: usize) !usize {
    var pos = start;
    pos = try skipName(response, pos);
    pos += 4;
    return pos;
}

fn skipName(response: []const u8, start: usize) !usize {
    var pos = start;
    while (pos < response.len) {
        const len = response[pos];
        if (len == 0) {
            return pos + 1;
        }
        if ((len & 0xC0) == 0xC0) {
            return pos + 2;
        }
        pos += 1 + len;
    }
    return error.InvalidResponse;
}

pub fn matchesDomainWildcard(pattern: []const u8, domain: []const u8) bool {
    return policy.matchDomainPattern(pattern, domain);
}

pub fn resolveWithPolicy(
    allocator: std.mem.Allocator,
    resolver: *DnsResolver,
    domain: []const u8,
    net_policy: *policy.NetworkPolicy,
) DnsError!void {
    if (!net_policy.isDomainAllowed(domain)) {
        return DnsError.DomainNotAllowed;
    }

    const records = try resolver.resolve(domain, net_policy);
    defer allocator.free(records);

    for (records) |record| {
        net_policy.addResolvedIp(domain, record.ip, record.ttl) catch continue;
    }
}

test "dns: DnsHeader init" {
    const header = DnsHeader.init(0x1234);
    try std.testing.expect(header.isResponse() == false);
    try std.testing.expectEqual(@as(u16, 1), std.mem.bigToNative(u16, header.qd_count));
}

test "dns: buildQuery" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", 0x1234);

    try std.testing.expect(len > @sizeOf(DnsHeader));

    const header: *const DnsHeader = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u16, 0x1234), std.mem.bigToNative(u16, header.id));
}

test "dns: DnsResolver init" {
    const allocator = std.testing.allocator;

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();

    try resolver.addServer([4]u8{ 8, 8, 8, 8 });
    try std.testing.expectEqual(@as(usize, 1), resolver.servers.items.len);
}

test "dns: matchesDomainWildcard" {
    try std.testing.expect(matchesDomainWildcard("*.example.com", "sub.example.com"));
    try std.testing.expect(!matchesDomainWildcard("*.example.com", "example.com"));
    try std.testing.expect(matchesDomainWildcard("example.com", "example.com"));
}

test "dns: skipName handles compression pointer" {
    const data = [_]u8{ 0xC0, 0x0C };
    const result = try skipName(&data, 0);
    try std.testing.expectEqual(@as(usize, 2), result);
}

test "dns: skipName handles regular label" {
    const data = [_]u8{ 3, 'w', 'w', 'w', 0 };
    const result = try skipName(&data, 0);
    try std.testing.expectEqual(@as(usize, 5), result);
}

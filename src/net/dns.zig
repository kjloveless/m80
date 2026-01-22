//! Pure Zig DNS Resolver
//!
//! This module implements DNS resolution without using libc, giving full
//! control over DNS queries and allowing policy enforcement at the DNS level.
//!
//! ## DNS Protocol Overview
//! DNS uses a simple request/response protocol over UDP (port 53):
//! 1. Client builds a query with header + question section
//! 2. Server responds with header + question + answer sections
//! 3. Answers contain resource records (A, AAAA, CNAME, etc.)
//!
//! ## Wire Format
//! - `DnsHeader`: 12-byte fixed header with ID, flags, and section counts
//! - QNAME: Domain name as length-prefixed labels (e.g., \x07example\x03com\x00)
//! - Compression: Names can use pointers (0xC0xx) to avoid repetition
//!
//! ## Policy Integration
//! The resolver integrates with NetworkPolicy to:
//! - Block DNS queries for disallowed domains (before any network traffic)
//! - Cache resolved IPs into the policy for subsequent connection checks
//!
//! ## Limitations
//! This is a minimal implementation:
//! - Only A records (IPv4) are parsed
//! - No EDNS support (512-byte limit)
//! - No TCP fallback for truncated responses

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
    servers: std.ArrayList(std.net.Address),
    timeout_ms: u32,
    max_retries: u8,

    pub fn init(allocator: std.mem.Allocator) DnsResolver {
        // Defaults favor simplicity over full-featured resolver behavior.
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
        try self.servers.append(self.allocator, std.net.Address.initIp4(ip, 53));
    }

    pub fn addServerWithPort(self: *DnsResolver, ip: [4]u8, port: u16) !void {
        try self.servers.append(self.allocator, std.net.Address.initIp4(ip, port));
    }

    pub fn addDefaultServers(self: *DnsResolver) !void {
        // Public resolvers; callers can override for private DNS.
        try self.addServer([4]u8{ 8, 8, 8, 8 }); // Google
        try self.addServer([4]u8{ 1, 1, 1, 1 }); // Cloudflare
    }

    pub fn resolve(
        self: *DnsResolver,
        domain: []const u8,
        net_policy: ?*const policy.NetworkPolicy,
    ) DnsError![]DnsRecord {
        // Policy is enforced before any network traffic. This keeps DNS resolution
        // aligned with the allowlist semantics used for outbound connections.
        if (net_policy) |p| {
            if (!p.isDomainAllowed(domain)) {
                return DnsError.DomainNotAllowed;
            }
        }

        if (self.servers.items.len == 0) {
            return DnsError.NoServers;
        }

        // DNS over UDP with a single 512-byte buffer (no EDNS in this stub).
        var query_buf: [512]u8 = undefined;
        const query_len = buildQuery(
            &query_buf,
            domain,
            @truncate(@as(u64, @bitCast(std.time.milliTimestamp()))),
        ) catch return DnsError.OutOfMemory;

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

    fn sendQuery(self: *DnsResolver, server: std.net.Address, query: []const u8, response: []u8) !usize {
        _ = self;

        // UDP query/response without explicit timeouts; caller retries per server.
        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return error.NetworkError;
        defer std.posix.close(sock);

        _ = std.posix.sendto(sock, query, 0, &server.any, server.getOsSockLen()) catch return error.NetworkError;

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

    // DNS header + QNAME + QTYPE + QCLASS.
    const header = DnsHeader.init(id);
    @memcpy(buf[0..@sizeOf(DnsHeader)], std.mem.asBytes(&header));

    var pos: usize = @sizeOf(DnsHeader);

    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |label| {
        if (label.len > 63) return error.LabelTooLong;
        // DNS labels are length-prefixed (max 63 bytes each).
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
    // Minimal parser: expects a valid response and collects A records only.
    if (response.len < @sizeOf(DnsHeader)) {
        return error.InvalidResponse;
    }

    const flags = std.mem.readInt(u16, response[2..][0..2], .big);
    const answer_count = std.mem.readInt(u16, response[6..][0..2], .big);

    if ((flags & 0x8000) == 0) {
        return error.InvalidResponse;
    }

    if ((flags & 0x000F) != 0) {
        return error.ResolutionFailed;
    }

    if (answer_count == 0) {
        return error.ResolutionFailed;
    }

    var records: std.ArrayList(DnsRecord) = .empty;
    errdefer records.deinit(allocator);

    var pos: usize = @sizeOf(DnsHeader);

    // Skip QNAME/QTYPE/QCLASS once, then iterate answers.
    pos = skipQuestion(response, pos) catch return error.InvalidResponse;

    var i: u16 = 0;
    while (i < answer_count) : (i += 1) {
        if (pos >= response.len) break;

        pos = skipName(response, pos) catch break;

        if (pos + 10 > response.len) break;

        const rtype = std.mem.readInt(u16, response[pos..][0..2], .big);
        pos += 2;

        pos += 2;

        const ttl = std.mem.readInt(u32, response[pos..][0..4], .big);
        pos += 4;

        const rdlength = std.mem.readInt(u16, response[pos..][0..2], .big);
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
    // Skip QNAME + QTYPE + QCLASS.
    var pos = start;
    pos = try skipName(response, pos);
    if (pos + 4 > response.len) return error.InvalidResponse;
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
            // Compression pointer: two-byte jump.
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

    // Cache successful A records into the policy for allowlist checks.
    const records = try resolver.resolve(domain, net_policy);
    defer allocator.free(records);

    for (records) |record| {
        net_policy.addResolvedIp(domain, record.ip, record.ttl) catch continue;
    }
}

// =============================================================================
// TESTS
// =============================================================================

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

test "dns: buildQuery rejects oversized label" {
    var buf: [512]u8 = undefined;
    var label: [64]u8 = undefined;
    @memset(&label, 'a');
    try std.testing.expectError(error.LabelTooLong, buildQuery(&buf, &label, 0x1234));
}

test "dns: parseResponse rejects non-response header" {
    var response: [@sizeOf(DnsHeader)]u8 = undefined;
    const header: *DnsHeader = @ptrCast(@alignCast(&response));
    header.* = DnsHeader.init(0x1234);
    try std.testing.expectError(error.InvalidResponse, parseResponse(std.testing.allocator, &response));
}

test "dns: parseResponse rejects non-zero rcode" {
    var response: [@sizeOf(DnsHeader)]u8 = undefined;
    const header: *DnsHeader = @ptrCast(@alignCast(&response));
    header.* = DnsHeader.init(0x1234);
    header.flags = std.mem.nativeToBig(u16, 0x8001); // response + rcode 1
    try std.testing.expectError(error.ResolutionFailed, parseResponse(std.testing.allocator, &response));
}

test "dns: parseResponse rejects empty answers" {
    var response: [@sizeOf(DnsHeader)]u8 = undefined;
    const header: *DnsHeader = @ptrCast(@alignCast(&response));
    header.* = DnsHeader.init(0x1234);
    header.flags = std.mem.nativeToBig(u16, 0x8000); // response
    header.an_count = std.mem.nativeToBig(u16, 0);
    try std.testing.expectError(error.ResolutionFailed, parseResponse(std.testing.allocator, &response));
}

test "dns: parseResponse parses A record" {
    var query_buf: [512]u8 = undefined;
    const qlen = try buildQuery(&query_buf, "example.com", 0xBEEF);

    var response: [512]u8 = undefined;
    const header: *DnsHeader = @ptrCast(@alignCast(&response));
    header.* = DnsHeader.init(0xBEEF);
    header.flags = std.mem.nativeToBig(u16, 0x8000); // response
    header.qd_count = std.mem.nativeToBig(u16, 1);
    header.an_count = std.mem.nativeToBig(u16, 1);
    header.ns_count = 0;
    header.ar_count = 0;

    var pos: usize = @sizeOf(DnsHeader);
    @memcpy(response[pos..][0..(qlen - pos)], query_buf[pos..][0..(qlen - pos)]);
    pos = qlen;

    // Answer: name pointer to offset 12 (0xC00C)
    response[pos] = 0xC0;
    response[pos + 1] = 0x0C;
    pos += 2;

    const rtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
    const rclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rtype));
    pos += 2;
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
    pos += 2;

    const ttl = std.mem.nativeToBig(u32, 60);
    @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
    pos += 4;

    const rdlen = std.mem.nativeToBig(u16, 4);
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rdlen));
    pos += 2;

    response[pos] = 1;
    response[pos + 1] = 2;
    response[pos + 2] = 3;
    response[pos + 3] = 4;
    pos += 4;

    const records = try parseResponse(std.testing.allocator, response[0..pos]);
    defer std.testing.allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, records[0].ip);
    try std.testing.expectEqual(@as(u32, 60), records[0].ttl);
}

test "dns: parseResponse handles unaligned buffer" {
    var query_buf: [512]u8 = undefined;
    const qlen = try buildQuery(&query_buf, "example.com", 0xBEEF);

    var backing: [513]u8 = undefined;
    const response = backing[1..];

    var header = DnsHeader.init(0xBEEF);
    header.flags = std.mem.nativeToBig(u16, 0x8000); // response
    header.qd_count = std.mem.nativeToBig(u16, 1);
    header.an_count = std.mem.nativeToBig(u16, 1);
    header.ns_count = 0;
    header.ar_count = 0;
    @memcpy(response[0..@sizeOf(DnsHeader)], std.mem.asBytes(&header));

    var pos: usize = @sizeOf(DnsHeader);
    @memcpy(response[pos..][0..(qlen - pos)], query_buf[pos..][0..(qlen - pos)]);
    pos = qlen;

    response[pos] = 0xC0;
    response[pos + 1] = 0x0C;
    pos += 2;

    const rtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
    const rclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rtype));
    pos += 2;
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
    pos += 2;

    const ttl = std.mem.nativeToBig(u32, 60);
    @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
    pos += 4;

    const rdlen = std.mem.nativeToBig(u16, 4);
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rdlen));
    pos += 2;

    response[pos] = 1;
    response[pos + 1] = 2;
    response[pos + 2] = 3;
    response[pos + 3] = 4;
    pos += 4;

    const records = try parseResponse(std.testing.allocator, response[0..pos]);
    defer std.testing.allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, records[0].ip);
}

test "dns: parseResponse ignores non-A records" {
    var query_buf: [512]u8 = undefined;
    const qlen = try buildQuery(&query_buf, "example.com", 0xBEEF);

    var response: [512]u8 = undefined;
    const header: *DnsHeader = @ptrCast(@alignCast(&response));
    header.* = DnsHeader.init(0xBEEF);
    header.flags = std.mem.nativeToBig(u16, 0x8000); // response
    header.qd_count = std.mem.nativeToBig(u16, 1);
    header.an_count = std.mem.nativeToBig(u16, 2);
    header.ns_count = 0;
    header.ar_count = 0;

    var pos: usize = @sizeOf(DnsHeader);
    @memcpy(response[pos..][0..(qlen - pos)], query_buf[pos..][0..(qlen - pos)]);
    pos = qlen;

    // Answer 1: CNAME
    response[pos] = 0xC0;
    response[pos + 1] = 0x0C;
    pos += 2;

    const cname_type = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.CNAME));
    const rclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));
    @memcpy(response[pos..][0..2], std.mem.asBytes(&cname_type));
    pos += 2;
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
    pos += 2;

    const ttl = std.mem.nativeToBig(u32, 60);
    @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
    pos += 4;

    const cname_len = std.mem.nativeToBig(u16, 4);
    @memcpy(response[pos..][0..2], std.mem.asBytes(&cname_len));
    pos += 2;
    response[pos] = 1;
    response[pos + 1] = 2;
    response[pos + 2] = 3;
    response[pos + 3] = 4;
    pos += 4;

    // Answer 2: A
    response[pos] = 0xC0;
    response[pos + 1] = 0x0C;
    pos += 2;

    const rtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rtype));
    pos += 2;
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
    pos += 2;

    @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
    pos += 4;

    const rdlen = std.mem.nativeToBig(u16, 4);
    @memcpy(response[pos..][0..2], std.mem.asBytes(&rdlen));
    pos += 2;

    response[pos] = 5;
    response[pos + 1] = 6;
    response[pos + 2] = 7;
    response[pos + 3] = 8;
    pos += 4;

    const records = try parseResponse(std.testing.allocator, response[0..pos]);
    defer std.testing.allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 5, 6, 7, 8 }, records[0].ip);
}

test "dns: skipName rejects truncated label" {
    const data = [_]u8{ 3, 'w', 'w' };
    try std.testing.expectError(error.InvalidResponse, skipName(&data, 0));
}

test "dns: skipQuestion rejects truncated" {
    // QNAME ok, but missing QTYPE/QCLASS (needs 4 bytes).
    const data = [_]u8{ 0 };
    try std.testing.expectError(error.InvalidResponse, skipQuestion(&data, 0));
}

test "dns: buildQuery rejects too-small buffer" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, buildQuery(&buf, "a", 1));
}

test "dns: resolve returns NoServers when empty" {
    const allocator = std.testing.allocator;

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();

    try std.testing.expectError(DnsError.NoServers, resolver.resolve("example.com", null));
}

test "dns: resolve uses udp responder" {
    const allocator = std.testing.allocator;

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    const bind_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    try std.posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

    var bound_storage: std.posix.sockaddr.storage = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_storage));
    try std.posix.getsockname(sock, @ptrCast(&bound_storage), &bound_len);
    const bound_addr = std.net.Address.initPosix(@alignCast(@ptrCast(&bound_storage)));
    const port = bound_addr.getPort();

    const ResponderCtx = struct {
        sock: std.posix.socket_t,
    };

    const responder = struct {
        fn run(ctx: *ResponderCtx) void {
            var buf: [512]u8 = undefined;
            var from_addr: std.posix.sockaddr.storage = undefined;
            var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));
            const n = std.posix.recvfrom(ctx.sock, &buf, 0, @ptrCast(&from_addr), &from_len) catch return;
            if (n < @sizeOf(DnsHeader)) return;

            var response: [512]u8 = undefined;
            @memcpy(response[0..@sizeOf(DnsHeader)], buf[0..@sizeOf(DnsHeader)]);
            std.mem.writeInt(u16, response[2..][0..2], 0x8000, .big); // response
            std.mem.writeInt(u16, response[4..][0..2], 1, .big); // qd
            std.mem.writeInt(u16, response[6..][0..2], 1, .big); // an
            std.mem.writeInt(u16, response[8..][0..2], 0, .big); // ns
            std.mem.writeInt(u16, response[10..][0..2], 0, .big); // ar

            const question_len = n - @sizeOf(DnsHeader);
            @memcpy(
                response[@sizeOf(DnsHeader)..][0..question_len],
                buf[@sizeOf(DnsHeader)..][0..question_len],
            );

            var pos: usize = @sizeOf(DnsHeader) + question_len;
            response[pos] = 0xC0;
            response[pos + 1] = 0x0C;
            pos += 2;

            const rtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
            const rclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rtype));
            pos += 2;
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
            pos += 2;

            const ttl = std.mem.nativeToBig(u32, 60);
            @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
            pos += 4;

            const rdlen = std.mem.nativeToBig(u16, 4);
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rdlen));
            pos += 2;

            response[pos] = 9;
            response[pos + 1] = 8;
            response[pos + 2] = 7;
            response[pos + 3] = 6;
            pos += 4;

            _ = std.posix.sendto(ctx.sock, response[0..pos], 0, @ptrCast(&from_addr), from_len) catch return;
        }
    };

    var ctx = ResponderCtx{ .sock = sock };
    const thread = try std.Thread.spawn(.{}, responder.run, .{ &ctx });
    defer thread.join();

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();
    resolver.max_retries = 1;
    try resolver.addServerWithPort([4]u8{ 127, 0, 0, 1 }, port);

    const records = try resolver.resolve("example.com", null);
    defer allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 9, 8, 7, 6 }, records[0].ip);
}

test "dns: resolveWithPolicy caches resolved ip" {
    const allocator = std.testing.allocator;

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    const bind_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    try std.posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

    var bound_storage: std.posix.sockaddr.storage = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_storage));
    try std.posix.getsockname(sock, @ptrCast(&bound_storage), &bound_len);
    const bound_addr = std.net.Address.initPosix(@alignCast(@ptrCast(&bound_storage)));
    const port = bound_addr.getPort();

    const ResponderCtx = struct {
        sock: std.posix.socket_t,
    };

    const responder = struct {
        fn run(ctx: *ResponderCtx) void {
            var buf: [512]u8 = undefined;
            var from_addr: std.posix.sockaddr.storage = undefined;
            var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));
            const n = std.posix.recvfrom(ctx.sock, &buf, 0, @ptrCast(&from_addr), &from_len) catch return;
            if (n < @sizeOf(DnsHeader)) return;

            var response: [512]u8 = undefined;
            @memcpy(response[0..@sizeOf(DnsHeader)], buf[0..@sizeOf(DnsHeader)]);
            std.mem.writeInt(u16, response[2..][0..2], 0x8000, .big); // response
            std.mem.writeInt(u16, response[4..][0..2], 1, .big); // qd
            std.mem.writeInt(u16, response[6..][0..2], 1, .big); // an
            std.mem.writeInt(u16, response[8..][0..2], 0, .big); // ns
            std.mem.writeInt(u16, response[10..][0..2], 0, .big); // ar

            const question_len = n - @sizeOf(DnsHeader);
            @memcpy(
                response[@sizeOf(DnsHeader)..][0..question_len],
                buf[@sizeOf(DnsHeader)..][0..question_len],
            );

            var pos: usize = @sizeOf(DnsHeader) + question_len;
            response[pos] = 0xC0;
            response[pos + 1] = 0x0C;
            pos += 2;

            const rtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.A));
            const rclass = std.mem.nativeToBig(u16, @intFromEnum(DnsClass.IN));
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rtype));
            pos += 2;
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rclass));
            pos += 2;

            const ttl = std.mem.nativeToBig(u32, 60);
            @memcpy(response[pos..][0..4], std.mem.asBytes(&ttl));
            pos += 4;

            const rdlen = std.mem.nativeToBig(u16, 4);
            @memcpy(response[pos..][0..2], std.mem.asBytes(&rdlen));
            pos += 2;

            response[pos] = 1;
            response[pos + 1] = 2;
            response[pos + 2] = 3;
            response[pos + 3] = 4;
            pos += 4;

            _ = std.posix.sendto(ctx.sock, response[0..pos], 0, @ptrCast(&from_addr), from_len) catch return;
        }
    };

    var ctx = ResponderCtx{ .sock = sock };
    const thread = try std.Thread.spawn(.{}, responder.run, .{ &ctx });
    defer thread.join();

    var net_policy = policy.NetworkPolicy.init(allocator);
    defer net_policy.deinit();
    net_policy.mode = .allowlist;
    try net_policy.addDomainRule("example.com");

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();
    resolver.max_retries = 1;
    try resolver.addServerWithPort([4]u8{ 127, 0, 0, 1 }, port);

    try resolveWithPolicy(allocator, &resolver, "example.com", &net_policy);

    try std.testing.expectEqual(@as(usize, 1), net_policy.resolved_ips.items.len);
    try std.testing.expect(net_policy.isIpAllowed([4]u8{ 1, 2, 3, 4 }));
}

test "dns: resolveWithPolicy rejects disallowed domain" {
    const allocator = std.testing.allocator;

    var net_policy = policy.NetworkPolicy.init(allocator);
    defer net_policy.deinit();
    net_policy.mode = .allowlist;
    try net_policy.addDomainRule("allowed.example.com");

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();
    try resolver.addServer([4]u8{ 8, 8, 8, 8 });

    try std.testing.expectError(
        DnsError.DomainNotAllowed,
        resolveWithPolicy(allocator, &resolver, "blocked.example.com", &net_policy),
    );
}

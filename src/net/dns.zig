//! DNS wire-codec helpers and synthetic m80 internal responses.
//!
//! ## Wire Format
//! - `DnsHeader`: 12-byte fixed header with ID, flags, and section counts
//! - QNAME: Domain name as length-prefixed labels (e.g., \x07example\x03com\x00)
//! - Compression: Names can use pointers (0xC0xx) to avoid repetition
//!
//! ## Limitations
//! This is a minimal implementation:
//! - Only A records are parsed into `DnsRecord`
//! - No EDNS support (512-byte limit)
//! - No TCP fallback for truncated responses

const std = @import("std");
const sync = @import("../util/sync.zig");
const fs = @import("../util/fs.zig");
const net = @import("../util/net.zig");
const builtin = @import("builtin");

pub const DnsError = error{
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
    servers: std.ArrayList(net.Address),
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
        try self.servers.append(self.allocator, net.Address.initIp4(ip, 53));
    }

    pub fn addServerWithPort(self: *DnsResolver, ip: [4]u8, port: u16) !void {
        try self.servers.append(self.allocator, net.Address.initIp4(ip, port));
    }

    pub fn addDefaultServers(self: *DnsResolver) !void {
        // Public resolvers; callers can override for private DNS.
        try self.addServer([4]u8{ 8, 8, 8, 8 }); // Google
        try self.addServer([4]u8{ 1, 1, 1, 1 }); // Cloudflare
    }

    pub fn resolve(
        self: *DnsResolver,
        domain: []const u8,
    ) DnsError![]DnsRecord {
        if (self.servers.items.len == 0) {
            return DnsError.NoServers;
        }

        // DNS over UDP with a single 512-byte buffer (no EDNS in this stub).
        var query_buf: [512]u8 = undefined;
        const query_len = buildQuery(
            &query_buf,
            domain,
            @truncate(@as(u64, @bitCast(sync.milliTimestamp()))),
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

    fn sendQuery(self: *DnsResolver, server: net.Address, query: []const u8, response: []u8) !usize {
        _ = self;

        // UDP query/response without explicit timeouts; caller retries per server.
        const bind_addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
        var sock = std.Io.net.IpAddress.bind(&bind_addr, fs.io(), .{
            .mode = .dgram,
            .protocol = .udp,
        }) catch return error.NetworkError;
        defer sock.close(fs.io());

        const dest = server.toIpAddress();
        sock.send(fs.io(), &dest, query) catch return error.NetworkError;
        const message = sock.receive(fs.io(), response) catch return error.NetworkError;
        return message.data.len;
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

pub fn parseResponse(allocator: std.mem.Allocator, response: []const u8) ![]DnsRecord {
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
            if (pos + 1 >= response.len) return error.InvalidResponse;
            return pos + 2;
        }
        const step: usize = 1 + @as(usize, len);
        if (pos + step > response.len) return error.InvalidResponse;
        pos += step;
    }
    return error.InvalidResponse;
}

fn parseMessageDomain(buf: []const u8, out: []u8, require_question: bool) ![]const u8 {
    if (buf.len < @sizeOf(DnsHeader)) return error.InvalidResponse;
    if (require_question) {
        const qd_count = std.mem.readInt(u16, buf[4..][0..2], .big);
        if (qd_count == 0) return error.InvalidResponse;
    }
    const name = try decodeName(buf, @sizeOf(DnsHeader), out);
    _ = std.ascii.lowerString(name, name);
    return name;
}

pub fn parseQueryDomain(buf: []const u8, out: []u8) ![]const u8 {
    return parseMessageDomain(buf, out, true);
}

pub fn parseResponseDomain(buf: []const u8, out: []u8) ![]const u8 {
    return parseMessageDomain(buf, out, false);
}

fn decodeName(buf: []const u8, start: usize, out: []u8) ![]u8 {
    var pos = start;
    var out_pos: usize = 0;
    var depth: u8 = 0;
    while (pos < buf.len) {
        const len = buf[pos];
        if (len == 0) {
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= buf.len) return error.InvalidResponse;
            const offset = (@as(u16, len & 0x3F) << 8) | buf[pos + 1];
            if (offset >= buf.len) return error.InvalidResponse;
            if (depth > 8) return error.InvalidResponse;
            depth += 1;
            pos = offset;
            continue;
        }
        pos += 1;
        if (pos + len > buf.len) return error.InvalidResponse;
        if (out_pos != 0) {
            if (out_pos >= out.len) return error.InvalidResponse;
            out[out_pos] = '.';
            out_pos += 1;
        }
        if (out_pos + len > out.len) return error.InvalidResponse;
        @memcpy(out[out_pos .. out_pos + len], buf[pos .. pos + len]);
        out_pos += len;
        pos += len;
    }
    return out[0..out_pos];
}

pub fn matchesDomainWildcard(pattern: []const u8, domain: []const u8) bool {
    if (std.mem.eql(u8, pattern, domain)) return true;
    if (!std.mem.startsWith(u8, pattern, "*.")) return false;
    const suffix = pattern[1..];
    return std.mem.endsWith(u8, domain, suffix) and domain.len > suffix.len;
}

pub const internal_metadata_name = "metadata.m80.internal";
pub const synthetic_ttl_secs: u32 = 60;

fn writeIntBig(writer: anytype, comptime T: type, value: T) !void {
    const be = std.mem.nativeToBig(T, value);
    try writer.writeAll(std.mem.asBytes(&be));
}

fn encodeHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = chars[byte >> 4];
        out[i * 2 + 1] = chars[byte & 0x0f];
    }
    return out;
}

fn parseQuestionType(message: []const u8) !u16 {
    const question_start = @sizeOf(DnsHeader);
    const question_end = try skipQuestion(message, question_start);
    const qtype_pos = question_end - 4;
    return std.mem.readInt(u16, message[qtype_pos..][0..2], .big);
}

fn buildInternalResponse(allocator: std.mem.Allocator, query: []const u8) ![]u8 {
    if (query.len < @sizeOf(DnsHeader)) return error.InvalidResponse;

    var domain_buf: [256]u8 = undefined;
    const domain = try parseQueryDomain(query, &domain_buf);
    const qtype = try parseQuestionType(query);
    const question_end = try skipQuestion(query, @sizeOf(DnsHeader));

    const name_matches = std.mem.eql(u8, domain, internal_metadata_name);
    const answer_matches = name_matches and (qtype == @intFromEnum(DnsRecordType.A) or qtype == @intFromEnum(DnsRecordType.AAAA));
    const flags: u16 = if (name_matches) 0x8180 else 0x8183;
    const answer_count: u16 = if (answer_matches) 1 else 0;

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();

    const header_id = std.mem.readInt(u16, query[0..2], .big);
    try writeIntBig(&out.writer, u16, header_id);
    try writeIntBig(&out.writer, u16, flags);
    try writeIntBig(&out.writer, u16, 1);
    try writeIntBig(&out.writer, u16, answer_count);
    try writeIntBig(&out.writer, u16, 0);
    try writeIntBig(&out.writer, u16, 0);
    try out.writer.writeAll(query[@sizeOf(DnsHeader)..question_end]);

    if (answer_matches) {
        try writeIntBig(&out.writer, u16, 0xC00C);
        try writeIntBig(&out.writer, u16, qtype);
        try writeIntBig(&out.writer, u16, @intFromEnum(DnsClass.IN));
        try writeIntBig(&out.writer, u32, synthetic_ttl_secs);

        switch (qtype) {
            @intFromEnum(DnsRecordType.A) => {
                try writeIntBig(&out.writer, u16, 4);
                try out.writer.writeAll(&[_]u8{ 127, 0, 0, 1 });
            },
            @intFromEnum(DnsRecordType.AAAA) => {
                try writeIntBig(&out.writer, u16, 16);
                try out.writer.writeAll(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
            },
            else => unreachable,
        }
    }

    return out.toOwnedSlice();
}

pub fn buildInternalResponseHex(allocator: std.mem.Allocator, request_hex: []const u8) ![]u8 {
    const query = try allocator.alloc(u8, request_hex.len / 2);
    defer allocator.free(query);
    const decoded = try std.fmt.hexToBytes(query, request_hex);

    const response = try buildInternalResponse(allocator, decoded);
    defer allocator.free(response);
    return try encodeHexAlloc(allocator, response);
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

test "dns: buildInternalResponseHex resolves metadata.m80.internal to loopback" {
    var query_buf: [512]u8 = undefined;
    const qlen = try buildQuery(&query_buf, internal_metadata_name, 0xCAFE);
    const query_hex = try encodeHexAlloc(std.testing.allocator, query_buf[0..qlen]);
    defer std.testing.allocator.free(query_hex);

    const response_hex = try buildInternalResponseHex(std.testing.allocator, query_hex);
    defer std.testing.allocator.free(response_hex);

    var response_buf: [512]u8 = undefined;
    const response = try std.fmt.hexToBytes(&response_buf, response_hex);
    const records = try parseResponse(std.testing.allocator, response);
    defer std.testing.allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, records[0].ip);
}

test "dns: buildInternalResponseHex returns NXDOMAIN for non-internal names" {
    var query_buf: [512]u8 = undefined;
    const qlen = try buildQuery(&query_buf, "example.com", 0xFACE);
    const query_hex = try encodeHexAlloc(std.testing.allocator, query_buf[0..qlen]);
    defer std.testing.allocator.free(query_hex);

    const response_hex = try buildInternalResponseHex(std.testing.allocator, query_hex);
    defer std.testing.allocator.free(response_hex);

    var response_buf: [512]u8 = undefined;
    const response = try std.fmt.hexToBytes(&response_buf, response_hex);
    try std.testing.expectEqual(@as(u16, 0x8183), std.mem.readInt(u16, response[2..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, response[6..][0..2], .big));
}

test "dns: buildInternalResponseHex returns NXDOMAIN for blocked PTR queries" {
    var query_buf: [512]u8 = undefined;
    const qlen = blk: {
        const base = try buildQuery(&query_buf, "110.210.251.142.in-addr.arpa", 0xF00D);
        const qtype = std.mem.nativeToBig(u16, 12);
        @memcpy(query_buf[base - 4 ..][0..2], std.mem.asBytes(&qtype));
        break :blk base;
    };
    const query_hex = try encodeHexAlloc(std.testing.allocator, query_buf[0..qlen]);
    defer std.testing.allocator.free(query_hex);

    const response_hex = try buildInternalResponseHex(std.testing.allocator, query_hex);
    defer std.testing.allocator.free(response_hex);

    var response_buf: [512]u8 = undefined;
    const response = try std.fmt.hexToBytes(&response_buf, response_hex);
    try std.testing.expectEqual(@as(u16, 0x8183), std.mem.readInt(u16, response[2..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, response[6..][0..2], .big));
}

test "dns: buildInternalResponseHex emits AAAA answer for metadata service" {
    var query_buf: [512]u8 = undefined;
    const qlen = blk: {
        const base = try buildQuery(&query_buf, internal_metadata_name, 0xC001);
        const qtype = std.mem.nativeToBig(u16, @intFromEnum(DnsRecordType.AAAA));
        @memcpy(query_buf[base - 4 ..][0..2], std.mem.asBytes(&qtype));
        break :blk base;
    };
    const query_hex = try encodeHexAlloc(std.testing.allocator, query_buf[0..qlen]);
    defer std.testing.allocator.free(query_hex);

    const response_hex = try buildInternalResponseHex(std.testing.allocator, query_hex);
    defer std.testing.allocator.free(response_hex);

    var response_buf: [512]u8 = undefined;
    const response = try std.fmt.hexToBytes(&response_buf, response_hex);
    const question_end = try skipQuestion(response, @sizeOf(DnsHeader));
    const rdlength_pos = question_end + 2 + 2 + 2 + 4;
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[6..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, response[rdlength_pos..][0..2], .big));
}

test "dns: skipName rejects truncated label" {
    const data = [_]u8{ 3, 'w', 'w' };
    try std.testing.expectError(error.InvalidResponse, skipName(&data, 0));
}

test "dns: skipQuestion rejects truncated" {
    // QNAME ok, but missing QTYPE/QCLASS (needs 4 bytes).
    const data = [_]u8{0};
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

    try std.testing.expectError(DnsError.NoServers, resolver.resolve("example.com"));
}

test "dns: resolve uses udp responder" {
    const allocator = std.testing.allocator;

    const bind_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const sock = try bind_addr.bind(fs.io(), .{ .mode = .dgram });
    defer sock.close(fs.io());
    const port = sock.address.getPort();

    const ResponderCtx = struct {
        sock: std.Io.net.Socket,
    };

    const responder = struct {
        fn run(ctx: *ResponderCtx) void {
            var buf: [512]u8 = undefined;
            const msg = ctx.sock.receive(fs.io(), &buf) catch return;
            const n = msg.data.len;
            if (n < @sizeOf(DnsHeader)) return;

            var response: [512]u8 = undefined;
            @memcpy(response[0..@sizeOf(DnsHeader)], msg.data[0..@sizeOf(DnsHeader)]);
            std.mem.writeInt(u16, response[2..][0..2], 0x8000, .big); // response
            std.mem.writeInt(u16, response[4..][0..2], 1, .big); // qd
            std.mem.writeInt(u16, response[6..][0..2], 1, .big); // an
            std.mem.writeInt(u16, response[8..][0..2], 0, .big); // ns
            std.mem.writeInt(u16, response[10..][0..2], 0, .big); // ar

            const question_len = n - @sizeOf(DnsHeader);
            @memcpy(
                response[@sizeOf(DnsHeader)..][0..question_len],
                msg.data[@sizeOf(DnsHeader)..][0..question_len],
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

            ctx.sock.send(fs.io(), &msg.from, response[0..pos]) catch return;
        }
    };

    var ctx = ResponderCtx{ .sock = sock };
    const thread = try std.Thread.spawn(.{}, responder.run, .{&ctx});
    defer thread.join();

    var resolver = DnsResolver.init(allocator);
    defer resolver.deinit();
    resolver.max_retries = 1;
    try resolver.addServerWithPort([4]u8{ 127, 0, 0, 1 }, port);

    const records = try resolver.resolve("example.com");
    defer allocator.free(records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual([4]u8{ 9, 8, 7, 6 }, records[0].ip);
}

test "dns: parseQueryDomain parses query name" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", 0x1234);
    var out: [256]u8 = undefined;
    const name = try parseQueryDomain(buf[0..len], &out);
    try std.testing.expectEqualStrings("example.com", name);
}

const std = @import("std");
const net = @import("../util/net.zig");

pub const api_version: u32 = 1;
pub const max_frame_bytes: usize = 1024 * 1024;

fn readAllCompat(reader: anytype, buffer: []u8) !void {
    const ReaderType = @TypeOf(reader);
    const ReaderBase = switch (@typeInfo(ReaderType)) {
        .pointer => |ptr| ptr.child,
        else => ReaderType,
    };
    if (@hasDecl(ReaderBase, "readNoEof")) {
        try reader.readNoEof(buffer);
        return;
    }
    if (@hasDecl(ReaderBase, "readSliceAll")) {
        try reader.readSliceAll(buffer);
        return;
    }
    @compileError("unsupported reader type");
}

pub fn readFrameAlloc(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readAllCompat(reader, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .little);
    if (len > max_frame_bytes) return error.MessageTooLarge;
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try readAllCompat(reader, payload);
    return payload;
}

pub fn writeFrame(writer: anytype, payload: []const u8) !void {
    if (payload.len > max_frame_bytes) return error.MessageTooLarge;
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .little);
    try writer.writeAll(&len_buf);
    try writer.writeAll(payload);
}

pub fn rpc(allocator: std.mem.Allocator, socket_path: []const u8, request_payload: []const u8) ![]u8 {
    var stream = try net.connectUnixSocket(socket_path);
    defer stream.close();
    var write_buf: [4096]u8 = undefined;
    var read_buf: [4096]u8 = undefined;
    var writer = stream.writer(&write_buf);
    var reader = stream.reader(&read_buf);
    try writeFrame(&writer.interface, request_payload);
    try writer.interface.flush();
    return try readFrameAlloc(allocator, &reader.interface);
}

pub fn buildRequestPayload(
    allocator: std.mem.Allocator,
    id: u64,
    method: []const u8,
    params: anytype,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(.{
        .version = api_version,
        .id = id,
        .method = method,
        .params = params,
    }, .{}, &out.writer);
    return out.toOwnedSlice();
}

pub fn buildSuccessPayload(
    allocator: std.mem.Allocator,
    id: u64,
    result: anytype,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(.{
        .version = api_version,
        .id = id,
        .ok = true,
        .result = result,
    }, .{}, &out.writer);
    return out.toOwnedSlice();
}

pub fn buildErrorPayload(allocator: std.mem.Allocator, id: u64, message: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(.{
        .version = api_version,
        .id = id,
        .ok = false,
        .@"error" = message,
    }, .{}, &out.writer);
    return out.toOwnedSlice();
}

test "daemon protocol: frame round-trip" {
    const payload = "hello-daemon";
    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try writeFrame(&writer, payload);

    var reader: std.Io.Reader = .fixed(buf[0..writer.end]);
    const decoded = try readFrameAlloc(std.testing.allocator, &reader);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);
}

test "daemon protocol: buildRequestPayload encodes method" {
    const payload = try buildRequestPayload(std.testing.allocator, 7, "daemon.ping", struct {}{});
    defer std.testing.allocator.free(payload);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 7), root.get("id").?.integer);
    try std.testing.expectEqualStrings("daemon.ping", root.get("method").?.string);
}

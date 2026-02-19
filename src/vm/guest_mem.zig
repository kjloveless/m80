const std = @import("std");

pub const Range = struct {
    offset: usize,
    end: usize,
};

pub const GuestIo = struct {
    read_bytes: *const fn (u64, []u8) anyerror!void,
    write_bytes: *const fn (u64, []const u8) anyerror!void,
};

pub fn checkedRange(memory_len: usize, guest_base: u64, guest_addr: u64, len: usize) !Range {
    if (guest_addr < guest_base) return error.InvalidGuestLayout;
    const offset_u64 = guest_addr - guest_base;
    if (offset_u64 > std.math.maxInt(usize)) return error.InvalidGuestLayout;
    const offset: usize = @intCast(offset_u64);
    const end = std.math.add(usize, offset, len) catch return error.InvalidGuestLayout;
    if (end > memory_len) return error.InvalidGuestLayout;
    return .{
        .offset = offset,
        .end = end,
    };
}

pub fn checkedRangeU64(memory_len: usize, guest_base: u64, guest_addr: u64, len: u64) !Range {
    if (len > std.math.maxInt(usize)) return error.InvalidGuestLayout;
    return checkedRange(memory_len, guest_base, guest_addr, @intCast(len));
}

pub fn writeBytes(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, data: []const u8) !void {
    const memory = memory_opt orelse return error.NoGuestMemory;
    const range = try checkedRange(memory.len, guest_base, guest_addr, data.len);
    std.mem.copyForwards(u8, memory[range.offset..range.end], data);
}

pub fn readBytes(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, out: []u8) !void {
    const memory = memory_opt orelse return error.NoGuestMemory;
    const range = try checkedRange(memory.len, guest_base, guest_addr, out.len);
    std.mem.copyForwards(u8, out, memory[range.offset..range.end]);
}

pub fn readU16(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64) !u16 {
    var buf: [2]u8 = undefined;
    try readBytes(memory_opt, guest_base, guest_addr, &buf);
    return std.mem.readInt(u16, &buf, .little);
}

pub fn readU32(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64) !u32 {
    var buf: [4]u8 = undefined;
    try readBytes(memory_opt, guest_base, guest_addr, &buf);
    return std.mem.readInt(u32, &buf, .little);
}

pub fn readU64(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64) !u64 {
    var buf: [8]u8 = undefined;
    try readBytes(memory_opt, guest_base, guest_addr, &buf);
    return std.mem.readInt(u64, &buf, .little);
}

pub fn writeU16(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try writeBytes(memory_opt, guest_base, guest_addr, &buf);
}

pub fn writeU32(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try writeBytes(memory_opt, guest_base, guest_addr, &buf);
}

pub fn writeU64(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try writeBytes(memory_opt, guest_base, guest_addr, &buf);
}

pub fn writeByte(memory_opt: ?[]u8, guest_base: u64, guest_addr: u64, value: u8) !void {
    try writeBytes(memory_opt, guest_base, guest_addr, &[_]u8{value});
}

pub fn readBytesViaIo(io: GuestIo, guest_addr: u64, out: []u8) !void {
    try io.read_bytes(guest_addr, out);
}

pub fn writeBytesViaIo(io: GuestIo, guest_addr: u64, data: []const u8) !void {
    try io.write_bytes(guest_addr, data);
}

pub fn readU16ViaIo(io: GuestIo, guest_addr: u64) !u16 {
    var buf: [2]u8 = undefined;
    try readBytesViaIo(io, guest_addr, &buf);
    return std.mem.readInt(u16, &buf, .little);
}

pub fn readU32ViaIo(io: GuestIo, guest_addr: u64) !u32 {
    var buf: [4]u8 = undefined;
    try readBytesViaIo(io, guest_addr, &buf);
    return std.mem.readInt(u32, &buf, .little);
}

pub fn readU64ViaIo(io: GuestIo, guest_addr: u64) !u64 {
    var buf: [8]u8 = undefined;
    try readBytesViaIo(io, guest_addr, &buf);
    return std.mem.readInt(u64, &buf, .little);
}

pub fn writeU16ViaIo(io: GuestIo, guest_addr: u64, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try writeBytesViaIo(io, guest_addr, &buf);
}

pub fn writeU32ViaIo(io: GuestIo, guest_addr: u64, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try writeBytesViaIo(io, guest_addr, &buf);
}

pub fn writeU64ViaIo(io: GuestIo, guest_addr: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try writeBytesViaIo(io, guest_addr, &buf);
}

pub fn writeByteViaIo(io: GuestIo, guest_addr: u64, value: u8) !void {
    try writeBytesViaIo(io, guest_addr, &[_]u8{value});
}

test "guest_mem: checkedRange validates bounds and base" {
    const ok = try checkedRange(0x1000, 0x4000, 0x4100, 16);
    try std.testing.expectEqual(@as(usize, 0x100), ok.offset);
    try std.testing.expectEqual(@as(usize, 0x110), ok.end);

    try std.testing.expectError(error.InvalidGuestLayout, checkedRange(0x1000, 0x4000, 0x3fff, 1));
    try std.testing.expectError(error.InvalidGuestLayout, checkedRange(0x1000, 0x4000, 0x4ff0, 0x20));
}

test "guest_mem: read/write primitives round-trip" {
    var buf: [256]u8 = undefined;
    @memset(&buf, 0);
    const memory = buf[0..];

    try writeBytes(memory, 0x1000, 0x1010, "abc");
    var out: [3]u8 = undefined;
    try readBytes(memory, 0x1000, 0x1010, &out);
    try std.testing.expectEqualStrings("abc", &out);

    try writeU16(memory, 0x1000, 0x1020, 0x1234);
    try std.testing.expectEqual(@as(u16, 0x1234), try readU16(memory, 0x1000, 0x1020));

    try writeU32(memory, 0x1000, 0x1030, 0x89abcdef);
    try std.testing.expectEqual(@as(u32, 0x89abcdef), try readU32(memory, 0x1000, 0x1030));

    try writeU64(memory, 0x1000, 0x1040, 0x0102030405060708);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try readU64(memory, 0x1000, 0x1040));
}

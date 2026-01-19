const std = @import("std");

pub const SerialIo = struct {
  buf: ?[]u8 = null,
  offset: usize = 0,

  pub fn setFromEnv(self: *SerialIo, allocator: std.mem.Allocator) void {
    const env = std.process.getEnvVarOwned(allocator, "M80_SERIAL_IN") catch null;
    if (env) |v| {
      self.clear(allocator);
      self.buf = v;
      self.offset = 0;
    }
  }

  pub fn clear(self: *SerialIo, allocator: std.mem.Allocator) void {
    if (self.buf) |buf| {
      allocator.free(buf);
      self.buf = null;
    }
    self.offset = 0;
  }

  pub fn hasData(self: *const SerialIo) bool {
    if (self.buf == null) return false;
    return self.offset < self.buf.?.len;
  }

  pub fn readByte(self: *SerialIo) ?u8 {
    if (!self.hasData()) return null;
    const b = self.buf.?[self.offset];
    self.offset += 1;
    return b;
  }

  pub fn writeFromRax(writer: anytype, size: usize, rax: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, rax, .little);
    try writer.writeAll(bytes[0..size]);
  }

  pub fn writeToStdout(size: usize, rax: u64) void {
    var buf: [256]u8 = undefined;
    var fw = std.fs.File.stdout().writer(&buf);
    const w = &fw.interface;
    writeFromRax(w, size, rax) catch return;
    w.flush() catch {};
  }

  pub fn readPort(self: *SerialIo, port: u16, size: usize) u64 {
    var val: u64 = 0;
    if (port == 0x3F8) {
      if (self.readByte()) |b| val = b;
    } else if (port == 0x3FD) {
      val = 0x20;
      if (self.hasData()) val |= 0x01;
    }
    if (size < 8) {
      const mask: u64 = (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
      val &= mask;
    }
    return val;
  }
};

pub const IoExit = struct {
  port: u16,
  is_write: bool,
  size: usize,
  rax: u64,
  is_string: bool = false,
  has_rep: bool = false,
};

test "serial: writeFromRax writes low bytes" {
  var buf: [8]u8 = undefined;
  var stream = std.io.fixedBufferStream(&buf);
  try SerialIo.writeFromRax(stream.writer(), 4, 0x64636261);
  try std.testing.expectEqualStrings("abcd", buf[0..4]);
}

test "serial: buffer feeds read" {
  var serial = SerialIo{};
  serial.buf = try std.testing.allocator.dupe(u8, "hi");
  serial.offset = 0;
  defer serial.clear(std.testing.allocator);

  try std.testing.expect(serial.hasData());
  try std.testing.expectEqual(@as(u8, 'h'), serial.readByte().?);
  try std.testing.expectEqual(@as(u8, 'i'), serial.readByte().?);
  try std.testing.expect(!serial.hasData());
  try std.testing.expectEqual(@as(?u8, null), serial.readByte());
}

test "serial: readPort reflects data ready" {
  var serial = SerialIo{};
  serial.buf = try std.testing.allocator.dupe(u8, "A");
  serial.offset = 0;
  defer serial.clear(std.testing.allocator);

  const lsr_with_data = serial.readPort(0x3FD, 1);
  try std.testing.expect((lsr_with_data & 0x21) == 0x21);

  const byte = serial.readPort(0x3F8, 1);
  try std.testing.expectEqual(@as(u8, 'A'), @as(u8, @intCast(byte)));

  const lsr_empty = serial.readPort(0x3FD, 1);
  try std.testing.expect((lsr_empty & 0x01) == 0);
}

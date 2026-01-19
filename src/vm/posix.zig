const std = @import("std");
const log = @import("../util/log.zig");
const config = @import("../core/config.zig");
const serial = @import("serial.zig");
const SerialIo = serial.SerialIo;
const IoExit = serial.IoExit;

const mb_to_bytes: u64 = 1024 * 1024;
const guest_kernel_base: u64 = 0x100000;
const guest_initrd_base: u64 = 0x4000000;
const guest_cmdline_base: u64 = 0x20000;

// Global stub state (single active VM instance).
var active_memory_size: usize = 0;
var active_vcpu_thread: ?std.Thread = null;
var vcpu_running = std.atomic.Value(bool).init(false);
var simulate_io = std.atomic.Value(bool).init(false);
var serial_io = SerialIo{};

const KvmIoExitDirection = enum(u8) {
  In = 0,
  Out = 1,
};

const KvmIoExit = struct {
  direction: KvmIoExitDirection,
  size: u8,
  port: u16,
  count: u32,
  data_offset: u64,
};

fn readLeU64(data: []const u8, size: usize) u64 {
  var out: u64 = 0;
  var i: usize = 0;
  while (i < size and i < data.len) : (i += 1) {
    out |= @as(u64, data[i]) << @as(u6, @intCast(i * 8));
  }
  return out;
}

fn envFlagPresent(allocator: std.mem.Allocator, name: []const u8) bool {
  const env = std.process.getEnvVarOwned(allocator, name) catch return false;
  allocator.free(env);
  return true;
}

fn kvmIoExitToIoExit(exit: KvmIoExit, data: []const u8) IoExit {
  const is_write = exit.direction == .Out;
  const size: usize = @intCast(exit.size);
  return .{
    .port = exit.port,
    .is_write = is_write,
    .size = size,
    .rax = if (is_write) readLeU64(data, size) else 0,
    .is_string = exit.count > 1,
    .has_rep = exit.count > 1,
  };
}

fn handleIoPortWrite(port: u16, size: usize, rax: u64) void {
  if (port == 0x3F8) {
    SerialIo.writeToStdout(size, rax);
    return;
  }
  log.debug("posix io port write port=0x{x} size={d}", .{ port, size });
}

fn handleIoPortRead(port: u16, size: usize) u64 {
  return serial_io.readPort(port, size);
}

fn handleIoExit(exit: IoExit) u64 {
  if (exit.is_write) {
    handleIoPortWrite(exit.port, exit.size, exit.rax);
    return 0;
  }
  return handleIoPortRead(exit.port, exit.size);
}

fn runVcpuStub(index: u32) void {
  log.info("posix vcpu {d} stub run loop entered", .{index});
  while (vcpu_running.load(.seq_cst)) {
    if (simulate_io.swap(false, .seq_cst)) {
      // Emulate a single write/read IO cycle on the serial port.
      _ = handleIoExit(.{ .port = 0x3F8, .is_write = true, .size = 1, .rax = '>', .is_string = false, .has_rep = false });
      _ = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    }
    std.Thread.sleep(50 * std.time.ns_per_ms);
  }
  log.info("posix vcpu {d} stub run loop exited", .{index});
}

fn prepareGuestImage(memory_size_bytes: u64) !void {
  if (guest_cmdline_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_kernel_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_initrd_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_cmdline_base >= guest_kernel_base) return error.InvalidGuestLayout;
  if (guest_kernel_base >= guest_initrd_base) return error.InvalidGuestLayout;

  log.info(
    "posix guest layout kernel=0x{x} initrd=0x{x} cmdline=0x{x}",
    .{ guest_kernel_base, guest_initrd_base, guest_cmdline_base },
  );
}

fn readGuestImageFile(path: []const u8, label: []const u8) !void {
  var file = try std.fs.cwd().openFile(path, .{});
  defer file.close();
  const stat = try file.stat();
  log.info("posix {s} size {d} bytes", .{ label, stat.size });
}

fn loadGuestKernel(memory_size_bytes: u64, kernel_path: ?[]const u8) !void {
  _ = memory_size_bytes;
  if (kernel_path == null) {
    log.warn("posix kernel path not set; skipping kernel load", .{});
    return;
  }
  try readGuestImageFile(kernel_path.?, "kernel");
}

fn loadGuestInitrd(memory_size_bytes: u64, initrd_path: ?[]const u8) !void {
  _ = memory_size_bytes;
  if (initrd_path == null) {
    log.warn("posix initrd path not set; skipping initrd load", .{});
    return;
  }
  try readGuestImageFile(initrd_path.?, "initrd");
}

pub fn start(cfg: config.VmConfig) !void {
  log.info("posix backend stub start (no-op)", .{});
  const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
  if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;
  try prepareGuestImage(size_bytes_u64);
  try loadGuestKernel(size_bytes_u64, cfg.kernel_path);
  try loadGuestInitrd(size_bytes_u64, cfg.initrd_path);
  active_memory_size = @intCast(size_bytes_u64);

  vcpu_running.store(true, .seq_cst);
  if (envFlagPresent(std.heap.page_allocator, "M80_IO_SIM")) {
    simulate_io.store(true, .seq_cst);
  }
  serial_io.setFromEnv(std.heap.page_allocator);
  active_vcpu_thread = try std.Thread.spawn(.{}, runVcpuStub, .{0});

  std.Thread.sleep(std.time.ns_per_s);
  log.info("vm running (stub)", .{});
}

pub fn stop() !void {
  log.info("posix backend stub stop (no-op)", .{});
  vcpu_running.store(false, .seq_cst);
  if (active_vcpu_thread) |t| {
    t.join();
    active_vcpu_thread = null;
  }
  serial_io.clear(std.heap.page_allocator);
  active_memory_size = 0;
}

test "smoke: posix backend start/stop" {
  const tag = @import("builtin").os.tag;
  if (tag == .windows or tag == .macos) return error.SkipZigTest;
  const cfg = try config.defaultConfig(std.testing.allocator, "test");
  var cfg_mut = cfg;
  defer config.freeConfig(std.testing.allocator, &cfg_mut);
  try start(cfg_mut);
  try stop();
}

test "posix: handleIoExit reads serial data" {
  serial_io.clear(std.testing.allocator);
  serial_io.buf = try std.testing.allocator.dupe(u8, "Z");
  serial_io.offset = 0;
  defer serial_io.clear(std.testing.allocator);

  const b = handleIoExit(.{ .port = 0x3F8, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
  try std.testing.expectEqual(@as(u8, 'Z'), @as(u8, @intCast(b)));

  const lsr = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
  try std.testing.expect((lsr & 0x01) == 0);
}

test "posix: kvm io exit mapping" {
  const raw = KvmIoExit{
    .direction = .Out,
    .size = 1,
    .port = 0x3F8,
    .count = 2,
    .data_offset = 0,
  };
  const mapped = kvmIoExitToIoExit(raw, "B");
  try std.testing.expect(mapped.is_write);
  try std.testing.expectEqual(@as(u64, 'B'), mapped.rax);
  try std.testing.expect(mapped.is_string);
  try std.testing.expect(mapped.has_rep);
}

test "posix: readLeU64 respects size and data length" {
  try std.testing.expectEqual(@as(u64, 0), readLeU64("", 0));
  try std.testing.expectEqual(@as(u64, 0x01), readLeU64("\x01\x02", 1));
  try std.testing.expectEqual(@as(u64, 0x0201), readLeU64("\x01\x02", 2));
  try std.testing.expectEqual(@as(u64, 0x0201), readLeU64("\x01\x02", 4));
  try std.testing.expectEqual(@as(u64, 0x04030201), readLeU64("\x01\x02\x03\x04", 4));
}

test "posix: prepareGuestImage rejects too small memory" {
  try std.testing.expectError(error.InvalidGuestLayout, prepareGuestImage(0x1000));
}

test "posix: loadGuestKernel errors on missing file" {
  try std.testing.expectError(error.FileNotFound, loadGuestKernel(64 * 1024 * 1024, "missing-kernel"));
}

test "posix: loadGuestInitrd errors on missing file" {
  try std.testing.expectError(error.FileNotFound, loadGuestInitrd(64 * 1024 * 1024, "missing-initrd"));
}

test "posix: loadGuestKernel skips when unset" {
  try loadGuestKernel(64 * 1024 * 1024, null);
}

test "posix: loadGuestInitrd skips when unset" {
  try loadGuestInitrd(64 * 1024 * 1024, null);
}

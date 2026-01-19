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

pub const Hvf = struct {
  pub const Error = error{
    NotImplemented,
  };

  pub const VmHandle = usize;

  pub const VmConfig = struct {
    cpu_cores: u16,
    memory_mb: u32,
  };

  pub fn createVm() Error!VmHandle {
    return error.NotImplemented;
  }

  pub fn setupVm(handle: VmHandle, cfg: VmConfig) Error!void {
    _ = handle;
    _ = cfg;
    return error.NotImplemented;
  }

  pub fn deleteVm(handle: VmHandle) Error!void {
    _ = handle;
    return error.NotImplemented;
  }
};

// Global stub state (single active VM instance).
var active_vm: ?Hvf.VmHandle = null;
var active_memory_size: usize = 0;
var active_vcpu_thread: ?std.Thread = null;
var vcpu_running = std.atomic.Value(bool).init(false);
var simulate_io = std.atomic.Value(bool).init(false);
var serial_io = SerialIo{};

const HvfIoExit = struct {
  port: u16,
  access_size: u8,
  access_type: u8, // 0 = read, 1 = write
  is_string: bool,
  has_rep: bool,
  rax: u64,
};

fn hvfIoExitToIoExit(exit: HvfIoExit) IoExit {
  const size: usize = switch (exit.access_size) {
    1 => 1,
    2 => 2,
    4 => 4,
    8 => 8,
    else => 1,
  };
  return .{
    .port = exit.port,
    .is_write = exit.access_type == 1,
    .size = size,
    .rax = exit.rax,
    .is_string = exit.is_string,
    .has_rep = exit.has_rep,
  };
}

fn envFlagPresent(allocator: std.mem.Allocator, name: []const u8) bool {
  const env = std.process.getEnvVarOwned(allocator, name) catch return false;
  allocator.free(env);
  return true;
}

fn handleIoPortWrite(port: u16, size: usize, rax: u64) void {
  if (port == 0x3F8) {
    SerialIo.writeToStdout(size, rax);
    return;
  }
  log.debug("hvf io port write port=0x{x} size={d}", .{ port, size });
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
  log.info("hvf vcpu {d} stub run loop entered", .{index});
  while (vcpu_running.load(.seq_cst)) {
    if (simulate_io.swap(false, .seq_cst)) {
      // Emulate a single write/read IO cycle on the serial port.
      _ = handleIoExit(.{ .port = 0x3F8, .is_write = true, .size = 1, .rax = '>', .is_string = false, .has_rep = false });
      _ = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    }
    std.Thread.sleep(50 * std.time.ns_per_ms);
  }
  log.info("hvf vcpu {d} stub run loop exited", .{index});
}

fn prepareGuestImage(memory_size_bytes: u64) !void {
  if (guest_cmdline_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_kernel_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_initrd_base >= memory_size_bytes) return error.InvalidGuestLayout;
  if (guest_cmdline_base >= guest_kernel_base) return error.InvalidGuestLayout;
  if (guest_kernel_base >= guest_initrd_base) return error.InvalidGuestLayout;

  log.info(
    "hvf guest layout kernel=0x{x} initrd=0x{x} cmdline=0x{x}",
    .{ guest_kernel_base, guest_initrd_base, guest_cmdline_base },
  );
}

fn readGuestImageFile(path: []const u8, label: []const u8) !void {
  var file = try std.fs.cwd().openFile(path, .{});
  defer file.close();
  const stat = try file.stat();
  log.info("hvf {s} size {d} bytes", .{ label, stat.size });
}

fn loadGuestKernel(memory_size_bytes: u64, kernel_path: ?[]const u8) !void {
  _ = memory_size_bytes;
  if (kernel_path == null) {
    log.warn("hvf kernel path not set; skipping kernel load", .{});
    return;
  }
  try readGuestImageFile(kernel_path.?, "kernel");
}

fn loadGuestInitrd(memory_size_bytes: u64, initrd_path: ?[]const u8) !void {
  _ = memory_size_bytes;
  if (initrd_path == null) {
    log.warn("hvf initrd path not set; skipping initrd load", .{});
    return;
  }
  try readGuestImageFile(initrd_path.?, "initrd");
}

pub fn start(cfg: config.VmConfig) !void {
  log.info("hvf backend starting (stub)", .{});
  if (active_vm != null) return error.AlreadyRunning;

  const handle = Hvf.createVm() catch |e| return e;
  errdefer Hvf.deleteVm(handle) catch {};

  try Hvf.setupVm(handle, .{
    .cpu_cores = cfg.cpu_cores,
    .memory_mb = cfg.memory_mb,
  });
  active_vm = handle;

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
  log.info("hvf backend ready (stub)", .{});
}

pub fn stop() !void {
  log.info("hvf backend stopping (stub)", .{});
  vcpu_running.store(false, .seq_cst);
  if (active_vcpu_thread) |t| {
    t.join();
    active_vcpu_thread = null;
  }
  serial_io.clear(std.heap.page_allocator);
  if (active_vm) |handle| {
    Hvf.deleteVm(handle) catch |e| {
      log.err("failed to delete hvf vm: {s}", .{@errorName(e)});
      return e;
    };
    active_vm = null;
  }
  active_memory_size = 0;
}

test "smoke: hvf backend start/stop" {
  if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
  const cfg = try config.defaultConfig(std.testing.allocator, "test");
  var cfg_mut = cfg;
  defer config.freeConfig(std.testing.allocator, &cfg_mut);
  start(cfg_mut) catch |e| switch (e) {
    error.NotImplemented => return error.SkipZigTest,
    else => return e,
  };
  try stop();
}

test "hvf: handleIoExit reads serial data" {
  serial_io.clear(std.testing.allocator);
  serial_io.buf = try std.testing.allocator.dupe(u8, "Z");
  serial_io.offset = 0;
  defer serial_io.clear(std.testing.allocator);

  const b = handleIoExit(.{ .port = 0x3F8, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
  try std.testing.expectEqual(@as(u8, 'Z'), @as(u8, @intCast(b)));

  const lsr = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
  try std.testing.expect((lsr & 0x01) == 0);
}

test "hvf: io exit mapping" {
  const raw = HvfIoExit{
    .port = 0x3F8,
    .access_size = 1,
    .access_type = 1,
    .is_string = false,
    .has_rep = true,
    .rax = 'A',
  };
  const mapped = hvfIoExitToIoExit(raw);
  try std.testing.expectEqual(@as(u16, 0x3F8), mapped.port);
  try std.testing.expect(mapped.is_write);
  try std.testing.expectEqual(@as(usize, 1), mapped.size);
  try std.testing.expectEqual(@as(u64, 'A'), mapped.rax);
  try std.testing.expect(mapped.has_rep);
}

test "hvf: io exit mapping defaults unknown size to 1" {
  const raw = HvfIoExit{
    .port = 0x3F8,
    .access_size = 3,
    .access_type = 0,
    .is_string = false,
    .has_rep = false,
    .rax = 0,
  };
  const mapped = hvfIoExitToIoExit(raw);
  try std.testing.expectEqual(@as(usize, 1), mapped.size);
  try std.testing.expect(!mapped.is_write);
}

test "hvf: prepareGuestImage rejects too small memory" {
  try std.testing.expectError(error.InvalidGuestLayout, prepareGuestImage(0x1000));
}

test "hvf: loadGuestKernel errors on missing file" {
  try std.testing.expectError(error.FileNotFound, loadGuestKernel(64 * 1024 * 1024, "missing-kernel"));
}

test "hvf: loadGuestInitrd errors on missing file" {
  try std.testing.expectError(error.FileNotFound, loadGuestInitrd(64 * 1024 * 1024, "missing-initrd"));
}

test "hvf: loadGuestKernel skips when unset" {
  try loadGuestKernel(64 * 1024 * 1024, null);
}

test "hvf: loadGuestInitrd skips when unset" {
  try loadGuestInitrd(64 * 1024 * 1024, null);
}

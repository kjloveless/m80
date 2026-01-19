const std = @import("std");
const Jailer = @import("../jailer/jailer.zig").Jailer;
const windows = @import("windows.zig");
const hvf = @import("hvf.zig");
const posix = @import("posix.zig");

pub const Vm = struct {
  allocator: std.mem.Allocator,
  jailer: *Jailer,

  pub fn init(
    allocator: std.mem.Allocator,
    jailer: *Jailer,  
  ) !Vm {
    // Vm is a thin dispatcher; platform-specific state lives in backends.
    return Vm{
      .allocator = allocator,
      .jailer = jailer,
    };
  }

  pub fn start(self: *Vm, cfg: @import("../core/config.zig").VmConfig) !void {
    _ = self;
    // Choose backend by host OS; each backend implements start/stop.
    switch (@import("builtin").os.tag) {
      .windows => try windows.start(cfg),
      .macos => try hvf.start(cfg),
      .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.start(cfg),
      else => return error.UnsupportedPlatform,
    }
  }

  pub fn stop(self: *Vm) !void {
    _ = self;
    // Stop mirrors start and delegates to the active backend.
    switch (@import("builtin").os.tag) {
      .windows => try windows.stop(),
      .macos => try hvf.stop(),
      .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.stop(),
      else => return error.UnsupportedPlatform,
    }
  }

  pub fn deinit(self: *Vm) void {
    _ = self;
  }
};

test "smoke: backend start/stop" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var jailer = try Jailer.init(allocator);
  defer jailer.deinit();

  var vm = try Vm.init(allocator, &jailer);
  defer vm.deinit();

  const cfg = try @import("../core/config.zig").defaultConfig(allocator, "test");
  var cfg_mut = cfg;
  defer @import("../core/config.zig").freeConfig(allocator, &cfg_mut);

  vm.start(cfg_mut) catch |e| switch (e) {
    error.NotImplemented,
    => return error.SkipZigTest,
    else => return e,
  };
  try vm.stop();
}

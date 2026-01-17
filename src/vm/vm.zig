const std = @import("std");
const Jailer = @import("../jailer/jailer.zig").Jailer;

pub const Vm = struct {
  allocator: std.mem.Allocator,
  jailer: *Jailer,

  pub fn init(
    allocator: std.mem.Allocator,
    jailer: *Jailer,  
  ) !Vm {
    return Vm{
      .allocator = allocator,
      .jailer = jailer,
    };
  }

  pub fn start(self: *Vm) !void {
    _ = self;
    std.debug.print("[m80] starting vm\n", .{});

    // placeholder: windows backend later
    // hyper-v / wsl / custom microVM
    std.Thread.sleep(std.time.ns_per_s);

    std.debug.print("[m80] vm running\n", .{});
  }

  pub fn deinit(self: *Vm) void {
    _ = self;
  }
};

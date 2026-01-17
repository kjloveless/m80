const std = @import("std");

pub const Jailer = struct {
  allocator: std.mem.Allocator,
  root: []u8,

  pub fn init(allocator: std.mem.Allocator) !Jailer {
    return Jailer{
      .allocator = allocator,
      .root = try allocator.dupe(u8, "C:\\m80\\instances\\default"),
    };
  }

  pub fn prepare(self: *Jailer) !void {
    std.debug.print("[m80] preparing jail at {s}\n", .{self.root});

    try std.fs.cwd().makePath(self.root);

    // future:
    // - drop privileges
    // - acl hardening
    // - filesystem view construction
    // - network namespace binding
  }

  pub fn deinit(self: *Jailer) void {
    self.allocator.free(self.root);
  }
};

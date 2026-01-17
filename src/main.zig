const std = @import("std");
const core = @import("core.zig");
const errors = core.errors;
const state = core.state;

const Vm = @import("vm/vm.zig").Vm;
const Jailer = @import("jailer/jailer.zig").Jailer;

fn printHelp() void {
  std.debug.print(
    \\m80 - windows-native microvm/sandbox manager (scaffold)
    \\
    \\usage:
    \\  m80 init <name>
    \\  m80 start <name>
    \\  m80 stop <name>
    \\  m80 delete <name>
    \\  m80 ps
    \\  m80 inspect <name>
    \\  m80 help
    \\  
  , .{});
}

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  const args = try std.process.argsAlloc(allocator);
  defer std.process.argsFree(allocator, args);

  if (args.len < 2) {
    printHelp();
    return;
  }

  const cmd = args[1];

  if (std.mem.eql(u8, cmd, "help") 
  or std.mem.eql(u8, cmd, "--help") 
  or std.mem.eql(u8, cmd, "-h")) {
    printHelp();
    return;
  }

  if (std.mem.eql(u8, cmd, "ps")) {
    const vms = try state.listVms(allocator);
    defer {
      for (vms) |r| allocator.free(r.name);
      allocator.free(vms);
    }

    if (vms.len == 0) {
      std.debug.print("(no vms)\n", .{});
      return;
    }

    for (vms) |r| {
      std.debug.print("{s}\t{s}\n", .{
        r.name,
        switch (r.status) {
          .running => "running",
          .stopped => "stopped",
        },
      });
    }
    return;
  }

  // commands that need a name
  if (args.len < 3) {
    errors.die("missing <name>", .{});
  }
  const name = args[2];

  if (std.mem.eql(u8, cmd, "init")) {
    state.initVm(allocator, name) catch |e| switch (e) {
      error.AlreadyExists => errors.die("vm already exists: {s}", .{name}),
      else => return e,
    };
    std.debug.print("initialized vm: {s}\n", .{name});
    return;
  }

  if (std.mem.eql(u8, cmd, "delete")) {
    state.deleteVm(allocator, name) catch |e| switch (e) {
      error.NotFound => errors.die("vm not found: {s}", .{name}),
      else => return e,
    };
    std.debug.print("deleted vm: {s}\n", .{name});
    return;
  }

  if (std.mem.eql(u8, cmd, "start")) {
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    try jailer.prepare();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    state.setStatus(allocator, name, .running) catch |e| switch (e) {
      error.NotFound => errors.die("vm not found: {s}\n", .{name}),
      else => return e,
    };
    try vm.start();
    return;
  }

  if (std.mem.eql(u8, cmd, "stop")) {
    // later: hypervisor.stop + jailer.cleanup
    state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
      error.NotFound => errors.die("vm not found: {s}", .{name}),
      else => return e,
    };
    std.debug.print("stopped vm: {s}\n", .{name});
    return;
  }

  if (std.mem.eql(u8, cmd, "inspect")) {
    // placeholder: show paths + status (we'll parse config later)
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const st = core.state.getStatus(vm_dir) catch .stopped;
    std.debug.print("name: {s}\n", .{name});
    std.debug.print("dir: {s}\n", .{dir_path});
    std.debug.print("status: {s}\n", .{switch (st) {
      .running => "running",
      .stopped => "stopped",
    }});
    std.debug.print("config: m80.conf\n", .{});
    return;
  }

  errors.die("unknown command: {s}", .{cmd});
}

test "smoke: help prints" {
  // placeholder to keep `zig build test` working once we add tests
  try std.testing.expect(true);
}

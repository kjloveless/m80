const std = @import("std");
const core = @import("core.zig");
const errors = core.errors;
const state = core.state;
const log = @import("util/log.zig");

const Vm = @import("vm/vm.zig").Vm;
const Jailer = @import("jailer/jailer.zig").Jailer;

fn printHelp() void {
  // Minimal CLI surface for now; config format is intentionally simple.
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

fn fileSizeIfExists(path_opt: ?[]const u8) ?u64 {
  if (path_opt == null) return null;
  const path = path_opt.?;
  const file = if (std.fs.path.isAbsolute(path))
    std.fs.openFileAbsolute(path, .{})
  else
    std.fs.cwd().openFile(path, .{});

  if (file) |f| {
    defer f.close();
    const stat = f.stat() catch return null;
    return stat.size;
  } else |_| {
    return null;
  }
}

fn logPathAndSize(label: []const u8, path_opt: ?[]const u8) void {
  if (path_opt == null) {
    log.debug("{s} path: (unset)", .{label});
    return;
  }
  const path = path_opt.?;
  log.debug("{s} path: {s}", .{ label, path });

  if (fileSizeIfExists(path_opt)) |size| {
    log.debug("{s} size: {d} bytes", .{ label, size });
  } else {
    log.debug("{s} size: (unavailable)", .{label});
  }
}

fn logStartPreflight(cfg: *const core.config.VmConfig) void {
  // Preflight logs are debug-only to avoid leaking host paths by default.
  log.debug("vm start preflight:", .{});
  log.debug("cpu_cores: {d}", .{cfg.cpu_cores});
  log.debug("memory_mb: {d}", .{cfg.memory_mb});
  logPathAndSize("kernel", cfg.kernel_path);
  logPathAndSize("initrd", cfg.initrd_path);
}

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  log.initFromEnv(allocator);

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
  if (!core.paths.validateVmName(name)) {
    errors.die("invalid vm name: {s}", .{name});
  }

  if (std.mem.eql(u8, cmd, "init")) {
    state.initVm(allocator, name) catch |e| switch (e) {
      error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
      error.AlreadyExists => errors.die("vm already exists: {s}", .{name}),
      else => return e,
    };
    std.debug.print("initialized vm: {s}\n", .{name});
    return;
  }

  if (std.mem.eql(u8, cmd, "delete")) {
    state.deleteVm(allocator, name) catch |e| switch (e) {
      error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
      error.NotFound => errors.die("vm not found: {s}", .{name}),
      else => return e,
    };
    std.debug.print("deleted vm: {s}\n", .{name});
    return;
  }

  if (std.mem.eql(u8, cmd, "start")) {
    // start uses the local VM directory for config and path resolution.
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    try jailer.prepare();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| {
      errors.die("invalid config: {s}", .{@errorName(e)});
    };
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);
    try core.config.resolveRelativePaths(allocator, dir_path, &cfg_mut);
    logStartPreflight(&cfg_mut);
    core.config.validateStartConfig(&cfg_mut) catch |e| {
      errors.die("invalid config for start: {s}", .{@errorName(e)});
    };
    core.config.validateStartFiles(&cfg_mut) catch |e| {
      errors.die("invalid config for start: {s}", .{@errorName(e)});
    };

    vm.start(cfg_mut) catch |e| {
      errors.die("start failed: {s}", .{@errorName(e)});
    };
    state.setStatus(allocator, name, .running) catch |e| switch (e) {
      error.InvalidArgs => errors.die("invalid vm name: {s}\n", .{name}),
      error.NotFound => errors.die("vm not found: {s}\n", .{name}),
      else => return e,
    };
    return;
  }

  if (std.mem.eql(u8, cmd, "stop")) {
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    vm.stop() catch |e| {
      errors.die("stop failed: {s}", .{@errorName(e)});
    };

    state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
      error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
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

test "main: fileSizeIfExists returns null for missing file" {
  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
  defer std.testing.allocator.free(base);

  const missing = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ base, "missing" });
  defer std.testing.allocator.free(missing);

  try std.testing.expect(fileSizeIfExists(missing) == null);
}

test "main: fileSizeIfExists returns size for existing file" {
  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  {
    var f = try tmp.dir.createFile("blob", .{});
    defer f.close();
    try f.writeAll("abc");
  }

  const abs = try tmp.dir.realpathAlloc(std.testing.allocator, "blob");
  defer std.testing.allocator.free(abs);

  const size = fileSizeIfExists(abs) orelse return error.TestExpectedEqual;
  try std.testing.expectEqual(@as(u64, 3), size);
}

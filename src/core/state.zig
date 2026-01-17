const std = @import("std");
const paths = @import("paths.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");

pub const VmStatus = enum { stopped, running };

pub const VmRecord = struct {
  name: []const u8,
  status: VmStatus,
};

fn ensureBaseDirs(allocator: std.mem.Allocator) !void {
  const base = try paths.dataDir(allocator);
  defer allocator.free(base);

  var cwd = std.fs.cwd();
  try cwd.makePath(base);

  const vms = try std.fs.path.join(allocator, &[_][]const u8{ base, "vms"  });
  defer allocator.free(vms);
  try cwd.makePath(vms);
}

pub fn initVm(allocator: std.mem.Allocator, name: []const u8) !void {
  try ensureBaseDirs(allocator);

  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  var cwd = std.fs.cwd();

  // if exists, error
  if (cwd.openDir(dir_path, .{})) |d| {
    var h = d;
    h.close();
    return errors.M80Error.AlreadyExists;
  } else |_| {}

  try cwd.makePath(dir_path);

  var vm_dir = try cwd.openDir(dir_path, .{});
  defer vm_dir.close();

  const cfg = try config.defaultConfig(allocator, name);
  defer allocator.free(cfg.name);

  try config.writeConfigFile(vm_dir, cfg);

  // status file (stopped)
  var sf = try vm_dir.createFile("status", .{ .truncate = true });
  defer sf.close();
  try sf.writeAll("stopped\n");
}

pub fn deleteVm(allocator: std.mem.Allocator, name: []const u8) !void {
  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  var cwd = std.fs.cwd();
  // danger: recursively delete vm dir only
  // (we'll harden this later with path validation...)
  cwd.deleteTree(dir_path) catch return errors.M80Error.NotFound;
}

pub fn setStatus(allocator: std.mem.Allocator, name: []const u8, status: VmStatus) !void {
  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  var cwd = std.fs.cwd();
  var vm_dir = cwd.openDir(dir_path, .{}) catch return errors.M80Error.NotFound;
  defer vm_dir.close();

  var sf = try vm_dir.createFile("status", .{ .truncate = true });
  defer sf.close();

  const line = switch (status) {
    .stopped => "stopped\n",
    .running => "running\n",
  };
  try sf.writeAll(line);
}

pub fn getStatus(vm_dir: std.fs.Dir) !VmStatus {
  var f = vm_dir.openFile("status", .{}) catch return .stopped;
  defer f.close();

  var buf: [64]u8 = undefined;
  const n = try f.readAll(&buf);
  const s = std.mem.trim(u8, buf[0..n], " \t\r\n");
  if (std.mem.eql(u8, s, "running")) return .running;
  return .stopped;
}

pub fn listVms(allocator: std.mem.Allocator) ![]VmRecord {
  try ensureBaseDirs(allocator);

  const base = try paths.dataDir(allocator);
  defer allocator.free(base);

  const vms_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "vms"  });
  defer allocator.free(vms_path);

  var cwd = std.fs.cwd();
  var vms_dir = try cwd.openDir(vms_path, .{ .iterate = true  });
  defer vms_dir.close();

  var it = vms_dir.iterate();
  var out: std.ArrayList(VmRecord) = .empty;
  errdefer {
    for (out.items) |r| allocator.free(r.name);
    out.deinit(allocator);
  }

  while (try it.next()) |e| {
    if (e.kind != .directory) continue;

    var vm_dir = vms_dir.openDir(e.name, .{}) catch continue;
    defer vm_dir.close();

    const st = getStatus(vm_dir) catch .stopped;
    try out.append(allocator, .{
      .name = try allocator.dupe(u8, e.name),
      .status = st,
    });
  }

  return try out.toOwnedSlice(allocator);
}

const std = @import("std");
const paths = @import("paths.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");
const path_util = @import("../util/path.zig");

pub const VmStatus = enum { stopped, running };

pub const VmRecord = struct {
  name: []const u8,
  status: VmStatus,
};

fn statusLine(status: VmStatus) []const u8 {
  return switch (status) {
    .stopped => "stopped\n",
    .running => "running\n",
  };
}

fn writeStatusFile(vm_dir: std.fs.Dir, status: VmStatus) !void {
  // Status is a simple sentinel file; last writer wins.
  var sf = try vm_dir.createFile("status", .{ .truncate = true });
  defer sf.close();
  try sf.writeAll(statusLine(status));
}

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

  const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
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
  try writeStatusFile(vm_dir, .stopped);
}

pub fn deleteVm(allocator: std.mem.Allocator, name: []const u8) !void {
  const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
  defer allocator.free(dir_path);

  // Avoid deleting a missing VM directory; map to NotFound early.
  if (std.fs.cwd().openDir(dir_path, .{})) |dir| {
    var d = dir;
    d.close();
  } else |_| {
    return errors.M80Error.NotFound;
  }

  // Get the data root for validation
  const data_root = paths.dataDir(allocator) catch return errors.M80Error.InvalidArgs;
  defer allocator.free(data_root);

  // Use safe deletion with path validation
  // Requires path to be at least 2 levels deep within data root
  path_util.safeDeleteTree(allocator, dir_path, data_root) catch |e| switch (e) {
    path_util.PathError.PathNotWithinRoot,
    path_util.PathError.PathTraversal,
    path_util.PathError.SymlinkEscape,
    path_util.PathError.PathTooShallow => return errors.M80Error.InvalidArgs,
    path_util.PathError.InvalidPath,
    path_util.PathError.AccessDenied => return errors.M80Error.NotFound,
    path_util.PathError.OutOfMemory => return error.OutOfMemory,
  };
}

pub fn setStatus(allocator: std.mem.Allocator, name: []const u8, status: VmStatus) !void {
  const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
  defer allocator.free(dir_path);

  var cwd = std.fs.cwd();
  var vm_dir = cwd.openDir(dir_path, .{}) catch return errors.M80Error.NotFound;
  defer vm_dir.close();

  try writeStatusFile(vm_dir, status);
}

pub fn getStatus(vm_dir: std.fs.Dir) !VmStatus {
  // Missing or malformed status file defaults to stopped.
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

test "state: status transitions" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "test-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };
  defer deleteVm(allocator, name) catch {};

  try setStatus(allocator, name, .running);

  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  var vm_dir = try std.fs.cwd().openDir(dir_path, .{});
  defer vm_dir.close();

  try std.testing.expectEqual(VmStatus.running, try getStatus(vm_dir));

  try setStatus(allocator, name, .stopped);
  try std.testing.expectEqual(VmStatus.stopped, try getStatus(vm_dir));
}

test "state: listVms reflects status" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "list-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };
  defer deleteVm(allocator, name) catch {};

  try setStatus(allocator, name, .running);

  const list = try listVms(allocator);
  defer {
    for (list) |r| allocator.free(r.name);
    allocator.free(list);
  }

  var found = false;
  for (list) |r| {
    if (std.mem.eql(u8, r.name, name)) {
      found = true;
      try std.testing.expectEqual(VmStatus.running, r.status);
    }
  }
  try std.testing.expect(found);
}

test "state: initVm creates config and status files" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "init-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };
  defer deleteVm(allocator, name) catch {};

  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  var vm_dir = try std.fs.cwd().openDir(dir_path, .{});
  defer vm_dir.close();

  var status_file = try vm_dir.openFile("status", .{});
  defer status_file.close();

  var status_buf: [64]u8 = undefined;
  const status_len = try status_file.readAll(&status_buf);
  const status = std.mem.trim(u8, status_buf[0..status_len], " \t\r\n");
  try std.testing.expectEqualStrings("stopped", status);

  const cfg = try config.readConfigFile(allocator, vm_dir, name);
  var cfg_mut = cfg;
  defer config.freeConfig(allocator, &cfg_mut);
  try std.testing.expectEqualStrings(name, cfg_mut.name);
  try std.testing.expect(!cfg_mut.ephemeral);
}

test "state: initVm rejects duplicate names" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "dup-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };
  defer deleteVm(allocator, name) catch {};

  try std.testing.expectError(errors.M80Error.AlreadyExists, initVm(allocator, name));
}

test "state: deleteVm removes record" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "del-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };

  try deleteVm(allocator, name);

  const list = try listVms(allocator);
  defer {
    for (list) |r| allocator.free(r.name);
    allocator.free(list);
  }

  for (list) |r| {
    if (std.mem.eql(u8, r.name, name)) {
      return error.TestExpectedEqual;
    }
  }
}

test "state: initVm deleteVm removes config and status files" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "rm-{s}", .{hex[0..]});

  initVm(allocator, name) catch |e| switch (e) {
    error.AlreadyExists => return error.SkipZigTest,
    else => return e,
  };

  const dir_path = try paths.vmDir(allocator, name);
  defer allocator.free(dir_path);

  {
    var vm_dir = try std.fs.cwd().openDir(dir_path, .{});
    defer vm_dir.close();
    _ = try vm_dir.statFile("m80.conf");
    _ = try vm_dir.statFile("status");
  }

  try deleteVm(allocator, name);

  try std.testing.expectError(error.FileNotFound, std.fs.cwd().openDir(dir_path, .{}));
}

test "state: getStatus defaults to stopped when missing or invalid" {
  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  // Missing status file should default to stopped.
  try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));

  // Invalid contents should also resolve to stopped.
  var f = try tmp.dir.createFile("status", .{ .truncate = true });
  defer f.close();
  try f.writeAll("unknown\n");
  try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));
}

test "state: deleteVm rejects invalid name" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  try std.testing.expectError(errors.M80Error.InvalidArgs, deleteVm(allocator, "../evil"));
}

test "state: deleteVm returns NotFound for missing vm" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "missing-{s}", .{hex[0..]});

  const dir_path = paths.vmDir(allocator, name) catch return error.SkipZigTest;
  defer allocator.free(dir_path);

  if (std.fs.cwd().openDir(dir_path, .{})) |dir| {
    var d = dir;
    d.close();
    return error.SkipZigTest;
  } else |_| {}

  try std.testing.expectError(errors.M80Error.NotFound, deleteVm(allocator, name));
}

test "state: setStatus returns NotFound for missing vm" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var rnd: [8]u8 = undefined;
  std.crypto.random.bytes(&rnd);
  const hex = std.fmt.bytesToHex(rnd, .lower);

  var name_buf: [32]u8 = undefined;
  const name = try std.fmt.bufPrint(&name_buf, "missing-{s}", .{hex[0..]});

  try std.testing.expectError(errors.M80Error.NotFound, setStatus(allocator, name, .running));
}

test "state: getStatus returns stopped on unexpected content" {
  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  {
    var f = try tmp.dir.createFile("status", .{ .truncate = true });
    defer f.close();
    try f.writeAll("gibberish\n");
  }

  try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));
}

test "state: listVms returns empty when data dir is empty" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  const data_root = try tmp.dir.realpathAlloc(allocator, ".");
  defer allocator.free(data_root);

  const vms_path = try std.fs.path.join(allocator, &[_][]const u8{ data_root, "vms" });
  defer allocator.free(vms_path);
  try tmp.dir.makePath("vms");

  var vms_dir = try tmp.dir.openDir("vms", .{ .iterate = true });
  defer vms_dir.close();

  var it = vms_dir.iterate();
  const next = try it.next();
  try std.testing.expect(next == null);
}

test "state: deleteVm returns NotFound for valid but missing name" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  try std.testing.expectError(errors.M80Error.NotFound, deleteVm(allocator, "a"));
}

test "state: initVm rejects invalid name" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  try std.testing.expectError(errors.M80Error.InvalidArgs, initVm(allocator, "../evil"));
}

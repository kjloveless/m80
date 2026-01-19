const std = @import("std");
const paths = @import("paths.zig");
const net_policy = @import("../net/policy.zig");

pub const VmConfig = struct {
  name: []const u8,
  ephemeral: bool = false,

  // placeholder fields for later
  memory_mb: u32 = default_memory_mb,
  cpu_cores: u16 = default_cpu_cores,
  kernel_path: ?[]const u8 = null,
  initrd_path: ?[]const u8 = null,

  // Network configuration
  network_mode: net_policy.NetworkMode = .locked_down,
  allowed_domains: []const []const u8 = &[_][]const u8{},
  allowed_ips: []const []const u8 = &[_][]const u8{},
};

pub const default_memory_mb: u32 = 2048;
pub const default_cpu_cores: u16 = 2;

pub const ConfigError = error{
  InvalidFormat,
  InvalidValue,
  OutOfMemory,
};

pub const StartConfigError = error{
  MissingKernel,
  MissingInitrd,
  KernelNotFound,
  InitrdNotFound,
  KernelUnreadable,
  InitrdUnreadable,
};

pub fn defaultConfig(allocator: std.mem.Allocator, name: []const u8) !VmConfig {
  return VmConfig{
    .name = try allocator.dupe(u8, name),
    .ephemeral = false,
    .memory_mb = default_memory_mb,
    .cpu_cores = default_cpu_cores,
    .kernel_path = null,
    .initrd_path = null,
  };
}

pub fn freeConfig(allocator: std.mem.Allocator, cfg: *VmConfig) void {
  allocator.free(cfg.name);
  cfg.name = "";
  if (cfg.kernel_path) |path| allocator.free(path);
  cfg.kernel_path = null;
  if (cfg.initrd_path) |path| allocator.free(path);
  cfg.initrd_path = null;

  for (cfg.allowed_domains) |d| allocator.free(d);
  if (cfg.allowed_domains.len > 0) allocator.free(cfg.allowed_domains);
  cfg.allowed_domains = &[_][]const u8{};

  for (cfg.allowed_ips) |ip| allocator.free(ip);
  if (cfg.allowed_ips.len > 0) allocator.free(cfg.allowed_ips);
  cfg.allowed_ips = &[_][]const u8{};
}

pub fn readConfigFile(
  allocator: std.mem.Allocator,
  dir: std.fs.Dir,
  fallback_name: []const u8,
) !VmConfig {
  var cfg = try defaultConfig(allocator, fallback_name);
  errdefer freeConfig(allocator, &cfg);

  var file = dir.openFile("m80.conf", .{}) catch return cfg;
  defer file.close();

  const data = try file.readToEndAlloc(allocator, 64 * 1024);
  defer allocator.free(data);

  var it = std.mem.splitScalar(u8, data, '\n');
  while (it.next()) |raw_line| {
    const line = std.mem.trim(u8, raw_line, " \t\r");
    if (line.len == 0) continue;
    if (line[0] == '#') continue;

    const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidFormat;
    const key = std.mem.trim(u8, line[0..eq], " \t\r");
    const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
    if (key.len == 0) return error.InvalidFormat;

    if (std.mem.eql(u8, key, "name")) {
      if (!paths.validateVmName(value)) return error.InvalidValue;
      allocator.free(cfg.name);
      cfg.name = try allocator.dupe(u8, value);
      continue;
    }

    if (std.mem.eql(u8, key, "ephemeral")) {
      cfg.ephemeral = try parseBool(value);
      continue;
    }

    if (std.mem.eql(u8, key, "memory_mb")) {
      cfg.memory_mb = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
      continue;
    }

    if (std.mem.eql(u8, key, "cpu_cores")) {
      cfg.cpu_cores = std.fmt.parseInt(u16, value, 10) catch return error.InvalidValue;
      continue;
    }

    if (std.mem.eql(u8, key, "kernel_path")) {
      try setOptionalPath(allocator, &cfg.kernel_path, value);
      continue;
    }

    if (std.mem.eql(u8, key, "initrd_path")) {
      try setOptionalPath(allocator, &cfg.initrd_path, value);
      continue;
    }

    if (std.mem.eql(u8, key, "network_mode")) {
      cfg.network_mode = net_policy.NetworkMode.fromString(value) orelse return error.InvalidValue;
      continue;
    }

    if (std.mem.eql(u8, key, "allowed_domains")) {
      cfg.allowed_domains = try parseCommaSeparated(allocator, value);
      continue;
    }

    if (std.mem.eql(u8, key, "allowed_ips")) {
      cfg.allowed_ips = try parseCommaSeparated(allocator, value);
      continue;
    }
  }

  return cfg;
}

pub fn resolveRelativePaths(
  allocator: std.mem.Allocator,
  base_dir: []const u8,
  cfg: *VmConfig,
) !void {
  if (cfg.kernel_path) |path| {
    if (!std.fs.path.isAbsolute(path)) {
      const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
      allocator.free(path);
      cfg.kernel_path = joined;
    }
  }
  if (cfg.initrd_path) |path| {
    if (!std.fs.path.isAbsolute(path)) {
      const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
      allocator.free(path);
      cfg.initrd_path = joined;
    }
  }
}

pub fn validateStartConfig(cfg: *const VmConfig) StartConfigError!void {
  if (cfg.kernel_path == null) return error.MissingKernel;
  if (cfg.initrd_path == null) return error.MissingInitrd;
}

pub fn validateStartFiles(cfg: *const VmConfig) StartConfigError!void {
  if (cfg.kernel_path) |path| {
    try checkReadableFile(path, .kernel);
  } else {
    return error.MissingKernel;
  }
  if (cfg.initrd_path) |path| {
    try checkReadableFile(path, .initrd);
  } else {
    return error.MissingInitrd;
  }
}

const StartFileKind = enum { kernel, initrd };

fn checkReadableFile(path: []const u8, kind: StartFileKind) StartConfigError!void {
  const file = if (std.fs.path.isAbsolute(path))
    std.fs.openFileAbsolute(path, .{})
  else
    std.fs.cwd().openFile(path, .{});

  if (file) |f| {
    f.close();
    return;
  } else |e| switch (e) {
    error.FileNotFound => return switch (kind) {
      .kernel => error.KernelNotFound,
      .initrd => error.InitrdNotFound,
    },
    else => return switch (kind) {
      .kernel => error.KernelUnreadable,
      .initrd => error.InitrdUnreadable,
    },
  }
}

fn parseBool(value: []const u8) ConfigError!bool {
  if (std.mem.eql(u8, value, "true")) return true;
  if (std.mem.eql(u8, value, "false")) return false;
  if (std.mem.eql(u8, value, "1")) return true;
  if (std.mem.eql(u8, value, "0")) return false;
  return error.InvalidValue;
}

fn parseCommaSeparated(allocator: std.mem.Allocator, value: []const u8) ![]const []const u8 {
  if (value.len == 0) return &[_][]const u8{};

  var count: usize = 1;
  for (value) |c| {
    if (c == ',') count += 1;
  }

  const result = try allocator.alloc([]const u8, count);
  errdefer allocator.free(result);

  var it = std.mem.splitScalar(u8, value, ',');
  var i: usize = 0;
  while (it.next()) |part| {
    const trimmed = std.mem.trim(u8, part, " \t");
    result[i] = try allocator.dupe(u8, trimmed);
    i += 1;
  }

  return result;
}

fn setOptionalPath(
  allocator: std.mem.Allocator,
  target: *?[]const u8,
  value: []const u8,
) ConfigError!void {
  if (target.*) |path| allocator.free(path);
  if (value.len == 0) {
    target.* = null;
    return;
  }
  target.* = try allocator.dupe(u8, value);
}

// super minimal "format" right now: key=value lines
// we can swap to toml/yaml later without breaking cli commands
pub fn writeConfigFile(dir: std.fs.Dir, cfg: VmConfig) !void {
  var f = try dir.createFile("m80.conf", .{ .truncate = true  });
  defer f.close();

  var buf: [4096]u8 = undefined;
  var fw = f.writer(&buf);
  const w = &fw.interface;

  try w.print("name={s}\n", .{cfg.name});
  try w.print("ephemeral={}\n", .{cfg.ephemeral});
  try w.print("memory_mb={}\n", .{cfg.memory_mb});
  try w.print("cpu_cores={}\n", .{cfg.cpu_cores});
  if (cfg.kernel_path) |path| {
    try w.print("kernel_path={s}\n", .{path});
  }
  if (cfg.initrd_path) |path| {
    try w.print("initrd_path={s}\n", .{path});
  }

  try w.print("network_mode={s}\n", .{cfg.network_mode.toString()});

  if (cfg.allowed_domains.len > 0) {
    try w.writeAll("allowed_domains=");
    for (cfg.allowed_domains, 0..) |d, i| {
      if (i > 0) try w.writeByte(',');
      try w.writeAll(d);
    }
    try w.writeByte('\n');
  }

  if (cfg.allowed_ips.len > 0) {
    try w.writeAll("allowed_ips=");
    for (cfg.allowed_ips, 0..) |ip, i| {
      if (i > 0) try w.writeByte(',');
      try w.writeAll(ip);
    }
    try w.writeByte('\n');
  }

  try w.flush();
}

test "config: parse kernel/initrd paths and overrides" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
  defer f.close();

  try f.writeAll(
    "name=testvm\n" ++
      "ephemeral=true\n" ++
      "memory_mb=4096\n" ++
      "cpu_cores=4\n" ++
      "kernel_path=/kernels/vmlinuz\n" ++
      "initrd_path=/images/initrd.img\n"
  );

  const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
  var cfg_mut = cfg;
  defer freeConfig(allocator, &cfg_mut);

  try std.testing.expectEqualStrings("testvm", cfg_mut.name);
  try std.testing.expect(cfg_mut.ephemeral);
  try std.testing.expectEqual(@as(u32, 4096), cfg_mut.memory_mb);
  try std.testing.expectEqual(@as(u16, 4), cfg_mut.cpu_cores);
  try std.testing.expectEqualStrings("/kernels/vmlinuz", cfg_mut.kernel_path.?);
  try std.testing.expectEqualStrings("/images/initrd.img", cfg_mut.initrd_path.?);
}

test "config: rejects malformed lines and bad values" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  {
    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("this_is_bad\n");
  }
  try std.testing.expectError(error.InvalidFormat, readConfigFile(allocator, tmp.dir, "fallback"));

  {
    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("ephemeral=maybe\n");
  }
  try std.testing.expectError(error.InvalidValue, readConfigFile(allocator, tmp.dir, "fallback"));
}

test "config: resolveRelativePaths joins vm dir" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var cfg = try defaultConfig(allocator, "testvm");
  defer freeConfig(allocator, &cfg);

  cfg.kernel_path = try allocator.dupe(u8, "kernel/bzImage");
  cfg.initrd_path = try allocator.dupe(u8, "initrd.img");

  try resolveRelativePaths(allocator, "/vm/root", &cfg);

  try std.testing.expectEqualStrings("/vm/root/kernel/bzImage", cfg.kernel_path.?);
  try std.testing.expectEqualStrings("/vm/root/initrd.img", cfg.initrd_path.?);
}

test "config: validateStartConfig requires kernel and initrd" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var cfg = try defaultConfig(allocator, "testvm");
  defer freeConfig(allocator, &cfg);

  try std.testing.expectError(error.MissingKernel, validateStartConfig(&cfg));

  cfg.kernel_path = try allocator.dupe(u8, "/kernels/vmlinuz");
  try std.testing.expectError(error.MissingInitrd, validateStartConfig(&cfg));

  cfg.initrd_path = try allocator.dupe(u8, "/images/initrd.img");
  try validateStartConfig(&cfg);
}

test "config: validateStartFiles checks existence" {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  defer _ = gpa.deinit();
  const allocator = gpa.allocator();

  var tmp = std.testing.tmpDir(.{});
  defer tmp.cleanup();

  {
    var f = try tmp.dir.createFile("vmlinuz", .{});
    defer f.close();
    try f.writeAll("kernel");
  }
  {
    var f = try tmp.dir.createFile("initrd.img", .{});
    defer f.close();
    try f.writeAll("initrd");
  }

  const base = try tmp.dir.realpathAlloc(allocator, ".");
  defer allocator.free(base);

  const kernel_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "vmlinuz" });
  defer allocator.free(kernel_path);
  const initrd_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "initrd.img" });
  defer allocator.free(initrd_path);

  var cfg = try defaultConfig(allocator, "testvm");
  defer freeConfig(allocator, &cfg);

  cfg.kernel_path = try allocator.dupe(u8, kernel_path);
  cfg.initrd_path = try allocator.dupe(u8, initrd_path);
  try validateStartFiles(&cfg);

  allocator.free(cfg.kernel_path.?);
  cfg.kernel_path = try allocator.dupe(u8, "missing-kernel");
  try std.testing.expectError(error.KernelNotFound, validateStartFiles(&cfg));
}

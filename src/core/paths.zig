const std = @import("std");

pub const VmNameError = error{ InvalidName };
const max_name_len: usize = 64;

pub fn validateVmName(name: []const u8) bool {
  if (name.len == 0 or name.len > max_name_len) return false;

  // Names are simple and filesystem-safe to reduce traversal risk.
  for (name) |c| {
    if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_') continue;
    return false;
  }
  return true;
}

pub fn dataDir(allocator: std.mem.Allocator) ![]u8 {
  // windows: %localappdata%\m80
  if (@import("builtin").os.tag == .windows) {
    const local = std.process.getEnvVarOwned(allocator, "LOCALAPPDATA") catch null;
    if (local) |base| {
      defer allocator.free(base);
      return try std.fs.path.join(allocator, &[_][]const u8{ base, "m80" });
    }
  }

  // fallback: $XDG_DATA_HOME/m80 or ~/.local/share/m80
  const xdg = std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME") catch null;
  if (xdg) |base| {
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &[_][]const u8{ base, "m80" });
  }

  const home = std.process.getEnvVarOwned(allocator, "HOME") catch null;
  if (home) |h| {
    defer allocator.free(h);
    return try std.fs.path.join(allocator, &[_][]const u8{ h, ".local", "share", "m80" });
  }

  // last resort
  return try allocator.dupe(u8, "m80-data");
}

pub fn vmDir(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
  if (!validateVmName(name)) return error.InvalidName;
  const base = try dataDir(allocator);
  defer allocator.free(base);
  return try std.fs.path.join(allocator, &[_][]const u8{ base, "vms", name });
}

test "vm name validation" {
  try std.testing.expect(validateVmName("abc-123_OK"));
  try std.testing.expect(!validateVmName(""));
  try std.testing.expect(!validateVmName(".."));
  try std.testing.expect(!validateVmName("../evil"));
  try std.testing.expect(!validateVmName("bad/name"));

  var max_buf: [max_name_len]u8 = undefined;
  @memset(&max_buf, 'a');
  try std.testing.expect(validateVmName(&max_buf));

  var too_long: [max_name_len + 1]u8 = undefined;
  @memset(&too_long, 'b');
  try std.testing.expect(!validateVmName(&too_long));
}

test "paths: dataDir returns m80 path" {
  const allocator = std.testing.allocator;
  const path = try dataDir(allocator);
  defer allocator.free(path);

  try std.testing.expect(path.len > 0);
  try std.testing.expect(std.mem.indexOf(u8, path, "m80") != null);
}

test "paths: vmDir rejects invalid name" {
  const allocator = std.testing.allocator;
  try std.testing.expectError(error.InvalidName, vmDir(allocator, "../evil"));
}

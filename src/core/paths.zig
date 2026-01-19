const std = @import("std");

pub const VmNameError = error{ InvalidName };
const max_name_len: usize = 64;

pub fn validateVmName(name: []const u8) bool {
  if (name.len == 0 or name.len > max_name_len) return false;

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

  // fallback: $xdg_data_home/m80 or ~/.local/share/m80
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
}

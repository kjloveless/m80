const std = @import("std");

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
  const base = try dataDir(allocator);
  defer allocator.free(base);
  return try std.fs.path.join(allocator, &[_][]const u8{ base, "vms", name });
}

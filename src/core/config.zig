const std = @import("std");

pub const VmConfig = struct {
  name: []const u8,
  ephemeral: bool = false,

  // placeholder fields for later
  memory_mb: u32 = 2048,
  cpu_cores: u16 = 2,
};

pub fn defaultConfig(allocator: std.mem.Allocator, name: []const u8) !VmConfig {
  return VmConfig{
    .name = try allocator.dupe(u8, name),
    .ephemeral = false,
    .memory_mb = 2048,
    .cpu_cores = 2,
  };
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
  try w.flush();
}

//! Logging Utility
//!
//! Provides structured logging with configurable severity levels.
//! Output is written to stderr with timestamps for debugging.
//!
//! ## Log Levels
//! Levels are ordered by severity (lowest to highest):
//! - `debug`: Verbose debugging information
//! - `info`: General operational messages
//! - `warn`: Warning conditions that may need attention
//! - `err`: Error conditions that affect operation
//!
//! Messages are only printed if their level is >= the current threshold.
//!
//! ## Configuration
//! Set `M80_LOG_LEVEL` environment variable: debug, info, warn, error
//! Default level is `info`.
//!
//! ## Output Format
//! [timestamp_ms] LEVEL message

const std = @import("std");

pub const Level = enum {
  debug,
  info,
  warn,
  err,
};

pub var level: Level = .info;
var log_file: ?std.fs.File = null;

pub fn initFromEnv(allocator: std.mem.Allocator) void {
  if (std.process.getEnvVarOwned(allocator, "M80_LOG_LEVEL")) |raw| {
    defer allocator.free(raw);
    if (raw.len != 0) {
      if (std.mem.eql(u8, raw, "debug")) {
        level = .debug;
      } else if (std.mem.eql(u8, raw, "info")) {
        level = .info;
      } else if (std.mem.eql(u8, raw, "warn")) {
        level = .warn;
      } else if (std.mem.eql(u8, raw, "error") or std.mem.eql(u8, raw, "err")) {
        level = .err;
      }
    }
  } else |_| {}

  const path = std.process.getEnvVarOwned(allocator, "M80_LOG_FILE") catch return;
  defer allocator.free(path);
  if (path.len == 0) return;
  if (std.fs.cwd().createFile(path, .{ .truncate = true })) |file| {
    log_file = file;
  } else |_| {}
}

fn levelTag(lvl: Level) []const u8 {
  return switch (lvl) {
    .debug => "DEBUG",
    .info => "INFO",
    .warn => "WARN",
    .err => "ERROR",
  };
}

fn levelValue(lvl: Level) u8 {
  return switch (lvl) {
    .debug => 0,
    .info => 1,
    .warn => 2,
    .err => 3,
  };
}

fn enabled(lvl: Level) bool {
  // Higher value means higher severity; enabled when message severity >= current level.
  return levelValue(lvl) >= levelValue(level);
}

pub fn log(lvl: Level, comptime fmt: []const u8, args: anytype) void {
  if (!enabled(lvl)) return;
  // Timestamp is milliseconds since epoch; used for quick local tracing.
  const ts_ms = std.time.milliTimestamp();
  if (log_file) |file| {
    var buf: [2048]u8 = undefined;
    const msg = std.fmt.bufPrint(
      &buf,
      "[{d}] {s} " ++ fmt ++ "\n",
      .{ ts_ms, levelTag(lvl) } ++ args,
    ) catch return;
    _ = file.writeAll(msg) catch return;
  } else {
    std.debug.print("[{d}] {s} " ++ fmt ++ "\n", .{ ts_ms, levelTag(lvl) } ++ args);
  }
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
  log(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
  log(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
  log(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
  log(.err, fmt, args);
}

// =============================================================================
// TESTS
// =============================================================================

test "log: enabled respects level ordering" {
  const saved = level;
  defer level = saved;

  level = .info;
  try std.testing.expect(!enabled(.debug));
  try std.testing.expect(enabled(.info));
  try std.testing.expect(enabled(.err));

  level = .err;
  try std.testing.expect(!enabled(.warn));
  try std.testing.expect(enabled(.err));
}

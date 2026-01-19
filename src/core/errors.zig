const std = @import("std");

pub const M80Error = error{
  InvalidArgs,
  UnknownCommand,
  NotFound,
  AlreadyExists,
};

pub fn die(comptime fmt: []const u8, args: anytype) noreturn {
  // Centralized fatal error for CLI; always exits with status 1.
  std.debug.print(fmt ++ "\n", args);
  std.process.exit(1);
}

test "errors: M80Error names are stable" {
  try std.testing.expectEqualStrings("InvalidArgs", @errorName(M80Error.InvalidArgs));
  try std.testing.expectEqualStrings("UnknownCommand", @errorName(M80Error.UnknownCommand));
  try std.testing.expectEqualStrings("NotFound", @errorName(M80Error.NotFound));
  try std.testing.expectEqualStrings("AlreadyExists", @errorName(M80Error.AlreadyExists));
}

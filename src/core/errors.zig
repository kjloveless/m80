const std = @import("std");

pub const M80Error = error{
  InvalidArgs,
  UnknownCommand,
  NotFound,
  AlreadyExists,
};

pub fn die(comptime fmt: []const u8, args: anytype) noreturn {
  std.debug.print(fmt ++ "\n", args);
  std.process.exit(1);
}

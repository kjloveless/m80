//! Error Types Module
//!
//! This module defines the common error types used throughout m80.
//! These errors represent user-facing problems (not internal bugs).
//!
//! ## Error Handling Philosophy
//! - M80Error: User errors that should be reported with helpful messages
//! - System errors (Zig's std errors): Bubble up to caller
//! - Fatal errors: Use die() to print message and exit immediately

const std = @import("std");

/// Common errors returned by m80 operations.
/// These represent user-correctable problems, not internal bugs.
pub const M80Error = error{
    /// Invalid arguments (bad VM name, malformed config, etc.)
    InvalidArgs,
    /// Unknown CLI command
    UnknownCommand,
    /// Requested resource (VM, file) doesn't exist
    NotFound,
    /// Resource already exists (e.g., creating VM with existing name)
    AlreadyExists,
};

/// Prints an error message to stderr and exits with status code 1.
///
/// Use this for fatal errors where the program cannot continue.
/// The message is automatically appended with a newline.
///
/// This function never returns (noreturn) - it always exits the process.
///
/// Example:
/// ```zig
/// if (cfg.kernel_path == null) {
///     errors.die("kernel_path not set in config", .{});
/// }
/// ```
pub fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(1);
}

// =============================================================================
// TESTS
// =============================================================================

// Verifies that error names are stable (important for error message consistency).
test "errors: M80Error names are stable" {
    try std.testing.expectEqualStrings("InvalidArgs", @errorName(M80Error.InvalidArgs));
    try std.testing.expectEqualStrings("UnknownCommand", @errorName(M80Error.UnknownCommand));
    try std.testing.expectEqualStrings("NotFound", @errorName(M80Error.NotFound));
    try std.testing.expectEqualStrings("AlreadyExists", @errorName(M80Error.AlreadyExists));
}

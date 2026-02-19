//! Path Management Module
//!
//! This module handles path construction and validation for m80's data directories.
//! It provides platform-specific paths and validates VM names to prevent security issues.
//!
//! ## Data Directory Locations
//! - Windows: %LOCALAPPDATA%\m80 (e.g., C:\Users\<user>\AppData\Local\m80)
//! - Linux/macOS: $XDG_DATA_HOME/m80 or ~/.local/share/m80
//!
//! ## VM Directory Structure
//! Each VM gets a subdirectory under {data_dir}/vms/{name}/:
//! ```
//! ~/.local/share/m80/
//!   └── vms/
//!       ├── my-web-server/
//!       │   ├── m80.conf
//!       │   └── status
//!       └── test-vm/
//!           ├── m80.conf
//!           └── status
//! ```
//!
//! ## Security
//! VM names are strictly validated to prevent path traversal attacks:
//! - Only alphanumeric characters, hyphens, and underscores allowed
//! - Maximum length of 64 characters
//! - No dots, slashes, or other special characters

const std = @import("std");
const builtin = @import("builtin");

/// Error returned when a VM name fails validation.
pub const VmNameError = error{InvalidName};

/// Maximum allowed length for VM names (prevents excessively long paths).
const max_name_len: usize = 64;

/// Validates a VM name for filesystem safety.
///
/// Valid names:
/// - Must be 1-64 characters long
/// - Can only contain: a-z, A-Z, 0-9, hyphen (-), underscore (_)
///
/// Invalid names (rejected):
/// - Empty string
/// - Names over 64 characters
/// - Names containing: / \ . spaces or other special characters
/// - Path traversal attempts like "..", "../evil", etc.
///
/// Example valid names: "my-vm", "test_server_1", "WebApp"
/// Example invalid names: "../evil", "my vm", "test.vm", ""
pub fn validateVmName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;

    // Only allow simple, filesystem-safe characters to prevent traversal attacks
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_') continue;
        return false;
    }
    return true;
}

/// Returns the platform-specific data directory for m80.
///
/// Resolution order:
/// 1. Windows: %LOCALAPPDATA%\m80
/// 2. POSIX: $XDG_DATA_HOME/m80 (if XDG_DATA_HOME is set)
/// 3. POSIX: $HOME/.local/share/m80 (standard location)
/// 4. Fallback: "m80-data" in current directory (last resort)
///
/// Returns: Allocator-owned path string (caller must free)
pub fn dataDir(allocator: std.mem.Allocator) ![]u8 {
    // windows: %localappdata%\m80
    if (builtin.os.tag == .windows) {
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

/// Returns the full path to a VM's data directory.
///
/// Combines the data directory with "vms/{name}" to get the full path.
/// Validates the VM name before constructing the path.
///
/// Parameters:
///   - allocator: Memory allocator for the returned path
///   - name: VM name (must pass validateVmName)
///
/// Returns: Allocator-owned path string (caller must free)
///
/// Errors:
///   - error.InvalidName: VM name contains invalid characters
pub fn vmDir(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    if (!validateVmName(name)) return error.InvalidName;
    const base = try dataDir(allocator);
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &[_][]const u8{ base, "vms", name });
}

// =============================================================================
// TESTS
// =============================================================================

// Tests VM name validation with various valid and invalid inputs.
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

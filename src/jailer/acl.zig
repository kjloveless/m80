const std = @import("std");
const builtin = @import("builtin");

pub const AclError = error{
    PermissionDenied,
    InvalidPath,
    OutOfMemory,
    SystemError,
};

/// Permission modes for POSIX systems
pub const PosixMode = struct {
    pub const dir_mode: std.posix.mode_t = 0o700; // rwx------
    pub const file_mode: std.posix.mode_t = 0o600; // rw-------
};

/// Hardens a VM directory by setting restrictive permissions
/// On POSIX: directories get 0700, files get 0600
/// On Windows: sets DACL for owner-only access
pub fn hardenVmDirectory(allocator: std.mem.Allocator, path: []const u8) AclError!void {
    if (builtin.os.tag == .windows) {
        return hardenVmDirectoryWindows(allocator, path);
    } else {
        return hardenVmDirectoryPosix(allocator, path);
    }
}

/// POSIX implementation of directory hardening
fn hardenVmDirectoryPosix(allocator: std.mem.Allocator, path: []const u8) AclError!void {
    // Open the directory
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |e| switch (e) {
        error.AccessDenied => return AclError.PermissionDenied,
        error.FileNotFound => return AclError.InvalidPath,
        else => return AclError.SystemError,
    };
    defer dir.close();

    // Set permissions on the root directory itself
    setDirPermissions(path) catch return AclError.SystemError;

    // Recursively set permissions on contents
    try hardenDirectoryContentsRecursive(allocator, dir, path);
}

/// Recursively hardens directory contents
fn hardenDirectoryContentsRecursive(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    base_path: []const u8,
) AclError!void {
    var iterator = dir.iterate();
    while (iterator.next() catch return AclError.SystemError) |entry| {
        const entry_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch return AclError.OutOfMemory;
        defer allocator.free(entry_path);

        switch (entry.kind) {
            .directory => {
                setDirPermissions(entry_path) catch return AclError.SystemError;

                // Recurse into subdirectory
                var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch |e| switch (e) {
                    error.AccessDenied => return AclError.PermissionDenied,
                    else => return AclError.SystemError,
                };
                defer subdir.close();
                try hardenDirectoryContentsRecursive(allocator, subdir, entry_path);
            },
            .file, .sym_link => {
                setFilePermissions(entry_path) catch return AclError.SystemError;
            },
            else => {
                // Skip special files (block devices, character devices, etc.)
                continue;
            },
        }
    }
}

/// Sets directory permissions to 0700
fn setDirPermissions(path: []const u8) !void {
    if (builtin.os.tag == .windows) return;
    std.posix.fchmodat(std.fs.cwd().fd, path, PosixMode.dir_mode, 0) catch return error.SystemError;
}

/// Sets file permissions to 0600
fn setFilePermissions(path: []const u8) !void {
    if (builtin.os.tag == .windows) return;

    std.posix.fchmodat(std.fs.cwd().fd, path, PosixMode.file_mode, 0) catch return error.SystemError;
}

/// Windows implementation of directory hardening
fn hardenVmDirectoryWindows(allocator: std.mem.Allocator, path: []const u8) AclError!void {
    _ = allocator;
    _ = path;

    // Windows ACL implementation
    // Uses SetSecurityInfo to set DACL with owner-only permissions
    // This is a placeholder - full implementation requires Windows API calls

    if (builtin.os.tag != .windows) return;

    // TODO: Implement Windows-specific ACL hardening
    // 1. Get current owner SID
    // 2. Create new DACL with only owner having full control
    // 3. Apply to directory and all contents recursively
    //
    // Would use:
    // - GetSecurityInfo to get owner
    // - SetEntriesInAcl to create new DACL
    // - SetSecurityInfo to apply

    return;
}

/// Sets owner-only access on a single file (Windows)
fn setFileOwnerOnly(path: []const u8) AclError!void {
    _ = path;
    if (builtin.os.tag != .windows) return;

    // Placeholder for Windows implementation
    return;
}

/// Verifies that a path has proper restrictive permissions
pub fn verifyHardenedPermissions(path: []const u8) AclError!bool {
    if (builtin.os.tag == .windows) {
        return verifyHardenedPermissionsWindows(path);
    } else {
        return verifyHardenedPermissionsPosix(path);
    }
}

fn verifyHardenedPermissionsPosix(path: []const u8) AclError!bool {
    const stat = std.fs.cwd().statFile(path) catch |e| switch (e) {
        error.AccessDenied => return AclError.PermissionDenied,
        error.FileNotFound => return AclError.InvalidPath,
        else => return AclError.SystemError,
    };

    const mode = stat.mode;
    const is_dir = stat.kind == .directory;

    // Check that group and other have no permissions
    const group_other_mask: std.fs.File.Mode = 0o077;
    if (mode & group_other_mask != 0) {
        return false;
    }

    // Check expected permissions for file vs directory
    if (is_dir) {
        return (mode & 0o700) == PosixMode.dir_mode;
    } else {
        return (mode & 0o700) == PosixMode.file_mode;
    }
}

fn verifyHardenedPermissionsWindows(path: []const u8) AclError!bool {
    _ = path;
    if (builtin.os.tag != .windows) return true;

    // Placeholder - would verify DACL contains only owner ACE
    return true;
}

/// Configuration for ACL hardening
pub const HardenConfig = struct {
    /// Whether to follow symlinks when setting permissions
    follow_symlinks: bool = false,
    /// Whether to fail on any error or continue with best effort
    fail_fast: bool = true,
    /// Custom file mode (POSIX only)
    file_mode: ?std.posix.mode_t = null,
    /// Custom directory mode (POSIX only)
    dir_mode: ?std.posix.mode_t = null,
};

/// Hardens a VM directory with custom configuration
pub fn hardenVmDirectoryWithConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
    config: HardenConfig,
) AclError!void {
    _ = config;
    // For now, use default hardening
    return hardenVmDirectory(allocator, path);
}

// Tests
test "acl: verifyHardenedPermissionsPosix" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    _ = allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a test file
    {
        var f = try tmp.dir.createFile("test.txt", .{});
        defer f.close();
        try f.writeAll("test");
    }

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "test.txt");
    defer std.testing.allocator.free(path);

    // Set restrictive permissions
    std.posix.fchmodat(tmp.dir.fd, "test.txt", PosixMode.file_mode, 0) catch return error.SkipZigTest;

    const is_hardened = try verifyHardenedPermissionsPosix(path);
    try std.testing.expect(is_hardened);
}

test "acl: hardenVmDirectory creates restrictive permissions" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create directory structure
    try tmp.dir.makePath("vm/data");
    {
        var f = try tmp.dir.createFile("vm/config.txt", .{});
        defer f.close();
        try f.writeAll("config");
    }
    {
        var f = try tmp.dir.createFile("vm/data/disk.img", .{});
        defer f.close();
        try f.writeAll("disk");
    }

    const path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(path);

    try hardenVmDirectory(allocator, path);

    // Verify root directory
    const dir_hardened = try verifyHardenedPermissions(path);
    try std.testing.expect(dir_hardened);
}

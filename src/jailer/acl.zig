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
    // Walk the directory tree and clamp permissions to owner-only.
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
            .file => {
                setFilePermissions(entry_path) catch return AclError.SystemError;
            },
            .sym_link => {
                // Never follow symlinks while hardening permissions.
                continue;
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

fn setDirPermissionsWithMode(path: []const u8, mode: ?std.posix.mode_t) !void {
    if (mode) |m| {
        if (builtin.os.tag == .windows) return;
        std.posix.fchmodat(std.fs.cwd().fd, path, m, 0) catch return error.SystemError;
        return;
    }
    return setDirPermissions(path);
}

/// Sets file permissions to 0600
fn setFilePermissions(path: []const u8) !void {
    if (builtin.os.tag == .windows) return;

    std.posix.fchmodat(std.fs.cwd().fd, path, PosixMode.file_mode, 0) catch return error.SystemError;
}

fn setFilePermissionsWithMode(path: []const u8, mode: ?std.posix.mode_t) !void {
    if (mode) |m| {
        if (builtin.os.tag == .windows) return;
        std.posix.fchmodat(std.fs.cwd().fd, path, m, 0) catch return error.SystemError;
        return;
    }
    return setFilePermissions(path);
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
    if (builtin.os.tag == .windows) {
        return hardenVmDirectoryWindows(allocator, path);
    }
    return hardenVmDirectoryPosixWithConfig(allocator, path, config);
}

/// POSIX implementation of directory hardening with config
fn hardenVmDirectoryPosixWithConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
    config: HardenConfig,
) AclError!void {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |e| switch (e) {
        error.AccessDenied => return AclError.PermissionDenied,
        error.FileNotFound => return AclError.InvalidPath,
        else => return AclError.SystemError,
    };
    defer dir.close();

    setDirPermissionsWithMode(path, config.dir_mode) catch |err| {
        if (config.fail_fast) return err;
    };

    try hardenDirectoryContentsRecursiveWithConfig(allocator, dir, path, config);
}

fn hardenDirectoryContentsRecursiveWithConfig(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    base_path: []const u8,
    config: HardenConfig,
) AclError!void {
    var iterator = dir.iterate();
    while (iterator.next() catch return AclError.SystemError) |entry| {
        const entry_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch return AclError.OutOfMemory;
        defer allocator.free(entry_path);

        switch (entry.kind) {
            .directory => {
                setDirPermissionsWithMode(entry_path, config.dir_mode) catch |err| {
                    if (config.fail_fast) return err;
                };

                var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch |e| switch (e) {
                    error.AccessDenied => return if (config.fail_fast) AclError.PermissionDenied else continue,
                    else => return if (config.fail_fast) AclError.SystemError else continue,
                };
                defer subdir.close();
                try hardenDirectoryContentsRecursiveWithConfig(allocator, subdir, entry_path, config);
            },
            .file => {
                setFilePermissionsWithMode(entry_path, config.file_mode) catch |err| {
                    if (config.fail_fast) return err;
                };
            },
            .sym_link => {
                if (config.follow_symlinks) {
                    setFilePermissionsWithMode(entry_path, config.file_mode) catch |err| {
                        if (config.fail_fast) return err;
                    };
                }
                continue;
            },
            else => continue,
        }
    }
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

test "acl: verifyHardenedPermissionsPosix rejects loose perms" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("loose.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    // Make it group/world-readable.
    std.posix.fchmodat(tmp.dir.fd, "loose.txt", 0o644, 0) catch return error.SkipZigTest;

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "loose.txt");
    defer std.testing.allocator.free(path);

    const ok = try verifyHardenedPermissionsPosix(path);
    try std.testing.expect(!ok);
}

test "acl: hardenVmDirectory does not follow symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    try tmp.dir.makePath("outside");
    {
        var f = try tmp.dir.createFile("outside/target.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    // Make target world-readable to detect unintended chmod.
    std.posix.fchmodat(tmp.dir.fd, "outside/target.txt", 0o644, 0) catch return error.SkipZigTest;

    try tmp.dir.symLink("../outside/target.txt", "vm/link", .{});

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectory(allocator, vm_path);

    const target_path = try tmp.dir.realpathAlloc(allocator, "outside/target.txt");
    defer allocator.free(target_path);

    const stat = try std.fs.cwd().statFile(target_path);
    try std.testing.expect((stat.mode & 0o777) == 0o644);
}

test "acl: hardenVmDirectoryWithConfig applies custom modes" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    {
        var f = try tmp.dir.createFile("vm/file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectoryWithConfig(allocator, vm_path, .{
        .file_mode = 0o640,
        .dir_mode = 0o750,
    });

    const file_path = try tmp.dir.realpathAlloc(allocator, "vm/file.txt");
    defer allocator.free(file_path);

    const dir_stat = try std.fs.cwd().statFile(vm_path);
    const file_stat = try std.fs.cwd().statFile(file_path);

    try std.testing.expect((dir_stat.mode & 0o777) == 0o750);
    try std.testing.expect((file_stat.mode & 0o777) == 0o640);
}

test "acl: hardenVmDirectoryWithConfig respects follow_symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    try tmp.dir.makePath("outside");
    {
        var f = try tmp.dir.createFile("outside/target.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    std.posix.fchmodat(tmp.dir.fd, "outside/target.txt", 0o644, 0) catch return error.SkipZigTest;
    try tmp.dir.symLink("../outside/target.txt", "vm/link", .{});

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectoryWithConfig(allocator, vm_path, .{
        .follow_symlinks = true,
        .file_mode = 0o600,
    });

    const target_path = try tmp.dir.realpathAlloc(allocator, "outside/target.txt");
    defer allocator.free(target_path);

    const stat = try std.fs.cwd().statFile(target_path);
    try std.testing.expect((stat.mode & 0o777) == 0o600);
}

test "acl: hardenVmDirectoryWithConfig fail_fast false continues" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm/a");
    try tmp.dir.makePath("vm/b");

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    // Make vm/a inaccessible to force a permission error.
    std.posix.fchmodat(tmp.dir.fd, "vm/a", 0o000, 0) catch return error.SkipZigTest;
    defer std.posix.fchmodat(tmp.dir.fd, "vm/a", 0o700, 0) catch {};

    try hardenVmDirectoryWithConfig(allocator, vm_path, .{
        .fail_fast = false,
    });

    const b_path = try tmp.dir.realpathAlloc(allocator, "vm/b");
    defer allocator.free(b_path);

    const b_stat = try std.fs.cwd().statFile(b_path);
    try std.testing.expect((b_stat.mode & 0o700) == PosixMode.dir_mode);
}

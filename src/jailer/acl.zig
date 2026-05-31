//! Access Control List (ACL) Module
//!
//! This module handles filesystem permission hardening for VM directories.
//! It ensures that VM data is only accessible by the owner, protecting
//! sensitive information like disk images and configuration files.
//!
//! ## POSIX Implementation
//! Uses chmod to set restrictive permissions:
//! - Directories: 0700 (rwx------) - owner only
//! - Files: 0600 (rw-------) - owner only
//!
//! ## Windows Implementation
//! Uses Windows Security APIs to set owner-only DACLs:
//! - GetNamedSecurityInfoW: Read current owner
//! - SetEntriesInAclW: Build new ACL with owner-only access
//! - SetNamedSecurityInfoW: Apply the ACL
//!
//! ## Security Notes
//! - Symlinks are NOT followed by default to prevent escape attacks
//! - Special files (devices, sockets) are skipped
//! - Recursive traversal hardens all contents

const std = @import("std");
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const windows = std.os.windows;

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
        return hardenVmDirectoryWindowsWithConfig(allocator, path, .{});
    } else {
        return hardenVmDirectoryPosix(allocator, path);
    }
}

/// POSIX implementation of directory hardening
fn hardenVmDirectoryPosix(allocator: std.mem.Allocator, path: []const u8) AclError!void {
    // Open the directory
    var dir = fs.cwd().openDir(path, .{ .iterate = true }) catch |e| switch (e) {
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
    dir: fs.Dir,
    base_path: []const u8,
) AclError!void {
    // Walk the directory tree and clamp permissions to owner-only.
    var iterator = dir.iterate();
    while (iterator.next() catch return AclError.SystemError) |entry| {
        const entry_path = fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch return AclError.OutOfMemory;
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
    fs.chmodAt(fs.cwd().fd, path, PosixMode.dir_mode, 0) catch return error.SystemError;
}

fn setDirPermissionsWithMode(path: []const u8, mode: ?std.posix.mode_t) !void {
    if (mode) |m| {
        if (builtin.os.tag == .windows) return;
        fs.chmodAt(fs.cwd().fd, path, m, 0) catch return error.SystemError;
        return;
    }
    return setDirPermissions(path);
}

/// Sets file permissions to 0600
fn setFilePermissions(path: []const u8) !void {
    if (builtin.os.tag == .windows) return;

    fs.chmodAt(fs.cwd().fd, path, PosixMode.file_mode, 0) catch return error.SystemError;
}

fn setFilePermissionsWithMode(path: []const u8, mode: ?std.posix.mode_t) !void {
    if (mode) |m| {
        if (builtin.os.tag == .windows) return;
        fs.chmodAt(fs.cwd().fd, path, m, 0) catch return error.SystemError;
        return;
    }
    return setFilePermissions(path);
}

/// Windows implementation of directory hardening
fn hardenVmDirectoryWindows(allocator: std.mem.Allocator, path: []const u8) AclError!void {
    return hardenVmDirectoryWindowsWithConfig(allocator, path, .{});
}

/// Sets owner-only access on a single file (Windows)
fn setFileOwnerOnly(path: []const u8) AclError!void {
    if (builtin.os.tag != .windows) return;
    try applyOwnerOnlyAcl(std.heap.page_allocator, path, false);
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
    const stat = fs.cwd().statFile(path) catch |e| switch (e) {
        error.AccessDenied => return AclError.PermissionDenied,
        error.FileNotFound => return AclError.InvalidPath,
        else => return AclError.SystemError,
    };

    const mode = stat.mode;
    const is_dir = stat.kind == .directory;

    // Check that group and other have no permissions
    const group_other_mask: fs.File.Mode = 0o077;
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
    if (builtin.os.tag != .windows) return true;

    const allocator = std.heap.page_allocator;
    const wide = try utf16ZFromUtf8Alloc(allocator, path);
    defer allocator.free(wide);

    var owner: PSID = null;
    var dacl: PACL = null;
    var sec_desc: PSECURITY_DESCRIPTOR = null;

    const err = GetNamedSecurityInfoW(
        wide.ptr,
        SE_OBJECT_TYPE.SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner,
        null,
        &dacl,
        null,
        &sec_desc,
    );
    if (err != 0) return mapWindowsAclError(err);
    defer _ = LocalFree(sec_desc);

    if (owner == null or dacl == null) return false;

    const acl: *const ACL = @ptrCast(@alignCast(dacl.?));
    if (acl.AceCount == 0) return false;

    var i: u16 = 0;
    while (i < acl.AceCount) : (i += 1) {
        var ace_ptr: ?*anyopaque = null;
        const ok = GetAce(dacl, i, &ace_ptr);
        if (ok == 0 or ace_ptr == null) return false;

        const header: *const ACE_HEADER = @ptrCast(@alignCast(ace_ptr.?));
        if (header.AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
        if ((header.AceFlags & INHERITANCE_FLAGS_MASK) != 0) return false;

        const allowed: *const ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(ace_ptr.?));
        if (allowed.Mask != FILE_ALL_ACCESS) return false;
        const ace_sid: PSID = @ptrCast(@constCast(&allowed.SidStart));
        if (EqualSid(owner.?, ace_sid) == 0) return false;
    }
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
        return hardenVmDirectoryWindowsWithConfig(allocator, path, config);
    }
    return hardenVmDirectoryPosixWithConfig(allocator, path, config);
}

/// POSIX implementation of directory hardening with config
fn hardenVmDirectoryPosixWithConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
    config: HardenConfig,
) AclError!void {
    var dir = fs.cwd().openDir(path, .{ .iterate = true }) catch |e| switch (e) {
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
    dir: fs.Dir,
    base_path: []const u8,
    config: HardenConfig,
) AclError!void {
    var iterator = dir.iterate();
    while (iterator.next() catch return AclError.SystemError) |entry| {
        const entry_path = fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch return AclError.OutOfMemory;
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

// ---- Windows ACL helpers ----
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const LPWSTR = windows.LPWSTR;
const PSID = ?*anyopaque;
const PACL = ?*anyopaque;
const PSECURITY_DESCRIPTOR = ?*anyopaque;

const SE_OBJECT_TYPE = enum(u32) {
    SE_FILE_OBJECT = 1,
};

const ACCESS_MODE = enum(u32) {
    NOT_USED_ACCESS = 0,
    GRANT_ACCESS = 1,
    SET_ACCESS = 2,
    DENY_ACCESS = 3,
    REVOKE_ACCESS = 4,
    SET_AUDIT_SUCCESS = 5,
    SET_AUDIT_FAILURE = 6,
};

const TRUSTEE_FORM = enum(u32) {
    TRUSTEE_IS_SID = 0,
};

const TRUSTEE_TYPE = enum(u32) {
    TRUSTEE_IS_USER = 1,
};

const MULTIPLE_TRUSTEE_OPERATION = enum(u32) {
    NO_MULTIPLE_TRUSTEE = 0,
};

const TRUSTEE_W = extern struct {
    pMultipleTrustee: ?*anyopaque,
    MultipleTrusteeOperation: MULTIPLE_TRUSTEE_OPERATION,
    TrusteeForm: TRUSTEE_FORM,
    TrusteeType: TRUSTEE_TYPE,
    ptstrName: ?*anyopaque,
};

const EXPLICIT_ACCESSW = extern struct {
    grfAccessPermissions: DWORD,
    grfAccessMode: ACCESS_MODE,
    grfInheritance: DWORD,
    Trustee: TRUSTEE_W,
};

const ACL = extern struct {
    AclRevision: u8,
    Sbz1: u8,
    AclSize: u16,
    AceCount: u16,
    Sbz2: u16,
};

const ACE_HEADER = extern struct {
    AceType: u8,
    AceFlags: u8,
    AceSize: u16,
};

const ACCESS_ALLOWED_ACE = extern struct {
    Header: ACE_HEADER,
    Mask: DWORD,
    SidStart: DWORD,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
const INHERITED_ACE: u8 = 0x10;
const INHERITANCE_FLAGS_MASK: u8 = 0x1F;

const SECURITY_INFORMATION = u32;
const OWNER_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x00000001;
const DACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x00000004;
const PROTECTED_DACL_SECURITY_INFORMATION: SECURITY_INFORMATION = 0x80000000;

const ERROR_ACCESS_DENIED: DWORD = 5;
const ERROR_FILE_NOT_FOUND: DWORD = 2;
const ERROR_PATH_NOT_FOUND: DWORD = 3;

const FILE_ALL_ACCESS: DWORD = 0x1F01FF;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: DWORD = 0x3;

extern "advapi32" fn GetNamedSecurityInfoW(
    pObjectName: LPWSTR,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    ppsidOwner: *PSID,
    ppsidGroup: ?*PSID,
    ppDacl: *PACL,
    ppSacl: ?*PACL,
    ppSecurityDescriptor: *PSECURITY_DESCRIPTOR,
) callconv(windows.WINAPI) DWORD;

extern "advapi32" fn SetNamedSecurityInfoW(
    pObjectName: LPWSTR,
    ObjectType: SE_OBJECT_TYPE,
    SecurityInfo: SECURITY_INFORMATION,
    psidOwner: PSID,
    psidGroup: PSID,
    pDacl: PACL,
    pSacl: PACL,
) callconv(windows.WINAPI) DWORD;

extern "advapi32" fn SetEntriesInAclW(
    cCountOfExplicitEntries: DWORD,
    pListOfExplicitEntries: *const EXPLICIT_ACCESSW,
    OldAcl: PACL,
    NewAcl: *PACL,
) callconv(windows.WINAPI) DWORD;

extern "advapi32" fn GetAce(
    pAcl: PACL,
    dwAceIndex: DWORD,
    pAce: *?*anyopaque,
) callconv(windows.WINAPI) BOOL;

extern "advapi32" fn EqualSid(
    pSid1: PSID,
    pSid2: PSID,
) callconv(windows.WINAPI) BOOL;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(windows.WINAPI) ?*anyopaque;

fn utf16ZFromUtf8Alloc(allocator: std.mem.Allocator, path: []const u8) AclError![:0]u16 {
    const utf16 = std.unicode.utf8ToUtf16LeAlloc(allocator, path) catch |e| switch (e) {
        error.OutOfMemory => return AclError.OutOfMemory,
        else => return AclError.InvalidPath,
    };
    defer allocator.free(utf16);

    const out = allocator.alloc(u16, utf16.len + 1) catch return AclError.OutOfMemory;
    @memcpy(out[0..utf16.len], utf16);
    out[utf16.len] = 0;
    return out[0..utf16.len :0];
}

fn mapWindowsAclError(err: DWORD) AclError {
    switch (err) {
        ERROR_ACCESS_DENIED => return AclError.PermissionDenied,
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND => return AclError.InvalidPath,
        else => return AclError.SystemError,
    }
}

fn applyOwnerOnlyAcl(allocator: std.mem.Allocator, path: []const u8, inherit: bool) AclError!void {
    const wide = try utf16ZFromUtf8Alloc(allocator, path);
    defer allocator.free(wide);

    var owner: PSID = null;
    var sec_desc: PSECURITY_DESCRIPTOR = null;
    var ignored_dacl: PACL = null;

    const err_owner = GetNamedSecurityInfoW(
        wide.ptr,
        SE_OBJECT_TYPE.SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &owner,
        null,
        &ignored_dacl,
        null,
        &sec_desc,
    );
    if (err_owner != 0) return mapWindowsAclError(err_owner);
    defer _ = LocalFree(sec_desc);
    if (owner == null) return AclError.SystemError;

    var explicit = EXPLICIT_ACCESSW{
        .grfAccessPermissions = FILE_ALL_ACCESS,
        .grfAccessMode = .SET_ACCESS,
        .grfInheritance = if (inherit) SUB_CONTAINERS_AND_OBJECTS_INHERIT else 0,
        .Trustee = .{
            .pMultipleTrustee = null,
            .MultipleTrusteeOperation = .NO_MULTIPLE_TRUSTEE,
            .TrusteeForm = .TRUSTEE_IS_SID,
            .TrusteeType = .TRUSTEE_IS_USER,
            .ptstrName = owner,
        },
    };

    var new_acl: PACL = null;
    const err_acl = SetEntriesInAclW(1, &explicit, null, &new_acl);
    if (err_acl != 0) return mapWindowsAclError(err_acl);
    defer _ = LocalFree(new_acl);

    const sec_info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    const err_set = SetNamedSecurityInfoW(
        wide.ptr,
        SE_OBJECT_TYPE.SE_FILE_OBJECT,
        sec_info,
        null,
        null,
        new_acl,
        null,
    );
    if (err_set != 0) return mapWindowsAclError(err_set);
}

fn hardenVmDirectoryWindowsWithConfig(
    allocator: std.mem.Allocator,
    path: []const u8,
    config: HardenConfig,
) AclError!void {
    if (builtin.os.tag != .windows) return;

    var dir = fs.cwd().openDir(path, .{ .iterate = true }) catch |e| switch (e) {
        error.AccessDenied => return AclError.PermissionDenied,
        error.FileNotFound => return AclError.InvalidPath,
        else => return AclError.SystemError,
    };
    defer dir.close();

    applyOwnerOnlyAcl(allocator, path, true) catch |err| {
        if (config.fail_fast) return err;
    };

    try hardenDirectoryContentsRecursiveWindows(allocator, dir, path, config);
}

fn hardenDirectoryContentsRecursiveWindows(
    allocator: std.mem.Allocator,
    dir: fs.Dir,
    base_path: []const u8,
    config: HardenConfig,
) AclError!void {
    var iterator = dir.iterate();
    while (iterator.next() catch return AclError.SystemError) |entry| {
        const entry_path = fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch return AclError.OutOfMemory;
        defer allocator.free(entry_path);

        switch (entry.kind) {
            .directory => {
                applyOwnerOnlyAcl(allocator, entry_path, true) catch |err| {
                    if (config.fail_fast) return err;
                };

                var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch |e| switch (e) {
                    error.AccessDenied => return if (config.fail_fast) AclError.PermissionDenied else continue,
                    else => return if (config.fail_fast) AclError.SystemError else continue,
                };
                defer subdir.close();
                try hardenDirectoryContentsRecursiveWindows(allocator, subdir, entry_path, config);
            },
            .file => {
                applyOwnerOnlyAcl(allocator, entry_path, false) catch |err| {
                    if (config.fail_fast) return err;
                };
            },
            .sym_link => {
                if (config.follow_symlinks) {
                    applyOwnerOnlyAcl(allocator, entry_path, false) catch |err| {
                        if (config.fail_fast) return err;
                    };
                }
                continue;
            },
            else => continue,
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

test "acl: verifyHardenedPermissionsPosix" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    _ = allocator;

    var tmp = fs.testingTmpDir(.{});
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
    fs.chmodAt(tmp.dir.fd, "test.txt", PosixMode.file_mode, 0) catch return error.SkipZigTest;

    const is_hardened = try verifyHardenedPermissionsPosix(path);
    try std.testing.expect(is_hardened);
}

test "acl: hardenVmDirectory windows owner-only" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    {
        var f = try tmp.dir.createFile("vm/file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectory(allocator, vm_path);

    const ok = try verifyHardenedPermissions(vm_path);
    try std.testing.expect(ok);
}

test "acl: hardenVmDirectory creates restrictive permissions" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
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

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("loose.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    // Make it group/world-readable.
    fs.chmodAt(tmp.dir.fd, "loose.txt", 0o644, 0) catch return error.SkipZigTest;

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "loose.txt");
    defer std.testing.allocator.free(path);

    const ok = try verifyHardenedPermissionsPosix(path);
    try std.testing.expect(!ok);
}

test "acl: hardenVmDirectory does not follow symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    try tmp.dir.makePath("outside");
    {
        var f = try tmp.dir.createFile("outside/target.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    // Make target world-readable to detect unintended chmod.
    fs.chmodAt(tmp.dir.fd, "outside/target.txt", 0o644, 0) catch return error.SkipZigTest;

    try tmp.dir.symLink("../outside/target.txt", "vm/link", .{});

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectory(allocator, vm_path);

    const target_path = try tmp.dir.realpathAlloc(allocator, "outside/target.txt");
    defer allocator.free(target_path);

    const stat = try fs.cwd().statFile(target_path);
    try std.testing.expect((stat.mode & 0o777) == 0o644);
}

test "acl: hardenVmDirectoryWithConfig applies custom modes" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
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

    const dir_stat = try fs.cwd().statFile(vm_path);
    const file_stat = try fs.cwd().statFile(file_path);

    try std.testing.expect((dir_stat.mode & 0o777) == 0o750);
    try std.testing.expect((file_stat.mode & 0o777) == 0o640);
}

test "acl: hardenVmDirectoryWithConfig respects follow_symlinks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm");
    try tmp.dir.makePath("outside");
    {
        var f = try tmp.dir.createFile("outside/target.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    fs.chmodAt(tmp.dir.fd, "outside/target.txt", 0o644, 0) catch return error.SkipZigTest;
    try tmp.dir.symLink("../outside/target.txt", "vm/link", .{});

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    try hardenVmDirectoryWithConfig(allocator, vm_path, .{
        .follow_symlinks = true,
        .file_mode = 0o600,
    });

    const target_path = try tmp.dir.realpathAlloc(allocator, "outside/target.txt");
    defer allocator.free(target_path);

    const stat = try fs.cwd().statFile(target_path);
    try std.testing.expect((stat.mode & 0o777) == 0o600);
}

test "acl: hardenVmDirectoryWithConfig fail_fast false continues" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("vm/a");
    try tmp.dir.makePath("vm/b");

    const vm_path = try tmp.dir.realpathAlloc(allocator, "vm");
    defer allocator.free(vm_path);

    // Make vm/a inaccessible to force a permission error.
    fs.chmodAt(tmp.dir.fd, "vm/a", 0o000, 0) catch return error.SkipZigTest;
    defer fs.chmodAt(tmp.dir.fd, "vm/a", 0o700, 0) catch {};

    try hardenVmDirectoryWithConfig(allocator, vm_path, .{
        .fail_fast = false,
    });

    const b_path = try tmp.dir.realpathAlloc(allocator, "vm/b");
    defer allocator.free(b_path);

    const b_stat = try fs.cwd().statFile(b_path);
    try std.testing.expect((b_stat.mode & 0o700) == PosixMode.dir_mode);
}

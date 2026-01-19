const std = @import("std");
const builtin = @import("builtin");
const paths = @import("../core/paths.zig");
const log = @import("../util/log.zig");
const acl = @import("acl.zig");

/// Configuration for the jailer
pub const JailerConfig = struct {
    /// Target user ID to drop privileges to (POSIX)
    target_uid: ?u32 = null,
    /// Target group ID to drop privileges to (POSIX)
    target_gid: ?u32 = null,
    /// Whether to enable chroot isolation
    chroot_enabled: bool = false,
    /// Path to chroot into (if chroot_enabled)
    chroot_path: ?[]const u8 = null,
    /// Resource limits
    limits: ResourceLimits = .{},
    /// Whether to harden directory permissions
    harden_permissions: bool = true,
};

/// Resource limits for the jailed process
pub const ResourceLimits = struct {
    /// Maximum number of open file descriptors
    max_files: ?u64 = 1024,
    /// Maximum number of processes
    max_procs: ?u64 = 64,
    /// Maximum address space size in bytes (0 = unlimited)
    max_address_space: ?u64 = null,
    /// Maximum core dump size (0 = disabled)
    max_core: ?u64 = 0,
    /// Maximum CPU time in seconds (0 = unlimited)
    max_cpu_time: ?u64 = null,
};

pub const JailerError = error{
    PrivilegeDropFailed,
    PrivilegeVerifyFailed,
    ChrootFailed,
    ResourceLimitFailed,
    PermissionDenied,
    InvalidConfig,
    OutOfMemory,
};

pub const Jailer = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    config: JailerConfig,

    pub fn init(allocator: std.mem.Allocator) !Jailer {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: JailerConfig) !Jailer {
        const base = try paths.dataDir(allocator);
        defer allocator.free(base);
        const root = try std.fs.path.join(allocator, &[_][]const u8{ base, "instances", "default" });
        return Jailer{
            .allocator = allocator,
            .root = root,
            .config = config,
        };
    }

    pub fn prepare(self: *Jailer) !void {
        log.info("preparing jail at {s}", .{self.root});

        try std.fs.cwd().makePath(self.root);

        // Harden directory permissions
        if (self.config.harden_permissions) {
            acl.hardenVmDirectory(self.allocator, self.root) catch |e| {
                log.err("failed to harden permissions: {}", .{e});
                // Continue anyway - not fatal
            };
        }

        // Set resource limits (before dropping privileges)
        if (builtin.os.tag != .windows) {
            try setResourceLimits(self.config.limits);
        }

        // Chroot if configured
        if (self.config.chroot_enabled) {
            if (self.config.chroot_path) |chroot_path| {
                try performChroot(chroot_path);
            } else {
                try performChroot(self.root);
            }
        }

        // Drop privileges if configured
        if (self.config.target_uid != null or self.config.target_gid != null) {
            try dropPrivileges(self.config.target_gid, self.config.target_uid);
            try verifyPrivilegesDropped();
        }
    }

    pub fn deinit(self: *Jailer) void {
        self.allocator.free(self.root);
    }
};

/// Drops privileges to the specified UID/GID
/// Must be called in correct order: setgroups, setgid, setuid
pub fn dropPrivileges(target_gid: ?u32, target_uid: ?u32) JailerError!void {
    if (builtin.os.tag == .windows) {
        // Windows doesn't have POSIX privilege model
        return;
    }

    // Drop supplementary groups first
    dropSupplementaryGroups() catch return JailerError.PrivilegeDropFailed;

    // Set GID before UID (required order)
    if (target_gid) |gid| {
        setGid(gid) catch return JailerError.PrivilegeDropFailed;
    }

    // Set UID last
    if (target_uid) |uid| {
        setUid(uid) catch return JailerError.PrivilegeDropFailed;
    }

    log.info("privileges dropped to uid={?}, gid={?}", .{ target_uid, target_gid });
}

/// Verifies that privileges have been successfully dropped
/// Attempts to regain root - if successful, dropping failed
pub fn verifyPrivilegesDropped() JailerError!void {
    if (builtin.os.tag == .windows) return;

    // Try to set UID to 0 - this should fail if privileges were dropped
    std.posix.setuid(0) catch {
        // Expected: we can't become root
        log.info("privilege drop verified - cannot regain root", .{});
        return;
    };

    // We were able to become root again - privilege drop failed!
    log.err("SECURITY: privilege drop verification failed - was able to regain root", .{});
    return JailerError.PrivilegeVerifyFailed;
}

/// Drops all supplementary groups
fn dropSupplementaryGroups() !void {
    if (builtin.os.tag == .windows) return;

    // On Linux, use syscall directly
    if (builtin.os.tag == .linux) {
        const result = std.os.linux.syscall(.setgroups, .{ 0, @as(usize, 0) });
        if (@as(isize, @bitCast(result)) < 0) {
            log.err("setgroups failed", .{});
            return error.SystemError;
        }
        return;
    }

    // On macOS/BSD, setgroups is available but we skip for safety
    // This is a no-op on non-Linux for now
}

/// Sets the effective and real GID
fn setGid(gid: u32) !void {
    if (builtin.os.tag == .windows) return;

    std.posix.setgid(gid) catch |e| {
        log.err("setgid failed: {}", .{e});
        return error.SystemError;
    };
}

/// Sets the effective and real UID
fn setUid(uid: u32) !void {
    if (builtin.os.tag == .windows) return;

    std.posix.setuid(uid) catch |e| {
        log.err("setuid failed: {}", .{e});
        return error.SystemError;
    };
}

/// Performs chroot to the specified path
fn performChroot(path: []const u8) JailerError!void {
    if (builtin.os.tag == .windows) return;

    // chroot is Linux-specific via syscall
    if (builtin.os.tag == .linux) {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len >= path_buf.len) return JailerError.InvalidConfig;

        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;

        const result = std.os.linux.syscall(.chroot, .{@intFromPtr(&path_buf)});
        if (@as(isize, @bitCast(result)) < 0) {
            log.err("chroot to {s} failed", .{path});
            return JailerError.ChrootFailed;
        }

        std.posix.chdir("/") catch |e| {
            log.err("chdir after chroot failed: {}", .{e});
            return JailerError.ChrootFailed;
        };

        log.info("chroot to {s} successful", .{path});
        return;
    }

    // chroot not supported on this platform
    log.warn("chroot not supported on this platform", .{});
}

/// Sets resource limits using setrlimit
pub fn setResourceLimits(limits: ResourceLimits) JailerError!void {
    if (builtin.os.tag == .windows) return;

    // RLIMIT_NOFILE - max open files
    if (limits.max_files) |max_files| {
        try setRlimit(.NOFILE, max_files);
    }

    // RLIMIT_NPROC - max processes
    if (limits.max_procs) |max_procs| {
        try setRlimit(.NPROC, max_procs);
    }

    // RLIMIT_AS - max address space
    if (limits.max_address_space) |max_as| {
        try setRlimit(.AS, max_as);
    }

    // RLIMIT_CORE - max core dump size
    if (limits.max_core) |max_core| {
        try setRlimit(.CORE, max_core);
    }

    // RLIMIT_CPU - max CPU time
    if (limits.max_cpu_time) |max_cpu| {
        try setRlimit(.CPU, max_cpu);
    }

    log.info("resource limits set", .{});
}

/// Sets a single resource limit
fn setRlimit(resource: std.posix.rlimit_resource, value: u64) JailerError!void {
    const limit = std.posix.rlimit{
        .cur = value,
        .max = value,
    };

    std.posix.setrlimit(resource, limit) catch |e| {
        log.err("setrlimit for {} failed: {}", .{ resource, e });
        return JailerError.ResourceLimitFailed;
    };
}

/// Gets the current UID
pub fn getCurrentUid() u32 {
    if (builtin.os.tag == .windows) return 0;
    return std.posix.getuid();
}

/// Gets the current GID
pub fn getCurrentGid() u32 {
    if (builtin.os.tag == .windows) return 0;
    return std.posix.getgid();
}

/// Checks if running as root
pub fn isRoot() bool {
    if (builtin.os.tag == .windows) return false;
    return getCurrentUid() == 0;
}

/// Gets the effective UID
pub fn getEffectiveUid() u32 {
    if (builtin.os.tag == .windows) return 0;
    return std.posix.geteuid();
}

/// Gets the effective GID
pub fn getEffectiveGid() u32 {
    if (builtin.os.tag == .windows) return 0;
    return std.posix.getegid();
}

// Tests
test "jailer: init and deinit" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    try std.testing.expect(jailer.root.len > 0);
}

test "jailer: config defaults" {
    const config = JailerConfig{};
    try std.testing.expect(config.target_uid == null);
    try std.testing.expect(config.target_gid == null);
    try std.testing.expect(!config.chroot_enabled);
    try std.testing.expect(config.harden_permissions);
}

test "jailer: resource limits defaults" {
    const limits = ResourceLimits{};
    try std.testing.expectEqual(@as(?u64, 1024), limits.max_files);
    try std.testing.expectEqual(@as(?u64, 64), limits.max_procs);
    try std.testing.expectEqual(@as(?u64, 0), limits.max_core);
}

test "jailer: getCurrentUid returns value" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const uid = getCurrentUid();
    // Just verify it returns something - value depends on who runs the test
    _ = uid;
}

test "jailer: isRoot check" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const root = isRoot();
    // If UID is 0, should be root. Otherwise not.
    try std.testing.expectEqual(getCurrentUid() == 0, root);
}

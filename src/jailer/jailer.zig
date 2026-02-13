//! Security Jailer Module
//!
//! The jailer provides defense-in-depth security for VM processes by:
//! - Dropping privileges from root to a less-privileged user
//! - Setting resource limits (max files, processes, memory)
//! - Optionally chrooting to restrict filesystem access
//! - Hardening directory permissions
//!
//! ## Why Jailing Matters
//! Even with hardware virtualization, bugs in the hypervisor or host kernel
//! could allow guest escape. The jailer ensures that even if escape occurs,
//! the attacker has limited capabilities (no root, restricted resources).
//!
//! ## Privilege Drop Order
//! POSIX requires a specific order for dropping privileges:
//! 1. setgroups(0, NULL) - Drop supplementary groups
//! 2. setgid(gid) - Set group ID
//! 3. setuid(uid) - Set user ID (cannot be undone)
//!
//! The uid must be set LAST because once set, you can't regain root to
//! complete the other steps.
//!
//! ## Resource Limits (setrlimit)
//! - RLIMIT_NOFILE: Max open file descriptors (default: 1024)
//! - RLIMIT_NPROC: Max processes/threads (default: 64)
//! - RLIMIT_AS: Max address space (optional)
//! - RLIMIT_CORE: Max core dump size (default: 0 = disabled)
//! - RLIMIT_CPU: Max CPU time in seconds (optional)
//!
//! ## Platform Support
//! - Linux: Full support (chroot, setuid, setrlimit)
//! - macOS: Partial support (setuid, setrlimit, no chroot)
//! - Windows: Stub (different privilege model)

const std = @import("std");
const builtin = @import("builtin");
const paths = @import("../core/paths.zig");
const vm_config = @import("../core/config.zig");
const log = @import("../util/log.zig");
const acl = @import("acl.zig");
const seccomp = @import("seccomp.zig");
const sandbox_darwin = @import("sandbox_darwin.zig");
const sandbox_windows = @import("sandbox_windows.zig");

extern "c" fn getgid() std.posix.gid_t;
extern "c" fn getegid() std.posix.gid_t;
extern "c" fn setgroups(size: c_int, list: ?*const std.posix.gid_t) c_int;

pub const EnforcementMode = enum {
    off,
    observe,
    strict,

    pub fn fromString(value: []const u8) ?EnforcementMode {
        if (std.mem.eql(u8, value, "off")) return .off;
        if (std.mem.eql(u8, value, "observe")) return .observe;
        if (std.mem.eql(u8, value, "strict")) return .strict;
        return null;
    }
};

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
    /// Runtime platform hardening behavior when seccomp/sandbox setup fails.
    enforcement_mode: EnforcementMode = .observe,
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
    SecurityPolicyFailed,
    PermissionDenied,
    InvalidConfig,
    OutOfMemory,
};

pub const Jailer = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    config: JailerConfig,

    pub fn init(allocator: std.mem.Allocator) !Jailer {
        var cfg = JailerConfig{};
        cfg.enforcement_mode = readEnforcementModeFromEnv(allocator);
        return initWithConfig(allocator, cfg);
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, jailer_config: JailerConfig) !Jailer {
        const base = try paths.dataDir(allocator);
        defer allocator.free(base);
        const root = try std.fs.path.join(allocator, &[_][]const u8{ base, "instances", "default" });
        return Jailer{
            .allocator = allocator,
            .root = root,
            .config = jailer_config,
        };
    }

    pub fn prepare(self: *Jailer) !void {
        try self.prepareForVm(null, null);
    }

    pub fn prepareForVm(self: *Jailer, vm_dir: ?[]const u8, vm_cfg: ?*const vm_config.VmConfig) !void {
        // Prepare enforces filesystem + resource constraints before VM startup.
        log.info("preparing jail at {s}", .{self.root});

        try std.fs.cwd().makePath(self.root);

        // Harden directory permissions.
        if (self.config.harden_permissions) {
            acl.hardenVmDirectory(self.allocator, self.root) catch |e| {
                log.err("failed to harden permissions: {}", .{e});
                // Continue anyway - not fatal
            };
        }

        // Set resource limits before dropping privileges.
        if (builtin.os.tag != .windows) {
            try setResourceLimits(self.config.limits);
        }

        // Chroot if configured.
        if (self.config.chroot_enabled) {
            if (self.config.chroot_path) |chroot_path| {
                try performChroot(chroot_path);
            } else {
                try performChroot(self.root);
            }
        }

        // Drop privileges if configured.
        if (self.config.target_uid != null or self.config.target_gid != null) {
            try dropPrivileges(self.config.target_gid, self.config.target_uid);
            try verifyPrivilegesDropped();
        }

        try applyPlatformHardening(self, vm_dir, vm_cfg);
    }

    pub fn deinit(self: *Jailer) void {
        self.allocator.free(self.root);
    }
};

fn readEnforcementModeFromEnv(allocator: std.mem.Allocator) EnforcementMode {
    const raw = std.process.getEnvVarOwned(allocator, "M80_JAILER_ENFORCEMENT") catch return .observe;
    defer allocator.free(raw);
    return EnforcementMode.fromString(raw) orelse blk: {
        log.warn("invalid M80_JAILER_ENFORCEMENT={s}; using observe", .{raw});
        break :blk .observe;
    };
}

fn effectiveVmDir(root: []const u8, vm_dir: ?[]const u8) ?[]const u8 {
    return vm_dir orelse root;
}

fn allowSandboxNetwork(vm_cfg: ?*const vm_config.VmConfig) bool {
    const cfg = vm_cfg orelse return false;
    return cfg.network_mode != .locked_down;
}

fn maybePath(vm_cfg: ?*const vm_config.VmConfig, comptime field: []const u8) ?[]const u8 {
    const cfg = vm_cfg orelse return null;
    return @field(cfg, field);
}

fn handleHardeningFailure(mode: EnforcementMode, component: []const u8, err_name: []const u8) JailerError!void {
    switch (mode) {
        .off => return,
        .observe => {
            log.warn("jailer {s} hardening failed: {s} (mode=observe; continuing)", .{ component, err_name });
            return;
        },
        .strict => {
            log.err("jailer {s} hardening failed: {s} (mode=strict)", .{ component, err_name });
            return JailerError.SecurityPolicyFailed;
        },
    }
}

fn applyLinuxSeccomp(self: *Jailer) JailerError!void {
    seccomp.applyVmmSeccompFilter(self.allocator) catch |e| {
        try handleHardeningFailure(self.config.enforcement_mode, "seccomp", @errorName(e));
    };
}

fn applyDarwinSandbox(self: *Jailer, vm_dir: ?[]const u8, vm_cfg: ?*const vm_config.VmConfig) JailerError!void {
    const options = sandbox_darwin.VmmSandboxOptions{
        .vm_directory = effectiveVmDir(self.root, vm_dir),
        .allow_write_vm_dir = true,
        .kernel_path = maybePath(vm_cfg, "kernel_path"),
        .initrd_path = maybePath(vm_cfg, "initrd_path"),
        .disk_path = maybePath(vm_cfg, "disk_path"),
        .seed_path = maybePath(vm_cfg, "seed_path"),
        .data_disk_path = maybePath(vm_cfg, "data_disk_path"),
        .allow_network = allowSandboxNetwork(vm_cfg),
    };
    sandbox_darwin.applyVmmSandbox(self.allocator, options) catch |e| {
        try handleHardeningFailure(self.config.enforcement_mode, "darwin-sandbox", @errorName(e));
    };
}

fn applyWindowsSandbox(self: *Jailer) JailerError!void {
    const options = sandbox_windows.VmmSandboxOptions{
        .memory_limit = self.config.limits.max_address_space,
        .allow_clipboard = false,
    };
    sandbox_windows.applyVmmSandbox(self.allocator, options) catch |e| {
        try handleHardeningFailure(self.config.enforcement_mode, "windows-job-object", @errorName(e));
    };
}

fn applyPlatformHardening(self: *Jailer, vm_dir: ?[]const u8, vm_cfg: ?*const vm_config.VmConfig) JailerError!void {
    if (builtin.is_test and vm_cfg == null and vm_dir == null) return;
    if (self.config.enforcement_mode == .off) return;
    switch (builtin.os.tag) {
        .linux => try applyLinuxSeccomp(self),
        .macos => try applyDarwinSandbox(self, vm_dir, vm_cfg),
        .windows => try applyWindowsSandbox(self),
        else => {},
    }
}

fn integrationEnvEnabled(allocator: std.mem.Allocator, name: []const u8) bool {
    const value = std.process.getEnvVarOwned(allocator, name) catch return false;
    defer allocator.free(value);
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "false")) return false;
    return true;
}

fn requireIntegrationEnv(name: []const u8) !void {
    if (!integrationEnvEnabled(std.testing.allocator, name)) {
        return error.SkipZigTest;
    }
}

fn integrationTestJailerConfig(mode: EnforcementMode) JailerConfig {
    return .{
        .harden_permissions = false,
        .enforcement_mode = mode,
        .limits = .{
            .max_files = null,
            .max_procs = null,
            .max_address_space = null,
            .max_core = null,
            .max_cpu_time = null,
        },
    };
}

fn buildIntegrationVmConfig(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) !vm_config.VmConfig {
    var cfg = try vm_config.defaultConfig(allocator, "jailer-integration");
    errdefer vm_config.freeConfig(allocator, &cfg);

    {
        var kernel = try tmp.dir.createFile("kernel", .{ .truncate = true });
        defer kernel.close();
        try kernel.writeAll("kernel");
    }
    {
        var initrd = try tmp.dir.createFile("initrd", .{ .truncate = true });
        defer initrd.close();
        try initrd.writeAll("initrd");
    }

    const vm_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(vm_dir);
    cfg.kernel_path = try std.fs.path.join(allocator, &[_][]const u8{ vm_dir, "kernel" });
    cfg.initrd_path = try std.fs.path.join(allocator, &[_][]const u8{ vm_dir, "initrd" });
    cfg.network_mode = .locked_down;
    return cfg;
}

/// Drops privileges to the specified UID/GID
/// Must be called in correct order: setgroups, setgid, setuid
pub fn dropPrivileges(target_gid: ?u32, target_uid: ?u32) JailerError!void {
    if (builtin.os.tag == .windows) {
        // Windows doesn't have POSIX privilege model
        return;
    }

    // Drop supplementary groups first.
    dropSupplementaryGroups() catch return JailerError.PrivilegeDropFailed;

    // Set GID before UID (required order).
    if (target_gid) |gid| {
        setGid(gid) catch return JailerError.PrivilegeDropFailed;
    }

    // Set UID last.
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

    // POSIX path (macOS/BSD): clear supplemental groups explicitly.
    if (setgroups(0, null) != 0) {
        log.err("setgroups failed", .{});
        return error.SystemError;
    }
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
    if (builtin.os.tag == .linux) {
        return @intCast(std.os.linux.getgid());
    }
    return @intCast(getgid());
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
    if (builtin.os.tag == .linux) {
        return @intCast(std.os.linux.getegid());
    }
    return @intCast(getegid());
}

// =============================================================================
// TESTS
// =============================================================================

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
    try std.testing.expectEqual(EnforcementMode.observe, config.enforcement_mode);
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

test "jailer: prepare creates root directory" {
    const allocator = std.testing.allocator;
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    try jailer.prepare();
    const stat = try std.fs.cwd().statFile(jailer.root);
    try std.testing.expectEqual(std.fs.File.Kind.directory, stat.kind);
}

test "jailer: prepare with no harden and no limits" {
    const allocator = std.testing.allocator;
    var jailer = try Jailer.initWithConfig(allocator, .{
        .harden_permissions = false,
        .limits = .{
            .max_files = null,
            .max_procs = null,
            .max_address_space = null,
            .max_core = null,
            .max_cpu_time = null,
        },
    });
    defer jailer.deinit();

    try jailer.prepare();
    const stat = try std.fs.cwd().statFile(jailer.root);
    try std.testing.expectEqual(std.fs.File.Kind.directory, stat.kind);
}

test "jailer: getEffectiveUid returns value" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const euid = getEffectiveUid();
    // Just verify it returns something
    _ = euid;
}

test "jailer: getEffectiveGid returns value" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const egid = getEffectiveGid();
    // Just verify it returns something
    _ = egid;
}

test "jailer: getCurrentGid returns value" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const gid = getCurrentGid();
    // Just verify it returns something
    _ = gid;
}

test "jailer: config with custom target uid/gid" {
    const config = JailerConfig{
        .target_uid = 1000,
        .target_gid = 1000,
        .chroot_enabled = true,
        .chroot_path = "/tmp/jail",
    };
    try std.testing.expectEqual(@as(?u32, 1000), config.target_uid);
    try std.testing.expectEqual(@as(?u32, 1000), config.target_gid);
    try std.testing.expect(config.chroot_enabled);
    try std.testing.expectEqualStrings("/tmp/jail", config.chroot_path.?);
}

test "jailer: ResourceLimits with custom values" {
    const limits = ResourceLimits{
        .max_files = 256,
        .max_procs = 32,
        .max_address_space = 1024 * 1024 * 1024,
        .max_core = 0,
        .max_cpu_time = 60,
    };
    try std.testing.expectEqual(@as(?u64, 256), limits.max_files);
    try std.testing.expectEqual(@as(?u64, 32), limits.max_procs);
    try std.testing.expectEqual(@as(?u64, 1024 * 1024 * 1024), limits.max_address_space);
    try std.testing.expectEqual(@as(?u64, 0), limits.max_core);
    try std.testing.expectEqual(@as(?u64, 60), limits.max_cpu_time);
}

test "jailer: JailerError variants exist" {
    // Test that error type has expected variants
    const errors = [_]JailerError{
        JailerError.PrivilegeDropFailed,
        JailerError.PrivilegeVerifyFailed,
        JailerError.ChrootFailed,
        JailerError.ResourceLimitFailed,
        JailerError.SecurityPolicyFailed,
        JailerError.PermissionDenied,
        JailerError.InvalidConfig,
        JailerError.OutOfMemory,
    };
    try std.testing.expectEqual(@as(usize, 8), errors.len);
}

test "jailer: isRoot matches getCurrentUid" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const uid = getCurrentUid();
    const root = isRoot();
    try std.testing.expectEqual(uid == 0, root);
}

test "jailer: initWithConfig preserves config" {
    const allocator = std.testing.allocator;
    const config = JailerConfig{
        .target_uid = 500,
        .target_gid = 500,
        .chroot_enabled = false,
        .harden_permissions = false,
        .limits = .{ .max_files = 512 },
    };
    var jailer = try Jailer.initWithConfig(allocator, config);
    defer jailer.deinit();

    try std.testing.expectEqual(@as(?u32, 500), jailer.config.target_uid);
    try std.testing.expectEqual(@as(?u32, 500), jailer.config.target_gid);
    try std.testing.expect(!jailer.config.chroot_enabled);
    try std.testing.expect(!jailer.config.harden_permissions);
    try std.testing.expectEqual(@as(?u64, 512), jailer.config.limits.max_files);
}

test "jailer: EnforcementMode fromString" {
    try std.testing.expectEqual(EnforcementMode.off, EnforcementMode.fromString("off").?);
    try std.testing.expectEqual(EnforcementMode.observe, EnforcementMode.fromString("observe").?);
    try std.testing.expectEqual(EnforcementMode.strict, EnforcementMode.fromString("strict").?);
    try std.testing.expect(EnforcementMode.fromString("invalid") == null);
}

test "jailer: integration observe mode exercises platform hardening path" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try requireIntegrationEnv("M80_TEST_JAILER_INTEGRATION");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try buildIntegrationVmConfig(std.testing.allocator, &tmp);
    defer vm_config.freeConfig(std.testing.allocator, &cfg);
    const vm_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(vm_dir);

    var jailer = try Jailer.initWithConfig(
        std.testing.allocator,
        integrationTestJailerConfig(.observe),
    );
    defer jailer.deinit();
    try jailer.prepareForVm(vm_dir, &cfg);
}

test "jailer: integration strict mode fails when hardening cannot be applied" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try requireIntegrationEnv("M80_TEST_JAILER_INTEGRATION");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try buildIntegrationVmConfig(std.testing.allocator, &tmp);
    defer vm_config.freeConfig(std.testing.allocator, &cfg);
    const vm_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(vm_dir);

    var jailer = try Jailer.initWithConfig(
        std.testing.allocator,
        integrationTestJailerConfig(.strict),
    );
    defer jailer.deinit();
    try std.testing.expectError(
        JailerError.SecurityPolicyFailed,
        jailer.prepareForVm(vm_dir, &cfg),
    );
}

test "jailer: dropPrivileges is no-op on windows" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    // Should return without error
    try dropPrivileges(1000, 1000);
}

test "jailer: verifyPrivilegesDropped is no-op on windows" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    // Should return without error
    try verifyPrivilegesDropped();
}

test "jailer: setResourceLimits is no-op on windows" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    // Should return without error
    try setResourceLimits(.{});
}

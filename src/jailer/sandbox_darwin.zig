//! macOS Sandbox Profile Builder
//!
//! This module implements process sandboxing using macOS's sandbox-exec
//! (Seatbelt) facility. It builds a declarative sandbox profile that
//! restricts what the VMM process can do.
//!
//! ## How macOS Sandbox Works
//! macOS sandboxing uses a Scheme-like DSL to declare allowed operations:
//! - `(version 1)` - Profile format version
//! - `(deny default)` - Deny everything not explicitly allowed
//! - `(allow ...)` - Permit specific operations
//!
//! The profile is compiled and applied via `sandbox_init()`, which is
//! a private API looked up dynamically at runtime.
//!
//! ## VMM Profile Permissions
//! The VMM profile allows only what's needed for hypervisor operation:
//! - `hv-create`: Create Hypervisor Framework VMs
//! - `mach-vm*`: Virtual memory operations for guest RAM
//! - `mach-lookup`: Access Mach services
//! - File read for kernel/initrd images
//! - Optional network access
//! - Explicitly denies `process-exec` and `process-fork`
//!
//! ## Platform Support
//! This module only functions on macOS. On other platforms, all
//! functions are no-ops.

const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");

pub const SandboxError = error{
    ProfileCompilationFailed,
    SandboxInitFailed,
    InvalidProfile,
    OutOfMemory,
};

pub const VmmSandboxOptions = struct {
    vm_directory: ?[]const u8 = null,
    allow_write_vm_dir: bool = false,
    kernel_path: ?[]const u8 = null,
    initrd_path: ?[]const u8 = null,
    disk_path: ?[]const u8 = null,
    seed_path: ?[]const u8 = null,
    data_disk_path: ?[]const u8 = null,
    allow_network: bool = false,
};

pub const SandboxProfile = struct {
    allocator: std.mem.Allocator,
    profile: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) SandboxProfile {
        return .{
            .allocator = allocator,
            .profile = .empty,
        };
    }

    pub fn deinit(self: *SandboxProfile) void {
        self.profile.deinit(self.allocator);
    }

    pub fn buildVmmProfile(self: *SandboxProfile, options: VmmSandboxOptions) !void {
        self.profile.clearRetainingCapacity();
        var w = self.profile.writer(self.allocator);

        // Sandbox profile is built as a declarative allowlist.
        try w.writeAll("(version 1)\n");
        try w.writeAll("(deny default)\n\n");

        try w.writeAll("(allow sysctl-read)\n");
        try w.writeAll("(allow mach-lookup)\n");
        try w.writeAll("(allow signal (target self))\n");
        try w.writeAll("(allow process-info* (target self))\n\n");

        try w.writeAll("(allow mach-vm*)\n");
        try w.writeAll("(allow hv-create)\n\n");

        if (options.vm_directory) |vm_dir| {
            try w.print("(allow file-read* (subpath \"{s}\"))\n", .{vm_dir});
            if (options.allow_write_vm_dir) {
                try w.print("(allow file-write* (subpath \"{s}\"))\n", .{vm_dir});
            }
        }

        if (options.kernel_path) |kernel| {
            try w.print("(allow file-read* (literal \"{s}\"))\n", .{kernel});
        }
        if (options.initrd_path) |initrd| {
            try w.print("(allow file-read* (literal \"{s}\"))\n", .{initrd});
        }
        if (options.disk_path) |disk| {
            try w.print("(allow file-read* (literal \"{s}\"))\n", .{disk});
        }
        if (options.seed_path) |seed| {
            try w.print("(allow file-read* (literal \"{s}\"))\n", .{seed});
        }
        if (options.data_disk_path) |data_disk| {
            try w.print("(allow file-read* (literal \"{s}\"))\n", .{data_disk});
        }

        try w.writeAll("\n(allow file-read* (subpath \"/System/Library/Frameworks\"))\n");
        try w.writeAll("(allow file-read* (subpath \"/usr/lib\"))\n");

        try w.writeAll("\n(allow file-read* (literal \"/dev/null\"))\n");
        try w.writeAll("(allow file-read* (literal \"/dev/urandom\"))\n");
        try w.writeAll("(allow file-write* (literal \"/dev/null\"))\n");

        if (options.allow_network) {
            try w.writeAll("\n(allow network-outbound)\n");
            try w.writeAll("(allow network-bind)\n");
            try w.writeAll("(allow system-socket)\n");
        } else {
            try w.writeAll("\n(deny network*)\n");
        }

        try w.writeAll("\n(deny process-exec)\n");
        try w.writeAll("(deny process-fork)\n");
    }

    pub fn getProfileString(self: *const SandboxProfile) []const u8 {
        return self.profile.items;
    }

    pub fn apply(self: *SandboxProfile) SandboxError!void {
        if (builtin.os.tag != .macos) return;

        // sandbox_init is looked up dynamically to keep non-macOS builds clean.
        const sandbox_init_fn = @extern(?*const fn (
            [*:0]const u8,
            u64,
            *?[*:0]u8,
        ) callconv(.C) c_int, .{ .name = "sandbox_init" });

        const sandbox_free_error_fn = @extern(?*const fn (?[*:0]u8) callconv(.C) void, .{
            .name = "sandbox_free_error",
        });

        if (sandbox_init_fn == null) {
            log.err("sandbox_init not available", .{});
            return SandboxError.SandboxInitFailed;
        }

        const profile_z = self.allocator.allocSentinel(u8, self.profile.items.len, 0) catch return SandboxError.OutOfMemory;
        defer self.allocator.free(profile_z);
        @memcpy(profile_z[0..self.profile.items.len], self.profile.items);

        var error_buf: ?[*:0]u8 = null;
        const SANDBOX_NAMED: u64 = 0x0001;

        const result = sandbox_init_fn.?(profile_z, SANDBOX_NAMED, &error_buf);
        if (result != 0) {
            if (error_buf) |err| {
                log.err("sandbox_init failed: {s}", .{err});
                if (sandbox_free_error_fn) |free_fn| {
                    free_fn(err);
                }
            }
            return SandboxError.SandboxInitFailed;
        }

        log.info("macOS sandbox applied", .{});
    }
};

pub fn applyVmmSandbox(allocator: std.mem.Allocator, options: VmmSandboxOptions) SandboxError!void {
    if (builtin.os.tag != .macos) return;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    profile.buildVmmProfile(options) catch return SandboxError.OutOfMemory;
    try profile.apply();
}

pub fn isSandboxAvailable() bool {
    if (builtin.os.tag != .macos) return false;
    const ptr = @extern(?*const fn () void, .{ .name = "sandbox_init" });
    return ptr != null;
}

// =============================================================================
// TESTS
// =============================================================================

test "sandbox_darwin: SandboxProfile buildVmmProfile" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .vm_directory = "/Users/test/vms/myvm",
        .allow_write_vm_dir = true,
        .allow_network = false,
    });

    const s = profile.getProfileString();
    try std.testing.expect(s.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, s, "(version 1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "(deny default)") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "hv-create") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "/Users/test/vms/myvm") != null);
}

test "sandbox_darwin: network disabled" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{ .allow_network = false });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "(deny network*)") != null);
}

test "sandbox_darwin: network enabled" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{ .allow_network = true });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "(allow network-outbound)") != null);
}

test "sandbox_darwin: profile with kernel path" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .kernel_path = "/path/to/kernel",
    });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/path/to/kernel") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "file-read*") != null);
}

test "sandbox_darwin: profile with initrd path" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .initrd_path = "/path/to/initrd",
    });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/path/to/initrd") != null);
}

test "sandbox_darwin: profile with disk path" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .disk_path = "/path/to/disk.img",
    });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/path/to/disk.img") != null);
}

test "sandbox_darwin: profile with seed path" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .seed_path = "/path/to/seed.iso",
    });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/path/to/seed.iso") != null);
}

test "sandbox_darwin: profile with data disk path" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{
        .data_disk_path = "/path/to/data.img",
    });

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/path/to/data.img") != null);
}

test "sandbox_darwin: profile denies process-exec and process-fork" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{});

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "(deny process-exec)") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "(deny process-fork)") != null);
}

test "sandbox_darwin: profile allows hypervisor access" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{});

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "(allow hv-create)") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "(allow mach-vm*)") != null);
}

test "sandbox_darwin: profile allows system library access" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{});

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/System/Library/Frameworks") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "/usr/lib") != null);
}

test "sandbox_darwin: profile allows dev null and urandom" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{});

    const s = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s, "/dev/null") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "/dev/urandom") != null);
}

test "sandbox_darwin: VmmSandboxOptions defaults" {
    const options = VmmSandboxOptions{};
    try std.testing.expect(options.vm_directory == null);
    try std.testing.expect(options.kernel_path == null);
    try std.testing.expect(options.initrd_path == null);
    try std.testing.expect(options.disk_path == null);
    try std.testing.expect(options.seed_path == null);
    try std.testing.expect(options.data_disk_path == null);
    try std.testing.expect(!options.allow_network);
    try std.testing.expect(!options.allow_write_vm_dir);
}

test "sandbox_darwin: SandboxError variants exist" {
    const errors = [_]SandboxError{
        SandboxError.ProfileCompilationFailed,
        SandboxError.SandboxInitFailed,
        SandboxError.InvalidProfile,
        SandboxError.OutOfMemory,
    };
    try std.testing.expectEqual(@as(usize, 4), errors.len);
}

test "sandbox_darwin: profile can be rebuilt" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    try profile.buildVmmProfile(.{ .allow_network = false });
    const s1 = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s1, "(deny network*)") != null);

    try profile.buildVmmProfile(.{ .allow_network = true });
    const s2 = profile.getProfileString();
    try std.testing.expect(std.mem.indexOf(u8, s2, "(allow network-outbound)") != null);
}

test "sandbox_darwin: vm_directory write permission" {
    const allocator = std.testing.allocator;

    var profile = SandboxProfile.init(allocator);
    defer profile.deinit();

    // Without write permission
    try profile.buildVmmProfile(.{
        .vm_directory = "/Users/test/vms",
        .allow_write_vm_dir = false,
    });
    var s = profile.getProfileString();
    const read_count_1 = std.mem.count(u8, s, "file-read*");
    const write_count_1 = std.mem.count(u8, s, "file-write*");

    // With write permission
    try profile.buildVmmProfile(.{
        .vm_directory = "/Users/test/vms",
        .allow_write_vm_dir = true,
    });
    s = profile.getProfileString();
    const write_count_2 = std.mem.count(u8, s, "file-write*");

    // Should have more write rules when write is enabled
    try std.testing.expect(write_count_2 > write_count_1);
    _ = read_count_1;
}

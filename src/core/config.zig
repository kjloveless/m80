//! VM Configuration Module
//!
//! This module handles parsing, validating, and writing m80.conf configuration files.
//! Each VM has its own m80.conf file in its data directory that defines how the VM
//! should be configured (memory, CPU, kernel paths, network settings, etc.).
//!
//! ## Configuration File Format
//! The m80.conf file uses a simple key=value format:
//! ```
//! name=my-vm
//! memory_mb=4096
//! cpu_cores=4
//! kernel_path=/path/to/vmlinuz
//! initrd_path=/path/to/initrd.img
//! kernel_cmdline=console=ttyAMA0 root=/dev/vda
//! disk_path=/path/to/rootfs.ext4
//! seed_path=/path/to/cloud-init.iso
//! disk_readonly=false
//! network_mode=allowlist
//! allowed_domains=example.com,api.example.com
//! allowed_ips=10.0.0.0/8
//! ```
//!
//! ## Supported Configuration Keys
//! - `name`: VM identifier (alphanumeric, underscore, hyphen)
//! - `ephemeral`: bool - if true, VM data is not persisted (default: false)
//! - `memory_mb`: u32 - RAM allocation in megabytes (default: 2048)
//! - `cpu_cores`: u16 - number of virtual CPUs (default: 2)
//! - `kernel_path`: path to Linux kernel image (required for start)
//! - `initrd_path`: path to initial ramdisk (optional for start)
//! - `disk_path`: path to rootfs block image (optional for start)
//! - `seed_path`: path to a cloud-init NoCloud seed image (optional)
//! - `disk_readonly`: mount rootfs read-only (default: false)
//! - `kernel_cmdline`: optional kernel command line override
//! - `network_mode`: locked_down|allowlist|open (default: locked_down)
//! - `allowed_domains`: comma-separated domain allowlist
//! - `allowed_ips`: comma-separated IP/CIDR allowlist
//!
//! ## Path Resolution
//! Paths in the config can be relative or absolute. Relative paths are resolved
//! relative to the VM's data directory when the VM is started.

const std = @import("std");
const paths = @import("paths.zig");
const net_policy = @import("../net/policy.zig");

/// Configuration for a virtual machine.
/// This struct holds all settings needed to create and run a VM.
/// Configuration for a virtual machine.
/// This struct holds all settings needed to create and run a VM.
pub const VmConfig = struct {
    /// Unique identifier for this VM (e.g., "my-web-server").
    /// Must be alphanumeric with underscores/hyphens only.
    name: []const u8,

    /// If true, VM data is not persisted between runs.
    /// Ephemeral VMs are useful for one-off tasks or testing.
    ephemeral: bool = false,

    /// RAM allocation in megabytes. The hypervisor reserves this much
    /// memory for the guest OS. Default: 2048 MB (2 GB).
    memory_mb: u32 = default_memory_mb,

    /// Number of virtual CPU cores to allocate to the VM.
    /// Should not exceed host physical cores for best performance. Default: 2.
    cpu_cores: u16 = default_cpu_cores,

    /// Path to the Linux kernel image (vmlinuz/bzImage).
    /// Required for starting the VM. Can be relative (resolved against VM dir) or absolute.
    kernel_path: ?[]const u8 = null,

    /// Path to the initial ramdisk (initrd/initramfs).
    /// Optional for starting the VM. Contains drivers and init scripts.
    initrd_path: ?[]const u8 = null,

    /// Path to a root filesystem disk image (ext4).
    /// Optional for starting the VM. When set, root=/dev/vda should be used.
    disk_path: ?[]const u8 = null,

    /// Optional cloud-init NoCloud seed image (ISO or raw).
    /// When set, it is attached as a secondary read-only disk.
    seed_path: ?[]const u8 = null,

    /// If true, attach the disk image as read-only.
    disk_readonly: bool = false,

    /// Optional kernel command line override.
    /// If unset, the backend uses its default command line.
    kernel_cmdline: ?[]const u8 = null,

    /// Network security mode controlling outbound connections.
    /// - locked_down: No network access (default, most secure)
    /// - allowlist: Only allowed domains/IPs can be accessed
    /// - open: Full network access (requires M80_ALLOW_OPEN_NETWORK env var)
    network_mode: net_policy.NetworkMode = .locked_down,

    /// List of allowed domain names when network_mode is allowlist.
    /// Supports wildcards (e.g., "*.example.com").
    allowed_domains: []const []const u8 = &[_][]const u8{},

    /// List of allowed IP addresses/CIDR ranges when network_mode is allowlist.
    /// Example: "10.0.0.0/8", "192.168.1.1"
    allowed_ips: []const []const u8 = &[_][]const u8{},
};

/// Default RAM allocation: 2 GB - sufficient for most lightweight workloads
pub const default_memory_mb: u32 = 2048;

/// Default CPU cores: 2 - balances performance with resource consumption
pub const default_cpu_cores: u16 = 2;

/// Minimum RAM allocation: 16 MB - minimum viable for kernel boot
pub const min_memory_mb: u32 = 16;

/// Returns the host's total physical memory in megabytes.
/// Returns null if the value cannot be determined.
pub fn getHostMemoryMb() ?u64 {
    const builtin = @import("builtin");

    if (builtin.os.tag == .macos) {
        // macOS: use sysctl HW_MEMSIZE
        var mib = [2]c_int{ 6, 24 }; // CTL_HW, HW_MEMSIZE
        var memsize: u64 = 0;
        var len: usize = @sizeOf(u64);
        const rc = std.posix.system.sysctl(&mib, 2, &memsize, &len, null, 0);
        if (rc != 0) return null;
        return memsize / (1024 * 1024);
    }

    if (builtin.os.tag == .linux or builtin.os.tag == .windows) {
        const total = std.process.totalSystemMemory() catch return null;
        return total / (1024 * 1024);
    }

    return null;
}

/// Returns the host's logical CPU count.
/// Returns null if the value cannot be determined.
pub fn getHostCpuCount() ?u16 {
    const count = std.Thread.getCpuCount() catch return null;
    if (count > std.math.maxInt(u16)) return std.math.maxInt(u16);
    return @intCast(count);
}

/// Errors that can occur when parsing m80.conf files.
pub const ConfigError = error{
    /// Line doesn't contain '=' or has empty key (e.g., "this_is_bad\n")
    InvalidFormat,
    /// Value can't be parsed (e.g., "ephemeral=maybe" where bool expected)
    InvalidValue,
    /// Memory allocation failed during parsing
    OutOfMemory,
    /// memory_mb exceeds host physical memory
    MemoryExceedsHost,
    /// memory_mb below minimum (16 MB)
    MemoryBelowMinimum,
    /// cpu_cores exceeds host CPU count
    CpuExceedsHost,
    /// cpu_cores is zero
    CpuBelowMinimum,
    /// Could not determine host resources for validation
    HostResourcesUnknown,
};

/// Errors that can occur when validating config for VM start.
/// These are user-facing errors with specific guidance on what's missing.
pub const StartConfigError = error{
    /// kernel_path not set in config - required to boot
    MissingKernel,
    /// No root filesystem configured (initrd_path or disk_path required)
    MissingRootfs,
    /// seed_path requires disk_path (seed without rootfs doesn't make sense)
    SeedRequiresDisk,
    /// kernel_path file doesn't exist on disk
    KernelNotFound,
    /// initrd_path file doesn't exist on disk
    InitrdNotFound,
    /// disk_path file doesn't exist on disk
    DiskNotFound,
    /// seed_path file doesn't exist on disk
    SeedNotFound,
    /// kernel_path exists but can't be opened (permissions?)
    KernelUnreadable,
    /// initrd_path exists but can't be opened (permissions?)
    InitrdUnreadable,
    /// disk_path exists but can't be opened (permissions?)
    DiskUnreadable,
    /// seed_path exists but can't be opened (permissions?)
    SeedUnreadable,
};

/// Creates a VmConfig with default values and the given name.
/// The name is duplicated into allocator-owned memory.
///
/// Parameters:
///   - allocator: Memory allocator for the name string
///   - name: VM name to use
///
/// Returns: VmConfig with defaults (2GB RAM, 2 CPUs, locked_down network)
pub fn defaultConfig(allocator: std.mem.Allocator, name: []const u8) !VmConfig {
    return VmConfig{
        .name = try allocator.dupe(u8, name),
        .ephemeral = false,
        .memory_mb = default_memory_mb,
        .cpu_cores = default_cpu_cores,
        .kernel_path = null,
        .initrd_path = null,
        .disk_path = null,
        .seed_path = null,
        .disk_readonly = false,
        .kernel_cmdline = null,
    };
}

/// Frees all allocator-owned memory in a VmConfig struct.
/// Call this when done with a config returned by readConfigFile() or defaultConfig().
///
/// Frees:
///   - name string
    ///   - kernel_path, initrd_path, disk_path, seed_path (if set)
///   - allowed_domains list and each domain string
///   - allowed_ips list and each IP string
///
/// After calling, the config fields are reset to empty/null values.
pub fn freeConfig(allocator: std.mem.Allocator, cfg: *VmConfig) void {
    allocator.free(cfg.name);
    cfg.name = "";
    if (cfg.kernel_path) |path| allocator.free(path);
    cfg.kernel_path = null;
    if (cfg.initrd_path) |path| allocator.free(path);
    cfg.initrd_path = null;
    if (cfg.disk_path) |path| allocator.free(path);
    cfg.disk_path = null;
    if (cfg.seed_path) |path| allocator.free(path);
    cfg.seed_path = null;
    if (cfg.kernel_cmdline) |value| allocator.free(value);
    cfg.kernel_cmdline = null;

    // Free each domain string, then the slice itself
    for (cfg.allowed_domains) |d| allocator.free(d);
    if (cfg.allowed_domains.len > 0) allocator.free(cfg.allowed_domains);
    cfg.allowed_domains = &[_][]const u8{};

    // Free each IP string, then the slice itself
    for (cfg.allowed_ips) |ip| allocator.free(ip);
    if (cfg.allowed_ips.len > 0) allocator.free(cfg.allowed_ips);
    cfg.allowed_ips = &[_][]const u8{};
}

/// Reads and parses an m80.conf file from the given directory.
///
/// If the config file doesn't exist, returns a default config with the fallback_name.
/// This allows VMs to work with just a directory - config file is optional.
///
/// Parameters:
///   - allocator: Memory allocator for parsed strings
///   - dir: Directory containing m80.conf
///   - fallback_name: VM name to use if not specified in config
///
/// Returns: Parsed VmConfig (caller must call freeConfig when done)
///
/// Errors:
///   - ConfigError.InvalidFormat: Malformed line in config
///   - ConfigError.InvalidValue: Unparseable value for a key
pub fn readConfigFile(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    fallback_name: []const u8,
) !VmConfig {
    var cfg = try defaultConfig(allocator, fallback_name);
    errdefer freeConfig(allocator, &cfg);

    // Missing config is allowed: return defaults and fallback name.
    var file = dir.openFile("m80.conf", .{}) catch return cfg;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(data);

    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidFormat;
        const key = std.mem.trim(u8, line[0..eq], " \t\r");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (key.len == 0) return error.InvalidFormat;

        try applyConfigEntry(allocator, &cfg, key, value);
    }

    return cfg;
}

/// Converts relative paths in the config to absolute paths.
///
/// This allows m80.conf to use convenient relative paths like "kernel.img"
/// instead of full paths. Paths are resolved relative to the VM's data directory.
///
/// Example:
///   base_dir = "/home/user/.local/share/m80/vms/myvm"
///   kernel_path = "kernel/bzImage"  →  "/home/user/.local/share/m80/vms/myvm/kernel/bzImage"
///
/// Absolute paths are left unchanged.
///
/// Parameters:
///   - allocator: For allocating the new joined path strings
///   - base_dir: Base directory for resolving relative paths (VM data dir)
///   - cfg: Config to modify in place
pub fn resolveRelativePaths(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    cfg: *VmConfig,
) !void {
    if (cfg.kernel_path) |path| {
        if (!std.fs.path.isAbsolute(path)) {
            const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
            allocator.free(path);
            cfg.kernel_path = joined;
        }
    }
    if (cfg.initrd_path) |path| {
        if (!std.fs.path.isAbsolute(path)) {
            const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
            allocator.free(path);
            cfg.initrd_path = joined;
        }
    }
    if (cfg.disk_path) |path| {
        if (!std.fs.path.isAbsolute(path)) {
            const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
            allocator.free(path);
            cfg.disk_path = joined;
        }
    }
    if (cfg.seed_path) |path| {
        if (!std.fs.path.isAbsolute(path)) {
            const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_dir, path });
            allocator.free(path);
            cfg.seed_path = joined;
        }
    }
}

/// Validates that required config fields are set for starting a VM.
/// Does NOT check if files exist - just that paths are configured.
///
/// Required fields for start:
///   - kernel_path: Must be set (not null)
///   - initrd_path or disk_path: Must be set
///   - seed_path requires disk_path
///
/// Errors:
///   - MissingKernel: kernel_path is null
pub fn validateStartConfig(cfg: *const VmConfig) StartConfigError!void {
  if (cfg.kernel_path == null) return error.MissingKernel;
  if (cfg.seed_path != null and cfg.disk_path == null) return error.SeedRequiresDisk;
  if (cfg.initrd_path == null and cfg.disk_path == null) return error.MissingRootfs;
}

/// Validates that kernel/initrd files exist and are readable.
/// Call this after validateStartConfig() to verify the files are present.
///
/// Errors:
///   - MissingKernel/MissingRootfs/SeedRequiresDisk: Path not configured
///   - KernelNotFound/InitrdNotFound/DiskNotFound/SeedNotFound: File doesn't exist
///   - KernelUnreadable/InitrdUnreadable/DiskUnreadable/SeedUnreadable: File exists but can't be opened
pub fn validateStartFiles(cfg: *const VmConfig) StartConfigError!void {
  if (cfg.kernel_path) |path| {
    try checkReadableFile(path, .kernel);
  } else {
    return error.MissingKernel;
  }
  if (cfg.seed_path != null and cfg.disk_path == null) {
    return error.SeedRequiresDisk;
  }
  if (cfg.initrd_path == null and cfg.disk_path == null) {
    return error.MissingRootfs;
  }
  if (cfg.initrd_path) |path| {
    try checkReadableFile(path, .initrd);
  }
  if (cfg.disk_path) |path| {
    try checkReadableFile(path, .disk);
  }
  if (cfg.seed_path) |path| {
    try checkReadableFile(path, .seed);
  }
}

/// Used to provide specific error messages for kernel vs initrd file issues.
const StartFileKind = enum { kernel, initrd, disk, seed };

/// Checks if a file exists and is readable.
/// Returns appropriate error based on file kind (kernel or initrd).
fn checkReadableFile(path: []const u8, kind: StartFileKind) StartConfigError!void {
    const file = if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{});

    if (file) |f| {
        f.close();
        return;
    } else |e| switch (e) {
        error.FileNotFound => return switch (kind) {
            .kernel => error.KernelNotFound,
            .initrd => error.InitrdNotFound,
            .disk => error.DiskNotFound,
            .seed => error.SeedNotFound,
        },
        else => return switch (kind) {
            .kernel => error.KernelUnreadable,
            .initrd => error.InitrdUnreadable,
            .disk => error.DiskUnreadable,
            .seed => error.SeedUnreadable,
        },
    }
}

/// Parses a boolean value from a config string.
/// Accepts: "true", "false", "1", "0"
/// Returns error.InvalidValue for anything else (e.g., "yes", "no", "maybe")
fn parseBool(value: []const u8) ConfigError!bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return error.InvalidValue;
}

/// Parses a comma-separated list into a slice of trimmed strings.
/// Each element is allocated separately, so caller owns all memory.
///
/// Example: " a , b,  c " → ["a", "b", "c"]
///
/// Returns empty slice for empty input (not an error).
fn parseCommaSeparated(allocator: std.mem.Allocator, value: []const u8) ![]const []const u8 {
    if (value.len == 0) return &[_][]const u8{};

    var count: usize = 1;
    for (value) |c| {
        if (c == ',') count += 1;
    }

    const result = try allocator.alloc([]const u8, count);
    errdefer allocator.free(result);

    var it = std.mem.splitScalar(u8, value, ',');
    var i: usize = 0;
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        result[i] = try allocator.dupe(u8, trimmed);
        i += 1;
    }

    return result;
}

/// Replaces a string list field with a new parsed comma-separated list.
/// Properly frees the old list before replacing to prevent memory leaks.
fn replaceStringList(
    allocator: std.mem.Allocator,
    target: *[]const []const u8,
    value: []const u8,
) !void {
    // Free the previous list before replacing to avoid leaks.
    for (target.*) |item| allocator.free(item);
    if (target.*.len > 0) allocator.free(target.*);
    target.* = try parseCommaSeparated(allocator, value);
}

/// Sets an optional path field, freeing any previous value.
/// Empty string clears the path to null (allows "kernel_path=" to unset).
fn setOptionalPath(
    allocator: std.mem.Allocator,
    target: *?[]const u8,
    value: []const u8,
) ConfigError!void {
    if (target.*) |path| allocator.free(path);
    if (value.len == 0) {
        target.* = null;
        return;
    }
    target.* = try allocator.dupe(u8, value);
}

/// Sets an optional string field, freeing any previous value.
/// Empty string clears the value to null.
fn setOptionalString(
    allocator: std.mem.Allocator,
    target: *?[]const u8,
    value: []const u8,
) ConfigError!void {
    if (target.*) |prev| allocator.free(prev);
    if (value.len == 0) {
        target.* = null;
        return;
    }
    target.* = try allocator.dupe(u8, value);
}

/// Applies a single key=value entry to the config struct.
/// Unknown keys are silently ignored for forward compatibility
/// (allows newer configs to work with older m80 versions).
fn applyConfigEntry(
    allocator: std.mem.Allocator,
    cfg: *VmConfig,
    key: []const u8,
    value: []const u8,
) ConfigError!void {
    // Unknown keys are intentionally ignored to allow forward-compatible configs.
    if (std.mem.eql(u8, key, "name")) {
        if (!paths.validateVmName(value)) return error.InvalidValue;
        allocator.free(cfg.name);
        cfg.name = try allocator.dupe(u8, value);
        return;
    }

    if (std.mem.eql(u8, key, "ephemeral")) {
        cfg.ephemeral = try parseBool(value);
        return;
    }

    if (std.mem.eql(u8, key, "memory_mb")) {
        const mem = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        if (mem < min_memory_mb) return error.MemoryBelowMinimum;
        const host_mem = getHostMemoryMb() orelse return error.HostResourcesUnknown;
        if (mem > host_mem) return error.MemoryExceedsHost;
        cfg.memory_mb = mem;
        return;
    }

    if (std.mem.eql(u8, key, "cpu_cores")) {
        const cores = std.fmt.parseInt(u16, value, 10) catch return error.InvalidValue;
        if (cores == 0) return error.CpuBelowMinimum;
        const host_cores = getHostCpuCount() orelse return error.HostResourcesUnknown;
        if (cores > host_cores) return error.CpuExceedsHost;
        cfg.cpu_cores = cores;
        return;
    }

    if (std.mem.eql(u8, key, "kernel_path")) {
        try setOptionalPath(allocator, &cfg.kernel_path, value);
        return;
    }

    if (std.mem.eql(u8, key, "initrd_path")) {
        try setOptionalPath(allocator, &cfg.initrd_path, value);
        return;
    }
    if (std.mem.eql(u8, key, "disk_path")) {
        try setOptionalPath(allocator, &cfg.disk_path, value);
        return;
    }
    if (std.mem.eql(u8, key, "seed_path")) {
        try setOptionalPath(allocator, &cfg.seed_path, value);
        return;
    }
    if (std.mem.eql(u8, key, "disk_readonly")) {
        cfg.disk_readonly = try parseBool(value);
        return;
    }

    if (std.mem.eql(u8, key, "kernel_cmdline")) {
        try setOptionalString(allocator, &cfg.kernel_cmdline, value);
        return;
    }

    if (std.mem.eql(u8, key, "network_mode")) {
        cfg.network_mode = net_policy.NetworkMode.fromString(value) orelse return error.InvalidValue;
        return;
    }

    if (std.mem.eql(u8, key, "allowed_domains")) {
        try replaceStringList(allocator, &cfg.allowed_domains, value);
        return;
    }

    if (std.mem.eql(u8, key, "allowed_ips")) {
        try replaceStringList(allocator, &cfg.allowed_ips, value);
        return;
    }
}

/// Writes a VmConfig to m80.conf in the given directory.
///
/// Uses a simple key=value format that's human-readable and easy to edit.
/// The format is intentionally minimal - could be swapped to TOML/YAML later
/// without breaking CLI commands.
///
/// Writes all config fields including:
///   - name, ephemeral, memory_mb, cpu_cores
///   - kernel_path, initrd_path, disk_path, seed_path, disk_readonly, kernel_cmdline (if set)
///   - network_mode
///   - allowed_domains, allowed_ips (if non-empty, as comma-separated)
pub fn writeConfigFile(dir: std.fs.Dir, cfg: VmConfig) !void {
    var f = try dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();

    var buf: [4096]u8 = undefined;
    var fw = f.writer(&buf);
    const w = &fw.interface;

    try w.print("name={s}\n", .{cfg.name});
    try w.print("ephemeral={}\n", .{cfg.ephemeral});
    try w.print("memory_mb={}\n", .{cfg.memory_mb});
    try w.print("cpu_cores={}\n", .{cfg.cpu_cores});
    if (cfg.kernel_path) |path| {
        try w.print("kernel_path={s}\n", .{path});
    }
    if (cfg.initrd_path) |path| {
        try w.print("initrd_path={s}\n", .{path});
    }
    if (cfg.disk_path) |path| {
        try w.print("disk_path={s}\n", .{path});
    }
    if (cfg.seed_path) |path| {
        try w.print("seed_path={s}\n", .{path});
    }
    if (cfg.disk_readonly) {
        try w.print("disk_readonly=true\n", .{});
    }
    if (cfg.kernel_cmdline) |value| {
        try w.print("kernel_cmdline={s}\n", .{value});
    }
    try w.print("network_mode={s}\n", .{cfg.network_mode.toString()});

    if (cfg.allowed_domains.len > 0) {
        try w.writeAll("allowed_domains=");
        for (cfg.allowed_domains, 0..) |d, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(d);
        }
        try w.writeByte('\n');
    }

    if (cfg.allowed_ips.len > 0) {
        try w.writeAll("allowed_ips=");
        for (cfg.allowed_ips, 0..) |ip, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(ip);
        }
        try w.writeByte('\n');
    }

    try w.flush();
}

// =============================================================================
// TESTS
// =============================================================================
// Tests use the "config:" prefix to identify which module they belong to.

// Tests that config parsing correctly reads all fields from m80.conf.
test "config: parse kernel/initrd paths and overrides" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();

    try f.writeAll("name=testvm\n" ++
        "ephemeral=true\n" ++
        "memory_mb=4096\n" ++
        "cpu_cores=4\n" ++
        "kernel_path=/kernels/vmlinuz\n" ++
        "initrd_path=/images/initrd.img\n" ++
        "disk_path=/images/rootfs.ext4\n" ++
        "seed_path=/images/seed.iso\n" ++
        "disk_readonly=true\n" ++
        "kernel_cmdline=console=ttyAMA0\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expectEqualStrings("testvm", cfg_mut.name);
    try std.testing.expect(cfg_mut.ephemeral);
    try std.testing.expectEqual(@as(u32, 4096), cfg_mut.memory_mb);
    try std.testing.expectEqual(@as(u16, 4), cfg_mut.cpu_cores);
    try std.testing.expectEqualStrings("/kernels/vmlinuz", cfg_mut.kernel_path.?);
    try std.testing.expectEqualStrings("/images/initrd.img", cfg_mut.initrd_path.?);
    try std.testing.expectEqualStrings("/images/rootfs.ext4", cfg_mut.disk_path.?);
    try std.testing.expectEqualStrings("/images/seed.iso", cfg_mut.seed_path.?);
    try std.testing.expect(cfg_mut.disk_readonly);
    try std.testing.expectEqualStrings("console=ttyAMA0", cfg_mut.kernel_cmdline.?);
}

test "config: rejects malformed lines and bad values" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
        defer f.close();
        try f.writeAll("this_is_bad\n");
    }
    try std.testing.expectError(error.InvalidFormat, readConfigFile(allocator, tmp.dir, "fallback"));

    {
        var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
        defer f.close();
        try f.writeAll("ephemeral=maybe\n");
    }
    try std.testing.expectError(error.InvalidValue, readConfigFile(allocator, tmp.dir, "fallback"));
}

test "config: resolveRelativePaths joins vm dir" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    cfg.kernel_path = try allocator.dupe(u8, "kernel/bzImage");
    cfg.initrd_path = try allocator.dupe(u8, "initrd.img");
    cfg.disk_path = try allocator.dupe(u8, "rootfs.ext4");
    cfg.seed_path = try allocator.dupe(u8, "seed.iso");

    try resolveRelativePaths(allocator, "/vm/root", &cfg);

    try std.testing.expectEqualStrings("/vm/root/kernel/bzImage", cfg.kernel_path.?);
    try std.testing.expectEqualStrings("/vm/root/initrd.img", cfg.initrd_path.?);
    try std.testing.expectEqualStrings("/vm/root/rootfs.ext4", cfg.disk_path.?);
    try std.testing.expectEqualStrings("/vm/root/seed.iso", cfg.seed_path.?);
}

test "config: validateStartConfig requires kernel and rootfs" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    try std.testing.expectError(error.MissingKernel, validateStartConfig(&cfg));

  cfg.kernel_path = try allocator.dupe(u8, "/kernels/vmlinuz");
  try std.testing.expectError(error.MissingRootfs, validateStartConfig(&cfg));

  cfg.seed_path = try allocator.dupe(u8, "/images/seed.iso");
  try std.testing.expectError(error.SeedRequiresDisk, validateStartConfig(&cfg));
  allocator.free(cfg.seed_path.?);
  cfg.seed_path = null;

  cfg.initrd_path = try allocator.dupe(u8, "/images/initrd.img");
  try validateStartConfig(&cfg);
  allocator.free(cfg.initrd_path.?);
  cfg.initrd_path = null;
  cfg.disk_path = try allocator.dupe(u8, "/images/rootfs.ext4");
  try validateStartConfig(&cfg);
}

test "config: validateStartFiles checks existence" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("vmlinuz", .{});
        defer f.close();
        try f.writeAll("kernel");
    }
    {
        var f = try tmp.dir.createFile("initrd.img", .{});
        defer f.close();
        try f.writeAll("initrd");
    }
    {
        var f = try tmp.dir.createFile("rootfs.ext4", .{});
        defer f.close();
        try f.writeAll("rootfs");
    }
    {
        var f = try tmp.dir.createFile("seed.iso", .{});
        defer f.close();
        try f.writeAll("seed");
    }
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    const kernel_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "vmlinuz" });
    defer allocator.free(kernel_path);
    const initrd_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "initrd.img" });
    defer allocator.free(initrd_path);
    const disk_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "rootfs.ext4" });
    defer allocator.free(disk_path);
    const seed_path = try std.fs.path.join(allocator, &[_][]const u8{ base, "seed.iso" });
    defer allocator.free(seed_path);
    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    cfg.kernel_path = try allocator.dupe(u8, kernel_path);
    cfg.initrd_path = try allocator.dupe(u8, initrd_path);
    try validateStartFiles(&cfg);
    allocator.free(cfg.initrd_path.?);
    cfg.initrd_path = null;
    cfg.disk_path = try allocator.dupe(u8, disk_path);
    try validateStartFiles(&cfg);
    cfg.seed_path = try allocator.dupe(u8, seed_path);
    try validateStartFiles(&cfg);

    allocator.free(cfg.kernel_path.?);
    cfg.kernel_path = try allocator.dupe(u8, "missing-kernel");
    try std.testing.expectError(error.KernelNotFound, validateStartFiles(&cfg));
}

test "config: empty path clears optional value" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("kernel_path=/tmp/kernel\n" ++
        "kernel_path=\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expect(cfg_mut.kernel_path == null);
}

test "config: allowed list parsing and overrides" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("allowed_domains=example.com, api.example.com\n" ++
        "allowed_domains=second.com\n" ++
        "allowed_ips=10.0.0.1 , 10.0.0.2\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expectEqual(@as(usize, 1), cfg_mut.allowed_domains.len);
    try std.testing.expectEqualStrings("second.com", cfg_mut.allowed_domains[0]);

    try std.testing.expectEqual(@as(usize, 2), cfg_mut.allowed_ips.len);
    try std.testing.expectEqualStrings("10.0.0.1", cfg_mut.allowed_ips[0]);
    try std.testing.expectEqualStrings("10.0.0.2", cfg_mut.allowed_ips[1]);
}

test "config: parseBool accepts 0/1 and rejects other" {
    try std.testing.expectEqual(true, try parseBool("1"));
    try std.testing.expectEqual(false, try parseBool("0"));
    try std.testing.expectError(error.InvalidValue, parseBool("yes"));
}

test "config: parseCommaSeparated trims whitespace" {
    const allocator = std.testing.allocator;
    const list = try parseCommaSeparated(allocator, " a , b,  c ");
    defer {
        for (list) |item| allocator.free(item);
        if (list.len > 0) allocator.free(list);
    }

    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqualStrings("a", list[0]);
    try std.testing.expectEqualStrings("b", list[1]);
    try std.testing.expectEqualStrings("c", list[2]);
}

test "config: parseCommaSeparated handles empty string" {
    const allocator = std.testing.allocator;
    const list = try parseCommaSeparated(allocator, "");
    defer if (list.len > 0) allocator.free(list);
    try std.testing.expectEqual(@as(usize, 0), list.len);
}

test "config: writeConfigFile emits allowlists" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    cfg.allowed_domains = try parseCommaSeparated(allocator, "example.com,api.example.com");
    cfg.allowed_ips = try parseCommaSeparated(allocator, "10.0.0.1,10.0.0.2");

    try writeConfigFile(tmp.dir, cfg);
    const data = try tmp.dir.readFileAlloc(allocator, "m80.conf", 64 * 1024);
    defer allocator.free(data);

    try std.testing.expect(std.mem.indexOf(u8, data, "allowed_domains=") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "allowed_ips=") != null);
}

test "config: validateStartConfig missing fields" {
    var cfg = try defaultConfig(std.testing.allocator, "test");
    defer freeConfig(std.testing.allocator, &cfg);

    try std.testing.expectError(error.MissingKernel, validateStartConfig(&cfg));
    cfg.kernel_path = try std.testing.allocator.dupe(u8, "/kernel");
    try std.testing.expectError(error.MissingRootfs, validateStartConfig(&cfg));
    cfg.seed_path = try std.testing.allocator.dupe(u8, "/seed.iso");
    try std.testing.expectError(error.SeedRequiresDisk, validateStartConfig(&cfg));
    std.testing.allocator.free(cfg.seed_path.?);
    cfg.seed_path = null;
    cfg.initrd_path = try std.testing.allocator.dupe(u8, "/initrd.img");
    try validateStartConfig(&cfg);
    std.testing.allocator.free(cfg.initrd_path.?);
    cfg.initrd_path = null;
    cfg.disk_path = try std.testing.allocator.dupe(u8, "/rootfs.ext4");
    try validateStartConfig(&cfg);
}

test "config: unknown keys are ignored" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("unknown_key=what\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expectEqualStrings("fallback", cfg_mut.name);
    try std.testing.expect(!cfg_mut.ephemeral);
    try std.testing.expectEqual(default_memory_mb, cfg_mut.memory_mb);
    try std.testing.expectEqual(default_cpu_cores, cfg_mut.cpu_cores);
}

test "config: getHostMemoryMb returns reasonable value" {
    const mem = getHostMemoryMb();
    // Should succeed on all supported platforms
    try std.testing.expect(mem != null);
    // At least 64 MB (any less and we couldn't run this test)
    try std.testing.expect(mem.? >= 64);
}

test "config: getHostCpuCount returns reasonable value" {
    const cores = getHostCpuCount();
    try std.testing.expect(cores != null);
    // At least 1 CPU
    try std.testing.expect(cores.? >= 1);
}

test "config: memory_mb rejects below minimum" {
    const allocator = std.testing.allocator;
    var cfg = try defaultConfig(allocator, "test");
    defer freeConfig(allocator, &cfg);

    try std.testing.expectError(error.MemoryBelowMinimum, applyConfigEntry(allocator, &cfg, "memory_mb", "8"));
}

test "config: memory_mb rejects above host memory" {
    const allocator = std.testing.allocator;
    var cfg = try defaultConfig(allocator, "test");
    defer freeConfig(allocator, &cfg);

    // Request way more than any host could have (1 PB)
    try std.testing.expectError(error.MemoryExceedsHost, applyConfigEntry(allocator, &cfg, "memory_mb", "1073741824"));
}

test "config: cpu_cores rejects zero" {
    const allocator = std.testing.allocator;
    var cfg = try defaultConfig(allocator, "test");
    defer freeConfig(allocator, &cfg);

    try std.testing.expectError(error.CpuBelowMinimum, applyConfigEntry(allocator, &cfg, "cpu_cores", "0"));
}

test "config: cpu_cores rejects above host cores" {
    const allocator = std.testing.allocator;
    var cfg = try defaultConfig(allocator, "test");
    defer freeConfig(allocator, &cfg);

    // Request way more CPUs than any host could have
    try std.testing.expectError(error.CpuExceedsHost, applyConfigEntry(allocator, &cfg, "cpu_cores", "65535"));
}

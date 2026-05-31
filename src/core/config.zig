//! VM Configuration Module
//!
//! This module handles parsing, validating, and writing m80.conf configuration files.
//! Each VM has its own m80.conf file in its data directory that defines how the VM
//! should be configured (memory, CPU, kernel paths, mounts, and control-plane
//! network services and outbound policy).
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
//! network_mode=locked_down
//! network_services=dns,metadata
//! network_metadata_file=/path/to/metadata.json
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
//! - `data_disk_path`: path to an additional data disk image (optional)
//! - `seed_path`: path to a cloud-init NoCloud seed image (optional)
//! - `disk_readonly`: mount rootfs read-only (default: false)
//! - `data_disk_readonly`: mount data disk read-only (default: false)
//! - `kernel_cmdline`: optional kernel command line override
//! - `network_mode`: locked_down|allowlist|open
//! - `network_services`: comma-separated guest-local services (`dns`, `metadata`)
//! - `network_metadata_file`: optional JSON source for `/v1/user`
//! - `network_allowed_domains`: comma-separated domain allowlist
//! - `network_allowed_ips`: comma-separated IPv4/IPv6/CIDR allowlist
//!
//! ## Path Resolution
//! Paths in the config can be relative or absolute. Relative paths are resolved
//! relative to the VM's data directory when the VM is started.

const std = @import("std");
const fs = @import("../util/fs.zig");
const paths = @import("paths.zig");
const mounts = @import("../fs/mounts.zig");
const env = @import("../util/env.zig");

pub const NetworkMode = enum {
    locked_down,
    allowlist,
    open,

    pub fn fromString(value: []const u8) ?NetworkMode {
        if (std.mem.eql(u8, value, "locked_down")) return .locked_down;
        if (std.mem.eql(u8, value, "allowlist")) return .allowlist;
        if (std.mem.eql(u8, value, "open")) return .open;
        return null;
    }

    pub fn toString(self: NetworkMode) []const u8 {
        return switch (self) {
            .locked_down => "locked_down",
            .allowlist => "allowlist",
            .open => "open",
        };
    }
};

pub const Service = enum {
    dns,
    metadata,

    pub fn fromString(value: []const u8) ?Service {
        if (std.mem.eql(u8, value, "dns")) return .dns;
        if (std.mem.eql(u8, value, "metadata")) return .metadata;
        return null;
    }

    pub fn toString(self: Service) []const u8 {
        return switch (self) {
            .dns => "dns",
            .metadata => "metadata",
        };
    }
};

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

    /// Optional additional data disk image (ext4).
    /// When set, it is attached as an extra virtio-blk device.
    data_disk_path: ?[]const u8 = null,

    /// If true, attach the data disk as read-only.
    data_disk_readonly: bool = false,

    /// Optional kernel command line override.
    /// If unset, the backend uses its default command line.
    kernel_cmdline: ?[]const u8 = null,

    /// Allowed host roots for mount sharing.
    /// Required when mounts are configured.
    mount_roots: []const []const u8 = &[_][]const u8{},

    /// Mount configurations (virtio-fs/9p).
    mounts: []mounts.MountConfig = &[_]mounts.MountConfig{},

    assigned_guest_cid: ?u32 = null,

    /// Outbound networking policy. Guest-local services are still allowed
    /// in locked_down mode when explicitly enabled.
    network_mode: NetworkMode = .locked_down,

    /// Guest-local services injected into the guest bootstrap.
    network_services: []const Service = &[_]Service{},

    /// Optional JSON document served by the metadata service at `/v1/user`.
    network_metadata_file: ?[]const u8 = null,

    /// Domain allowlist used when network_mode=allowlist.
    network_allowed_domains: []const []const u8 = &[_][]const u8{},

    /// IPv4/CIDR allowlist used when network_mode=allowlist.
    network_allowed_ips: []const []const u8 = &[_][]const u8{},

    /// Per-VM daemon socket assigned during registration.
    assigned_guest_session_socket_path: ?[]const u8 = null,

    /// Number of virtio-fs request queues to expose (1-8).
    /// Higher values can improve throughput on multi-core systems.
    virtio_fs_queues: u16 = 1,

    /// Virtio-fs cache mode.
    virtio_fs_cache: VirtioFsCacheMode = .auto,
};

pub const VirtioFsCacheMode = enum {
    none,
    auto,
    always,

    pub fn fromString(value: []const u8) ?VirtioFsCacheMode {
        if (std.mem.eql(u8, value, "none")) return .none;
        if (std.mem.eql(u8, value, "auto")) return .auto;
        if (std.mem.eql(u8, value, "always")) return .always;
        return null;
    }

    pub fn toString(self: VirtioFsCacheMode) []const u8 {
        return switch (self) {
            .none => "none",
            .auto => "auto",
            .always => "always",
        };
    }
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
    /// Legacy network policy keys are no longer supported
    RemovedNetworkKey,
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
    /// data_disk_path file doesn't exist on disk
    DataDiskNotFound,
    /// kernel_path exists but can't be opened (permissions?)
    KernelUnreadable,
    /// initrd_path exists but can't be opened (permissions?)
    InitrdUnreadable,
    /// disk_path exists but can't be opened (permissions?)
    DiskUnreadable,
    /// seed_path exists but can't be opened (permissions?)
    SeedUnreadable,
    /// data_disk_path exists but can't be opened (permissions?)
    DataDiskUnreadable,
    /// metadata_file doesn't exist
    MetadataFileNotFound,
    /// metadata_file exists but cannot be opened
    MetadataFileUnreadable,
    /// network_mode=open requires explicit operator opt-in
    OpenNetworkNotAllowed,
    /// network_allowed_domains has an invalid entry
    InvalidNetworkAllowedDomainSpec,
    /// network_allowed_ips has an invalid entry
    InvalidNetworkAllowedIpSpec,
    /// virtio_fs_queues outside supported range
    VirtioFsQueuesInvalid,
    /// mounts configured without mount_roots
    MountRootsRequired,
    /// unsupported mount type for this backend
    MountTypeUnsupported,
    /// too many mounts for current backend
    MountCountUnsupported,
};

/// Creates a VmConfig with default values and the given name.
/// The name is duplicated into allocator-owned memory.
///
/// Parameters:
///   - allocator: Memory allocator for the name string
///   - name: VM name to use
///
/// Returns: VmConfig with defaults (2GB RAM, 2 CPUs, locked_down networking)
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
        .data_disk_path = null,
        .data_disk_readonly = false,
        .kernel_cmdline = null,
        .network_metadata_file = null,
    };
}

/// Frees all allocator-owned memory in a VmConfig struct.
/// Call this when done with a config returned by readConfigFile() or defaultConfig().
///
/// Frees:
///   - name string
///   - kernel_path, initrd_path, disk_path, seed_path, data_disk_path (if set)
///   - network_metadata_file (if set)
///   - network_services list
///   - network allowlist entries
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
    if (cfg.data_disk_path) |path| allocator.free(path);
    cfg.data_disk_path = null;
    if (cfg.kernel_cmdline) |value| allocator.free(value);
    cfg.kernel_cmdline = null;
    if (cfg.network_metadata_file) |value| allocator.free(value);
    cfg.network_metadata_file = null;

    if (cfg.network_services.len > 0) allocator.free(cfg.network_services);
    cfg.network_services = &[_]Service{};

    for (cfg.network_allowed_domains) |value| allocator.free(value);
    if (cfg.network_allowed_domains.len > 0) allocator.free(cfg.network_allowed_domains);
    cfg.network_allowed_domains = &[_][]const u8{};

    for (cfg.network_allowed_ips) |value| allocator.free(value);
    if (cfg.network_allowed_ips.len > 0) allocator.free(cfg.network_allowed_ips);
    cfg.network_allowed_ips = &[_][]const u8{};

    if (cfg.assigned_guest_session_socket_path) |value| allocator.free(value);
    cfg.assigned_guest_session_socket_path = null;

    // Free mount roots
    for (cfg.mount_roots) |root| allocator.free(root);
    if (cfg.mount_roots.len > 0) allocator.free(cfg.mount_roots);
    cfg.mount_roots = &[_][]const u8{};

    // Free mounts
    for (cfg.mounts) |mount| {
        allocator.free(mount.tag);
        allocator.free(mount.host_path);
        allocator.free(mount.guest_path);
    }
    if (cfg.mounts.len > 0) allocator.free(cfg.mounts);
    cfg.mounts = &[_]mounts.MountConfig{};
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
    dir: fs.Dir,
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
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.kernel_path = joined;
        } else {
            cfg.kernel_path = resolved;
        }
    }
    if (cfg.initrd_path) |path| {
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.initrd_path = joined;
        } else {
            cfg.initrd_path = resolved;
        }
    }
    if (cfg.disk_path) |path| {
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.disk_path = joined;
        } else {
            cfg.disk_path = resolved;
        }
    }
    if (cfg.seed_path) |path| {
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.seed_path = joined;
        } else {
            cfg.seed_path = resolved;
        }
    }
    if (cfg.data_disk_path) |path| {
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.data_disk_path = joined;
        } else {
            cfg.data_disk_path = resolved;
        }
    }
    if (cfg.mount_roots.len > 0) {
        var needs_rewrite = false;
        for (cfg.mount_roots) |root| {
            if (root.len > 0 and root[0] == '~') {
                needs_rewrite = true;
                break;
            }
            if (!fs.path.isAbsolute(root)) {
                needs_rewrite = true;
                break;
            }
        }
        if (needs_rewrite) {
            const rewritten = try allocator.alloc([]const u8, cfg.mount_roots.len);
            for (cfg.mount_roots, 0..) |root, i| {
                var resolved = root;
                if (try expandTildePath(allocator, root)) |expanded| {
                    allocator.free(root);
                    resolved = expanded;
                }
                if (!fs.path.isAbsolute(resolved)) {
                    const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
                    allocator.free(resolved);
                    rewritten[i] = joined;
                } else {
                    rewritten[i] = resolved;
                }
            }
            allocator.free(cfg.mount_roots);
            cfg.mount_roots = rewritten;
        }
    }
    if (cfg.mounts.len > 0) {
        for (cfg.mounts) |*mount_cfg| {
            if (try expandTildePath(allocator, mount_cfg.host_path)) |expanded| {
                allocator.free(mount_cfg.host_path);
                mount_cfg.host_path = expanded;
            }
            if (!fs.path.isAbsolute(mount_cfg.host_path)) {
                const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, mount_cfg.host_path });
                allocator.free(mount_cfg.host_path);
                mount_cfg.host_path = joined;
            }
        }
    }
    if (cfg.network_metadata_file) |path| {
        var resolved = path;
        if (try expandTildePath(allocator, path)) |expanded| {
            allocator.free(path);
            resolved = expanded;
        }
        if (!fs.path.isAbsolute(resolved)) {
            const joined = try fs.path.join(allocator, &[_][]const u8{ base_dir, resolved });
            allocator.free(resolved);
            cfg.network_metadata_file = joined;
        } else {
            cfg.network_metadata_file = resolved;
        }
    }
}

fn expandTildePath(allocator: std.mem.Allocator, path: []const u8) !?[]const u8 {
    if (path.len == 0 or path[0] != '~') return null;
    if (path.len > 1 and path[1] != '/') return null;

    const home = env.getVarOwned(allocator, "HOME") catch
        env.getVarOwned(allocator, "USERPROFILE") catch return null;
    if (path.len == 1) return home;
    if (path.len == 2) return home;

    const joined = try fs.path.join(allocator, &[_][]const u8{ home, path[2..] });
    allocator.free(home);
    return joined;
}

fn openNetworkAllowed() bool {
    const value = env.getVarOwned(std.heap.page_allocator, "M80_ALLOW_OPEN_NETWORK") catch return false;
    defer std.heap.page_allocator.free(value);
    return env.flagEnabledValue(value);
}

fn isValidDomainLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 63) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;
    for (label) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-') continue;
        return false;
    }
    return true;
}

fn isValidDomainAllowlistSpec(spec: []const u8) bool {
    if (spec.len == 0) return false;

    var host = spec;
    if (std.mem.lastIndexOfScalar(u8, spec, ':')) |idx| {
        if (idx == 0 or idx == spec.len - 1) return false;
        const port = std.fmt.parseInt(u16, spec[idx + 1 ..], 10) catch return false;
        if (port == 0) return false;
        host = spec[0..idx];
    }

    if (host.len == 0 or host.len > 253) return false;
    if (std.mem.startsWith(u8, host, "*.")) {
        host = host[2..];
        if (host.len == 0) return false;
    }
    if (host[0] == '.' or host[host.len - 1] == '.') return false;

    var it = std.mem.splitScalar(u8, host, '.');
    var labels: usize = 0;
    while (it.next()) |label| {
        if (!isValidDomainLabel(label)) return false;
        labels += 1;
    }
    return labels > 0;
}

fn isValidIpv4(value: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, '.');
    var octets: usize = 0;
    while (it.next()) |part| {
        if (part.len == 0) return false;
        _ = std.fmt.parseInt(u8, part, 10) catch return false;
        octets += 1;
    }
    return octets == 4;
}

fn isValidIpLiteral(value: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(value, 0) catch return false;
    return true;
}

fn ipLiteralBitLen(value: []const u8) ?u8 {
    const parsed = std.Io.net.IpAddress.parse(value, 0) catch return null;
    return switch (parsed) {
        .ip4 => 32,
        .ip6 => 128,
    };
}

fn isValidIpAllowlistSpec(spec: []const u8) bool {
    if (spec.len == 0) return false;
    if (std.mem.indexOfScalar(u8, spec, '/')) |idx| {
        if (idx == 0 or idx == spec.len - 1) return false;
        const bits = ipLiteralBitLen(spec[0..idx]) orelse return false;
        const prefix = std.fmt.parseInt(u8, spec[idx + 1 ..], 10) catch return false;
        return prefix <= bits;
    }
    return isValidIpLiteral(spec);
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
    if (cfg.network_mode == .open and !openNetworkAllowed()) return error.OpenNetworkNotAllowed;
    for (cfg.network_allowed_domains) |entry| {
        if (!isValidDomainAllowlistSpec(entry)) return error.InvalidNetworkAllowedDomainSpec;
    }
    for (cfg.network_allowed_ips) |entry| {
        if (!isValidIpAllowlistSpec(entry)) return error.InvalidNetworkAllowedIpSpec;
    }
    if (cfg.mounts.len > 0 and cfg.mount_roots.len == 0) return error.MountRootsRequired;
    if (cfg.mounts.len > 1) return error.MountCountUnsupported;
    for (cfg.mounts) |mount_cfg| {
        if (mount_cfg.mount_type != .virtio_fs) return error.MountTypeUnsupported;
    }
    if (cfg.virtio_fs_queues == 0 or cfg.virtio_fs_queues > 8) return error.VirtioFsQueuesInvalid;
}

/// Validates that kernel/initrd files exist and are readable.
/// Call this after validateStartConfig() to verify the files are present.
///
/// Errors:
///   - MissingKernel/MissingRootfs/SeedRequiresDisk: Path not configured
///   - KernelNotFound/InitrdNotFound/DiskNotFound/SeedNotFound/DataDiskNotFound: File doesn't exist
///   - KernelUnreadable/InitrdUnreadable/DiskUnreadable/SeedUnreadable/DataDiskUnreadable: File exists but can't be opened
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
    if (cfg.data_disk_path) |path| {
        try checkReadableFile(path, .data_disk);
    }
    if (cfg.network_metadata_file) |path| {
        try checkReadableFile(path, .metadata);
    }
}

/// Used to provide specific error messages for kernel vs initrd file issues.
const StartFileKind = enum { kernel, initrd, disk, seed, data_disk, metadata };

/// Checks if a file exists and is readable.
/// Returns appropriate error based on file kind (kernel or initrd).
fn checkReadableFile(path: []const u8, kind: StartFileKind) StartConfigError!void {
    const file = if (fs.path.isAbsolute(path))
        fs.openFileAbsolute(path, .{})
    else
        fs.cwd().openFile(path, .{});

    if (file) |f| {
        f.close();
        return;
    } else |e| switch (e) {
        error.FileNotFound => return switch (kind) {
            .kernel => error.KernelNotFound,
            .initrd => error.InitrdNotFound,
            .disk => error.DiskNotFound,
            .seed => error.SeedNotFound,
            .data_disk => error.DataDiskNotFound,
            .metadata => error.MetadataFileNotFound,
        },
        else => return switch (kind) {
            .kernel => error.KernelUnreadable,
            .initrd => error.InitrdUnreadable,
            .disk => error.DiskUnreadable,
            .seed => error.SeedUnreadable,
            .data_disk => error.DataDiskUnreadable,
            .metadata => error.MetadataFileUnreadable,
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

fn parseServiceList(allocator: std.mem.Allocator, value: []const u8) ![]const Service {
    if (value.len == 0) return &[_]Service{};

    const parts = try parseCommaSeparated(allocator, value);
    defer {
        for (parts) |part| allocator.free(part);
        if (parts.len > 0) allocator.free(parts);
    }

    var services = try allocator.alloc(Service, parts.len);
    var count: usize = 0;
    errdefer allocator.free(services);

    for (parts) |part| {
        const service = Service.fromString(part) orelse return error.InvalidValue;
        var exists = false;
        for (services[0..count]) |existing| {
            if (existing == service) {
                exists = true;
                break;
            }
        }
        if (exists) continue;
        services[count] = service;
        count += 1;
    }

    if (count == services.len) return services;
    const trimmed = try allocator.alloc(Service, count);
    @memcpy(trimmed, services[0..count]);
    allocator.free(services);
    return trimmed;
}

/// Replaces a string list field with a new parsed comma-separated list.
/// Properly frees the old list before replacing to prevent memory leaks.
fn replaceStringList(
    allocator: std.mem.Allocator,
    target: *[]const []const u8,
    value: []const u8,
) !void {
    freeStringList(allocator, target);
    target.* = try parseCommaSeparated(allocator, value);
}

fn freeStringList(allocator: std.mem.Allocator, target: *[]const []const u8) void {
    for (target.*) |item| allocator.free(item);
    if (target.*.len > 0) allocator.free(target.*);
    target.* = &[_][]const u8{};
}

fn replaceServiceList(
    allocator: std.mem.Allocator,
    target: *[]const Service,
    value: []const u8,
) !void {
    if (target.*.len > 0) allocator.free(target.*);
    target.* = try parseServiceList(allocator, value);
}

pub fn hasService(cfg: *const VmConfig, service: Service) bool {
    for (cfg.network_services) |candidate| {
        if (candidate == service) return true;
    }
    return false;
}

fn freeMountList(allocator: std.mem.Allocator, list: []mounts.MountConfig) void {
    for (list) |mount| {
        allocator.free(mount.tag);
        allocator.free(mount.host_path);
        allocator.free(mount.guest_path);
    }
    if (list.len > 0) allocator.free(list);
}

fn replaceMountList(
    allocator: std.mem.Allocator,
    target: *[]mounts.MountConfig,
    value: []const u8,
) !void {
    freeMountList(allocator, target.*);
    if (value.len == 0) {
        target.* = &[_]mounts.MountConfig{};
        return;
    }

    const parts = try parseCommaSeparated(allocator, value);
    defer {
        for (parts) |part| allocator.free(part);
        if (parts.len > 0) allocator.free(parts);
    }

    const result = try allocator.alloc(mounts.MountConfig, parts.len);
    var filled: usize = 0;
    errdefer {
        for (result[0..filled]) |mount| {
            allocator.free(mount.tag);
            allocator.free(mount.host_path);
            allocator.free(mount.guest_path);
        }
        allocator.free(result);
    }

    var i: usize = 0;
    while (i < parts.len) : (i += 1) {
        const parsed = mounts.parseMountConfig(parts[i]) orelse return error.InvalidValue;
        result[i] = .{
            .tag = try allocator.dupe(u8, parsed.tag),
            .host_path = try allocator.dupe(u8, parsed.host_path),
            .guest_path = try allocator.dupe(u8, parsed.guest_path),
            .access = parsed.access,
            .mount_type = parsed.mount_type,
            .max_file_size = parsed.max_file_size,
            .allow_exec = parsed.allow_exec,
        };
        filled += 1;
    }

    target.* = result;
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
    if (std.mem.eql(u8, key, "data_disk_path")) {
        try setOptionalPath(allocator, &cfg.data_disk_path, value);
        return;
    }
    if (std.mem.eql(u8, key, "data_disk_readonly")) {
        cfg.data_disk_readonly = try parseBool(value);
        return;
    }

    if (std.mem.eql(u8, key, "kernel_cmdline")) {
        try setOptionalString(allocator, &cfg.kernel_cmdline, value);
        return;
    }

    if (std.mem.eql(u8, key, "virtio_fs_queues")) {
        const queues = std.fmt.parseInt(u16, value, 10) catch return error.InvalidValue;
        if (queues == 0 or queues > 8) return error.InvalidValue;
        cfg.virtio_fs_queues = queues;
        return;
    }

    if (std.mem.eql(u8, key, "virtio_fs_cache")) {
        cfg.virtio_fs_cache = VirtioFsCacheMode.fromString(value) orelse return error.InvalidValue;
        return;
    }

    if (std.mem.eql(u8, key, "services") or
        std.mem.eql(u8, key, "metadata_file") or
        std.mem.eql(u8, key, "allowed_domains") or
        std.mem.eql(u8, key, "allowed_ips"))
    {
        return error.RemovedNetworkKey;
    }

    if (std.mem.eql(u8, key, "network_mode")) {
        cfg.network_mode = NetworkMode.fromString(value) orelse return error.InvalidValue;
        return;
    }

    if (std.mem.eql(u8, key, "network_services")) {
        try replaceServiceList(allocator, &cfg.network_services, value);
        return;
    }

    if (std.mem.eql(u8, key, "network_metadata_file")) {
        try setOptionalPath(allocator, &cfg.network_metadata_file, value);
        return;
    }

    if (std.mem.eql(u8, key, "network_allowed_domains")) {
        try replaceStringList(allocator, &cfg.network_allowed_domains, value);
        return;
    }

    if (std.mem.eql(u8, key, "network_allowed_ips")) {
        try replaceStringList(allocator, &cfg.network_allowed_ips, value);
        return;
    }

    if (std.mem.eql(u8, key, "mount_roots")) {
        try replaceStringList(allocator, &cfg.mount_roots, value);
        return;
    }

    if (std.mem.eql(u8, key, "mounts")) {
        try replaceMountList(allocator, &cfg.mounts, value);
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
///   - kernel_path, initrd_path, disk_path, seed_path, data_disk_path, disk_readonly, data_disk_readonly, kernel_cmdline (if set)
///   - virtio_fs_queues, virtio_fs_cache (if non-default)
///   - network_mode, network_services, network_metadata_file, network allowlists
///   - mount_roots, mounts (if non-empty, as comma-separated)
pub fn writeConfigFile(dir: fs.Dir, cfg: VmConfig) !void {
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
    if (cfg.data_disk_path) |path| {
        try w.print("data_disk_path={s}\n", .{path});
    }
    if (cfg.disk_readonly) {
        try w.print("disk_readonly=true\n", .{});
    }
    if (cfg.data_disk_readonly) {
        try w.print("data_disk_readonly=true\n", .{});
    }
    if (cfg.kernel_cmdline) |value| {
        try w.print("kernel_cmdline={s}\n", .{value});
    }
    if (cfg.virtio_fs_queues != 1) {
        try w.print("virtio_fs_queues={}\n", .{cfg.virtio_fs_queues});
    }
    if (cfg.virtio_fs_cache != .auto) {
        try w.print("virtio_fs_cache={s}\n", .{cfg.virtio_fs_cache.toString()});
    }
    try w.print("network_mode={s}\n", .{cfg.network_mode.toString()});
    if (cfg.network_services.len > 0) {
        try w.writeAll("network_services=");
        for (cfg.network_services, 0..) |service, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(service.toString());
        }
        try w.writeByte('\n');
    }
    if (cfg.network_metadata_file) |path| {
        try w.print("network_metadata_file={s}\n", .{path});
    }
    if (cfg.network_allowed_domains.len > 0) {
        try w.writeAll("network_allowed_domains=");
        for (cfg.network_allowed_domains, 0..) |entry, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(entry);
        }
        try w.writeByte('\n');
    }
    if (cfg.network_allowed_ips.len > 0) {
        try w.writeAll("network_allowed_ips=");
        for (cfg.network_allowed_ips, 0..) |entry, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(entry);
        }
        try w.writeByte('\n');
    }

    if (cfg.mount_roots.len > 0) {
        try w.writeAll("mount_roots=");
        for (cfg.mount_roots, 0..) |root, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll(root);
        }
        try w.writeByte('\n');
    }

    if (cfg.mounts.len > 0) {
        try w.writeAll("mounts=");
        for (cfg.mounts, 0..) |mount_cfg, i| {
            if (i > 0) try w.writeByte(',');
            const formatted = try mounts.formatMountConfig(std.heap.page_allocator, &mount_cfg);
            defer std.heap.page_allocator.free(formatted);
            try w.writeAll(formatted);
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
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
        "data_disk_path=/images/data.ext4\n" ++
        "disk_readonly=true\n" ++
        "data_disk_readonly=true\n" ++
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
    try std.testing.expectEqualStrings("/images/data.ext4", cfg_mut.data_disk_path.?);
    try std.testing.expect(cfg_mut.disk_readonly);
    try std.testing.expect(cfg_mut.data_disk_readonly);
    try std.testing.expectEqualStrings("console=ttyAMA0", cfg_mut.kernel_cmdline.?);
}

test "config: parse mounts and mount_roots" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();

    try f.writeAll("name=testvm\n" ++
        "mount_roots=/data,/shared\n" ++
        "mounts=share:/data/project:/mnt/project:ro:virtiofs\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expectEqual(@as(usize, 2), cfg_mut.mount_roots.len);
    try std.testing.expectEqualStrings("/data", cfg_mut.mount_roots[0]);
    try std.testing.expectEqualStrings("/shared", cfg_mut.mount_roots[1]);
    try std.testing.expectEqual(@as(usize, 1), cfg_mut.mounts.len);
    try std.testing.expectEqualStrings("share", cfg_mut.mounts[0].tag);
    try std.testing.expectEqualStrings("/data/project", cfg_mut.mounts[0].host_path);
    try std.testing.expectEqualStrings("/mnt/project", cfg_mut.mounts[0].guest_path);
    try std.testing.expectEqual(mounts.MountAccess.read_only, cfg_mut.mounts[0].access);
    try std.testing.expectEqual(mounts.MountType.virtio_fs, cfg_mut.mounts[0].mount_type);
}

test "config: rejects malformed lines and bad values" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    cfg.kernel_path = try allocator.dupe(u8, "kernel/bzImage");
    cfg.initrd_path = try allocator.dupe(u8, "initrd.img");
    cfg.disk_path = try allocator.dupe(u8, "rootfs.ext4");
    cfg.seed_path = try allocator.dupe(u8, "seed.iso");
    cfg.mount_roots = try parseCommaSeparated(allocator, "shared,root");
    cfg.mounts = try allocator.alloc(mounts.MountConfig, 1);
    cfg.mounts[0] = .{
        .tag = try allocator.dupe(u8, "share"),
        .host_path = try allocator.dupe(u8, "shared"),
        .guest_path = try allocator.dupe(u8, "/mnt/share"),
        .access = .read_only,
        .mount_type = .virtio_fs,
    };

    try resolveRelativePaths(allocator, "/vm/root", &cfg);

    try std.testing.expectEqualStrings("/vm/root/kernel/bzImage", cfg.kernel_path.?);
    try std.testing.expectEqualStrings("/vm/root/initrd.img", cfg.initrd_path.?);
    try std.testing.expectEqualStrings("/vm/root/rootfs.ext4", cfg.disk_path.?);
    try std.testing.expectEqualStrings("/vm/root/seed.iso", cfg.seed_path.?);
    try std.testing.expectEqualStrings("/vm/root/shared", cfg.mount_roots[0]);
    try std.testing.expectEqualStrings("/vm/root/root", cfg.mount_roots[1]);
    try std.testing.expectEqualStrings("/vm/root/shared", cfg.mounts[0].host_path);
}

test "config: validateStartConfig requires kernel and rootfs" {
    var gpa = std.heap.DebugAllocator(.{}){};
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
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

    const kernel_path = try fs.path.join(allocator, &[_][]const u8{ base, "vmlinuz" });
    defer allocator.free(kernel_path);
    const initrd_path = try fs.path.join(allocator, &[_][]const u8{ base, "initrd.img" });
    defer allocator.free(initrd_path);
    const disk_path = try fs.path.join(allocator, &[_][]const u8{ base, "rootfs.ext4" });
    defer allocator.free(disk_path);
    const seed_path = try fs.path.join(allocator, &[_][]const u8{ base, "seed.iso" });
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
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
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

test "config: removed legacy network keys fail with migration error" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const legacy = [_][]const u8{
        "services=dns\n",
        "metadata_file=meta.json\n",
        "allowed_domains=example.com\n",
        "allowed_ips=192.0.2.0/24\n",
    };

    for (legacy) |line| {
        var tmp = fs.testingTmpDir(.{});
        defer tmp.cleanup();

        var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
        defer f.close();
        try f.writeAll(line);

        try std.testing.expectError(error.RemovedNetworkKey, readConfigFile(allocator, tmp.dir, "fallback"));
    }
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

test "config: parse network services and metadata file" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("m80.conf", .{ .truncate = true });
    defer f.close();
    try f.writeAll("network_mode=allowlist\n" ++
        "network_services=dns, metadata,dns\n" ++
        "network_metadata_file=meta/runtime.json\n" ++
        "network_allowed_domains=example.com,*.example.org:443\n" ++
        "network_allowed_ips=192.0.2.10,198.51.100.0/24,2001:db8::10,2001:db8:abcd::/48\n");

    const cfg = try readConfigFile(allocator, tmp.dir, "fallback");
    var cfg_mut = cfg;
    defer freeConfig(allocator, &cfg_mut);

    try std.testing.expectEqual(NetworkMode.allowlist, cfg_mut.network_mode);
    try std.testing.expectEqual(@as(usize, 2), cfg_mut.network_services.len);
    try std.testing.expectEqual(Service.dns, cfg_mut.network_services[0]);
    try std.testing.expectEqual(Service.metadata, cfg_mut.network_services[1]);
    try std.testing.expectEqualStrings("meta/runtime.json", cfg_mut.network_metadata_file.?);
    try std.testing.expectEqualStrings("example.com", cfg_mut.network_allowed_domains[0]);
    try std.testing.expectEqualStrings("*.example.org:443", cfg_mut.network_allowed_domains[1]);
    try std.testing.expectEqualStrings("192.0.2.10", cfg_mut.network_allowed_ips[0]);
    try std.testing.expectEqualStrings("198.51.100.0/24", cfg_mut.network_allowed_ips[1]);
    try std.testing.expectEqualStrings("2001:db8::10", cfg_mut.network_allowed_ips[2]);
    try std.testing.expectEqualStrings("2001:db8:abcd::/48", cfg_mut.network_allowed_ips[3]);
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

test "config: validateStartConfig requires mount_roots for mounts" {
    var cfg = try defaultConfig(std.testing.allocator, "test");
    defer freeConfig(std.testing.allocator, &cfg);
    cfg.kernel_path = try std.testing.allocator.dupe(u8, "kernel");
    cfg.disk_path = try std.testing.allocator.dupe(u8, "disk");
    cfg.mounts = try std.testing.allocator.alloc(mounts.MountConfig, 1);
    cfg.mounts[0] = .{
        .tag = try std.testing.allocator.dupe(u8, "share"),
        .host_path = try std.testing.allocator.dupe(u8, "/data"),
        .guest_path = try std.testing.allocator.dupe(u8, "/mnt"),
        .access = .read_only,
        .mount_type = .virtio_fs,
    };

    try std.testing.expectError(error.MountRootsRequired, validateStartConfig(&cfg));
}

test "config: validateStartConfig validates network allowlists" {
    var cfg = try defaultConfig(std.testing.allocator, "test");
    defer freeConfig(std.testing.allocator, &cfg);
    cfg.kernel_path = try std.testing.allocator.dupe(u8, "/kernel");
    cfg.initrd_path = try std.testing.allocator.dupe(u8, "/initrd.img");
    cfg.network_mode = .allowlist;

    cfg.network_allowed_domains = try parseCommaSeparated(std.testing.allocator, "example.com,*.example.org:443");
    cfg.network_allowed_ips = try parseCommaSeparated(std.testing.allocator, "192.0.2.10,198.51.100.0/24,2001:db8::10,2001:db8:abcd::/48");
    try validateStartConfig(&cfg);

    freeStringList(std.testing.allocator, &cfg.network_allowed_domains);
    cfg.network_allowed_domains = try parseCommaSeparated(std.testing.allocator, "-bad.example");
    try std.testing.expectError(error.InvalidNetworkAllowedDomainSpec, validateStartConfig(&cfg));

    freeStringList(std.testing.allocator, &cfg.network_allowed_domains);
    cfg.network_allowed_domains = &[_][]const u8{};
    freeStringList(std.testing.allocator, &cfg.network_allowed_ips);
    cfg.network_allowed_ips = try parseCommaSeparated(std.testing.allocator, "192.0.2.0/99");
    try std.testing.expectError(error.InvalidNetworkAllowedIpSpec, validateStartConfig(&cfg));

    freeStringList(std.testing.allocator, &cfg.network_allowed_ips);
    cfg.network_allowed_ips = try parseCommaSeparated(std.testing.allocator, "2001:db8::/129");
    try std.testing.expectError(error.InvalidNetworkAllowedIpSpec, validateStartConfig(&cfg));
}

test "config: writeConfigFile emits network keys" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var cfg = try defaultConfig(allocator, "testvm");
    defer freeConfig(allocator, &cfg);

    var services = try allocator.alloc(Service, 2);
    services[0] = .dns;
    services[1] = .metadata;
    cfg.network_mode = .allowlist;
    cfg.network_services = services;
    cfg.network_metadata_file = try allocator.dupe(u8, "/tmp/meta.json");
    cfg.network_allowed_domains = try parseCommaSeparated(allocator, "example.com,*.example.org:443");
    cfg.network_allowed_ips = try parseCommaSeparated(allocator, "192.0.2.10,198.51.100.0/24,2001:db8::10");

    try writeConfigFile(tmp.dir, cfg);
    const data = try tmp.dir.readFileAlloc(allocator, "m80.conf", 64 * 1024);
    defer allocator.free(data);

    try std.testing.expect(std.mem.indexOf(u8, data, "network_mode=allowlist") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "network_services=dns,metadata") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "network_metadata_file=/tmp/meta.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "network_allowed_domains=example.com,*.example.org:443") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "network_allowed_ips=192.0.2.10,198.51.100.0/24,2001:db8::10") != null);
}

test "config: unknown keys are ignored" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
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

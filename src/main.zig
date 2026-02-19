//! m80 CLI Entry Point
//!
//! This is the main entry point for the m80 microVM manager. It provides a command-line
//! interface for managing lightweight virtual machines across Windows, macOS, and Linux.
//!
//! ## Supported Commands
//! - `init <name>`: Create a new VM with the given name (creates directory and default config)
//! - `start <name>`: Start an existing VM (loads config, sets up jailer, launches hypervisor)
//! - `console <name>`: Attach to a running VM console (raw TTY, Unix socket)
//! - `stop <name>`: Stop a running VM
//! - `delete <name>`: Remove a VM and its associated files
//! - `ps`: List all VMs and their current status (running/stopped)
//! - `inspect <name>`: Show details about a specific VM (directory, status, config file)
//! - `help`: Display usage information
//!
//! ## Architecture Overview
//! The CLI follows this flow for VM operations:
//! 1. Parse command-line arguments
//! 2. Validate the VM name (alphanumeric, underscores, hyphens only)
//! 3. For `start`: Initialize Jailer (security sandbox) → Load config → Start VM
//! 4. Update VM status file to reflect current state
//!
//! ## Data Storage
//! VMs are stored in platform-specific data directories:
//! - Windows: %LOCALAPPDATA%\m80\vms\<name>\
//! - POSIX: ~/.local/share/m80/vms/<name>/
//!
//! Each VM directory contains:
//! - `m80.conf`: Configuration file (kernel path, memory, CPU cores, network settings)
//! - `.status`: Current VM state (running/stopped)

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
const errors = core.errors;
const state = core.state;
const log = @import("util/log.zig");
const mounts = @import("fs/mounts.zig");
const c = if (builtin.os.tag == .windows)
    struct {}
else
    @cImport({
        @cInclude("termios.h");
    });

const Vm = @import("vm/vm.zig").Vm;
const Jailer = @import("jailer/jailer.zig").Jailer;

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

const RawTty = struct {
    fd: std.posix.fd_t,
    prev: std.posix.termios,
};

fn enableRawStdin() ?RawTty {
    if (builtin.os.tag == .windows) return null;
    const fd = std.fs.File.stdin().handle;
    if (!std.posix.isatty(fd)) return null;
    const prev = std.posix.tcgetattr(fd) catch return null;
    var raw = prev;
    raw.iflag.IGNBRK = false;
    raw.iflag.BRKINT = false;
    raw.iflag.PARMRK = false;
    raw.iflag.ISTRIP = false;
    raw.iflag.INLCR = false;
    raw.iflag.IGNCR = false;
    raw.iflag.ICRNL = false;
    raw.iflag.IXON = false;
    if (@hasField(@TypeOf(raw.iflag), "IXOFF")) raw.iflag.IXOFF = false;
    if (@hasField(@TypeOf(raw.iflag), "IXANY")) raw.iflag.IXANY = false;

    raw.oflag.OPOST = false;
    if (@hasField(@TypeOf(raw.oflag), "ONLCR")) raw.oflag.ONLCR = false;

    raw.lflag.ECHO = false;
    raw.lflag.ECHONL = false;
    raw.lflag.ICANON = false;
    raw.lflag.ISIG = false;
    raw.lflag.IEXTEN = false;

    raw.cflag.CREAD = true;
    raw.cflag.CSIZE = .CS8;
    raw.cc[@intCast(c.VMIN)] = 1;
    raw.cc[@intCast(c.VTIME)] = 0;
    std.posix.tcsetattr(fd, .FLUSH, raw) catch return null;
    return .{ .fd = fd, .prev = prev };
}

fn restoreRawStdin(raw: RawTty) void {
    std.posix.tcsetattr(raw.fd, .FLUSH, raw.prev) catch {};
}

fn setEnvFlag(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (builtin.os.tag == .windows) return;
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);
    _ = setenv(name_z, value_z, 1);
}

const help_text =
    \\m80 - cross-platform microvm runtime
    \\
    \\usage:
    \\  m80 init <name>              create a new VM
    \\  m80 start <name>             start a VM in the background
    \\  m80 console <name>           attach to a running VM console
    \\  m80 stop <name>              stop a running VM
    \\  m80 delete <name>            remove a VM and its files
    \\  m80 ps                       list all VMs and their status
    \\  m80 inspect <name>           show VM details
    \\  m80 snapshot <name> <path>   save running VM disk snapshot to directory
    \\  m80 restore <name> <path>    restore VM disks from snapshot directory
    \\  m80 clone <name> <new-name>  clone a VM (copy config)
    \\  m80 help                     show this help message
    \\
;

/// Writes the help text to the provided writer.
/// This is separated from printHelp() so tests can capture the output.
///
/// Parameters:
///   - writer: Any type that implements the Writer interface (e.g., stderr, a buffer)
pub fn writeHelp(writer: anytype) !void {
    try writer.writeAll(help_text);
}

/// Convenience wrapper that prints help text to stdout.
/// Silently ignores any write errors (stdout might be closed/redirected).
fn printHelp() void {
    std.debug.print("{s}", .{help_text});
}

/// Checks if a file exists at the given path and returns its size in bytes.
/// Used during preflight logging to show kernel/initrd file sizes.
///
/// Parameters:
///   - path_opt: Optional file path (can be null if not configured)
///
/// Returns:
///   - File size in bytes if the file exists and is accessible
///   - null if path is null, file doesn't exist, or stat fails
fn fileSizeIfExists(path_opt: ?[]const u8) ?u64 {
    if (path_opt == null) return null;
    const path = path_opt.?;
    const file = if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{});

    if (file) |f| {
        defer f.close();
        const stat = f.stat() catch return null;
        return stat.size;
    } else |_| {
        return null;
    }
}

fn vmConsoleSocketPath(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);
    return try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "console.sock" });
}

fn readVmPid(vm_dir: std.fs.Dir) ?i32 {
    var file = vm_dir.openFile("pid", .{}) catch return null;
    defer file.close();
    var buf: [32]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(i32, trimmed, 10) catch null;
}

fn writeVmPid(vm_dir: std.fs.Dir, pid: i32) !void {
    var file = try vm_dir.createFile("pid", .{ .truncate = true });
    defer file.close();
    var buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    try file.writeAll(pid_str);
}

fn clearVmPid(vm_dir: std.fs.Dir) void {
    vm_dir.deleteFile("pid") catch {};
}

fn waitForPidExit(pid: i32, sleep_ms: u64, max_attempts: usize) bool {
    var attempts: usize = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        if (!isPidAlive(pid)) return true;
        std.Thread.sleep(sleep_ms * std.time.ns_per_ms);
    }
    return !isPidAlive(pid);
}

fn isPidAlive(pid: i32) bool {
    if (builtin.os.tag == .windows) return false;
    if (pid <= 0) return false;
    std.posix.kill(pid, 0) catch |e| switch (e) {
        error.ProcessNotFound => return false,
        else => return true,
    };
    return true;
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try std.posix.write(fd, bytes[offset..]);
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

/// Logs a file path and its size at debug level.
/// Used to show kernel and initrd paths during VM start preflight checks.
///
/// Output format:
///   - If path is null: "<label> path: (unset)"
///   - If path exists: "<label> path: <path>" and "<label> size: <bytes> bytes"
///   - If path doesn't exist: "<label> path: <path>" and "<label> size: (unavailable)"
///
/// Parameters:
///   - label: Human-readable name for the file (e.g., "kernel", "initrd")
///   - path_opt: Optional file path to log
fn logPathAndSize(label: []const u8, path_opt: ?[]const u8) void {
    if (path_opt == null) {
        log.debug("{s} path: (unset)", .{label});
        return;
    }
    const path = path_opt.?;
    log.debug("{s} path: {s}", .{ label, path });

    if (fileSizeIfExists(path_opt)) |size| {
        log.debug("{s} size: {d} bytes", .{ label, size });
    } else {
        log.debug("{s} size: (unavailable)", .{label});
    }
}

/// Logs VM configuration details before starting.
/// Only outputs at debug level to avoid leaking sensitive host paths in production.
///
/// Logs the following configuration values:
///   - cpu_cores: Number of virtual CPUs assigned to the VM
///   - memory_mb: RAM allocation in megabytes
///   - kernel: Path to the Linux kernel image and its file size
///   - initrd: Path to the initial ramdisk and its file size
///   - disk: Path to the rootfs disk image and its file size
///   - seed: Path to the cloud-init seed image and its file size
///   - kernel_cmdline: Optional kernel command line override
///
/// Parameters:
///   - cfg: Pointer to the VM configuration struct
fn logStartPreflight(cfg: *const core.config.VmConfig) void {
    // Preflight logs are debug-only to avoid leaking host paths by default.
    log.debug("vm start preflight:", .{});
    log.debug("cpu_cores: {d}", .{cfg.cpu_cores});
    log.debug("memory_mb: {d}", .{cfg.memory_mb});
    logPathAndSize("kernel", cfg.kernel_path);
    logPathAndSize("initrd", cfg.initrd_path);
    logPathAndSize("disk", cfg.disk_path);
    logPathAndSize("seed", cfg.seed_path);
    logPathAndSize("data_disk", cfg.data_disk_path);
    if (cfg.kernel_cmdline) |cmdline| {
        log.debug("kernel_cmdline: {s}", .{cmdline});
    }
}

fn optPath(path: ?[]const u8) []const u8 {
    return path orelse "<unset>";
}

fn dieStartConfigError(err: core.config.StartConfigError, cfg: *const core.config.VmConfig) noreturn {
    switch (err) {
        error.MissingKernel => errors.die(
            "kernel_path not set in m80.conf. Set kernel_path=/path/to/Image and retry.",
            .{},
        ),
        error.MissingRootfs => errors.die(
            "initrd_path or disk_path required. Set initrd_path=/path/to/initrd.gz or disk_path=/path/to/rootfs.raw and retry.",
            .{},
        ),
        error.SeedRequiresDisk => errors.die(
            "seed_path requires disk_path. Set disk_path or remove seed_path.",
            .{},
        ),
        error.KernelNotFound => errors.die(
            "kernel_path not found: {s}. Check the path or download a kernel.",
            .{optPath(cfg.kernel_path)},
        ),
        error.InitrdNotFound => errors.die(
            "initrd_path not found: {s}. Check the path or provide a valid initrd.",
            .{optPath(cfg.initrd_path)},
        ),
        error.DiskNotFound => errors.die(
            "disk_path not found: {s}. Check the path or provide a valid rootfs image.",
            .{optPath(cfg.disk_path)},
        ),
        error.SeedNotFound => errors.die(
            "seed_path not found: {s}. Check the path or remove seed_path.",
            .{optPath(cfg.seed_path)},
        ),
        error.DataDiskNotFound => errors.die(
            "data_disk_path not found: {s}. Check the path or remove data_disk_path.",
            .{optPath(cfg.data_disk_path)},
        ),
        error.KernelUnreadable => errors.die(
            "kernel_path not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.kernel_path)},
        ),
        error.InitrdUnreadable => errors.die(
            "initrd_path not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.initrd_path)},
        ),
        error.DiskUnreadable => errors.die(
            "disk_path not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.disk_path)},
        ),
        error.SeedUnreadable => errors.die(
            "seed_path not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.seed_path)},
        ),
        error.DataDiskUnreadable => errors.die(
            "data_disk_path not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.data_disk_path)},
        ),
        error.OpenNetworkNotAllowed => errors.die(
            "network_mode=open requires explicit opt-in. Run `export M80_ALLOW_OPEN_NETWORK=1` and retry.",
            .{},
        ),
        error.InvalidAllowedDomainSpec => errors.die(
            "allowed_domains contains an invalid entry. Use domain patterns like `example.com`, `*.example.com`, or `example.com:443`.",
            .{},
        ),
        error.InvalidAllowedIpSpec => errors.die(
            "allowed_ips contains an invalid entry. Use IPv4 or CIDR values like `1.2.3.4` or `10.0.0.0/8`.",
            .{},
        ),
        error.MountRootsRequired => errors.die(
            "mounts configured but mount_roots is empty. Set mount_roots=/allowed/path and retry.",
            .{},
        ),
        error.MountTypeUnsupported => errors.die(
            "mounts configured with unsupported type. Use mount_type=virtiofs.",
            .{},
        ),
        error.MountCountUnsupported => errors.die(
            "only one mount is supported right now. Remove extra mounts and retry.",
            .{},
        ),
        error.VirtioFsQueuesInvalid => errors.die(
            "virtio_fs_queues must be between 1 and 8. Set virtio_fs_queues=1 and retry.",
            .{},
        ),
    }
}

fn ensureDebVmConfig(allocator: std.mem.Allocator) !void {
    const name = "deb";
    state.initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => {},
        error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
        else => return e,
    };

    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| {
        errors.die("invalid config: {s}", .{@errorName(e)});
    };
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);

    const cwd_path = try cwd.realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    const kernel_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "debian-kernels", "boot", "vmlinuz-6.1.0-42-cloud-arm64" },
    );
    defer allocator.free(kernel_path);
    const initrd_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "m80-initramfs.cpio.gz" },
    );
    defer allocator.free(initrd_path);
    const disk_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "debian-12-nocloud-arm64-20250703-2162.raw" },
    );
    defer allocator.free(disk_path);
    const seed_path = try std.fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "debian-nocloud-seed.iso" });
    defer allocator.free(seed_path);

    if (cfg_mut.kernel_path) |path| {
        if (!std.mem.eql(u8, path, kernel_path)) {
            allocator.free(path);
            cfg_mut.kernel_path = null;
        }
    }
    if (cfg_mut.kernel_path == null) {
        cfg_mut.kernel_path = try allocator.dupe(u8, kernel_path);
    }
    if (cfg_mut.disk_path) |path| {
        if (!std.mem.eql(u8, path, disk_path)) {
            allocator.free(path);
            cfg_mut.disk_path = null;
        }
    }
    if (cfg_mut.disk_path == null) {
        cfg_mut.disk_path = try allocator.dupe(u8, disk_path);
    }
    cfg_mut.disk_readonly = false;
    if (cfg_mut.seed_path == null) {
        cfg_mut.seed_path = try allocator.dupe(u8, seed_path);
    }
    if (cfg_mut.initrd_path) |path| {
        if (!std.mem.eql(u8, path, initrd_path)) {
            allocator.free(path);
            cfg_mut.initrd_path = null;
        }
    }
    if (cfg_mut.initrd_path == null) {
        cfg_mut.initrd_path = try allocator.dupe(u8, initrd_path);
    }
    if (cfg_mut.kernel_cmdline) |cmdline| {
        allocator.free(cmdline);
        cfg_mut.kernel_cmdline = null;
    }
    cfg_mut.kernel_cmdline = try allocator.dupe(
        u8,
        "earlycon=pl011,0x09000000 keep_bootcon console=ttyAMA0 console=hvc0 root=/dev/vda1 rootwait rootfstype=ext4 rw devtmpfs.mount=1 systemd.mask=boot-efi.mount systemd.mask=systemd-boot-update.service quiet loglevel=3 systemd.show_status=false systemd.log_level=warning systemd.log_color=no fsck.mode=skip fsck.repair=no",
    );

    // Only set default mounts if none are configured
    if (cfg_mut.mounts.len == 0) {
        if (cfg_mut.mount_roots.len > 0) {
            for (cfg_mut.mount_roots) |root| allocator.free(root);
            allocator.free(cfg_mut.mount_roots);
            cfg_mut.mount_roots = &[_][]const u8{};
        }

        const mount_root = std.fs.path.dirname(cwd_path) orelse cwd_path;
        const mount_root_owned = try allocator.dupe(u8, mount_root);
        const mount_host = try allocator.dupe(u8, cwd_path);
        const mount_tag = try allocator.dupe(u8, "host");
        const mount_guest = try allocator.dupe(u8, "/mnt/host");

        const mount_roots_list = try allocator.alloc([]const u8, 1);
        @constCast(mount_roots_list)[0] = mount_root_owned;
        cfg_mut.mount_roots = mount_roots_list;

        cfg_mut.mounts = try allocator.alloc(mounts.MountConfig, 1);
        cfg_mut.mounts[0] = .{
            .tag = mount_tag,
            .host_path = mount_host,
            .guest_path = mount_guest,
            .access = .read_write,
            .mount_type = .virtio_fs,
            .max_file_size = 0,
            .allow_exec = false,
        };
    }

    try core.config.writeConfigFile(vm_dir, cfg_mut);
}

fn startVmCommand(allocator: std.mem.Allocator, name: []const u8, ensure_deb: bool, attach: bool) !void {
    if (ensure_deb) {
        try ensureDebVmConfig(allocator);
    }
    const restore_path = std.process.getEnvVarOwned(allocator, "M80_RESTORE_PATH") catch null;
    defer if (restore_path) |path| allocator.free(path);
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const st = core.state.getStatus(vm_dir) catch .stopped;
    if (st == .running) {
        errors.die(
            "vm already running: {s}\nuse `m80 stop {s}` to stop it",
            .{ name, name },
        );
    }

    const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| {
        errors.die("invalid config: {s}", .{@errorName(e)});
    };
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);

    try core.config.resolveRelativePaths(allocator, dir_path, &cfg_mut);

    logStartPreflight(&cfg_mut);

    core.config.validateStartConfig(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };
    core.config.validateStartFiles(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };
    jailer.prepareForVm(dir_path, &cfg_mut) catch |e| {
        errors.die("jailer prepare failed: {s}", .{@errorName(e)});
    };

    vm.start(cfg_mut) catch |e| switch (e) {
        error.MountsInvalid => errors.die(
            "mounts rejected. Ensure mount_roots includes the host path and no path traversal is present.",
            .{},
        ),
        error.MountsUnsupported => errors.die(
            "mounts not supported in this configuration. Use a single virtiofs mount.",
            .{},
        ),
        else => errors.die("start failed: {s}", .{@errorName(e)}),
    };

    if (restore_path) |path| {
        log.info("restoring filesystem snapshot: {s}", .{path});
        vm.restoreFilesystem(cfg_mut, path) catch |e| {
            log.err("filesystem restore failed: {s}", .{@errorName(e)});
            vm.stop() catch {};
            writeResultFile(vm_dir, restore_result_file, @errorName(e));
            return e;
        };
        log.info("filesystem restore complete", .{});
        writeResultFile(vm_dir, restore_result_file, "ok");
    }

    state.setStatus(allocator, name, .running) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}\n", .{name}),
        error.NotFound => errors.die("vm not found: {s}\n", .{name}),
        else => return e,
    };
    if (!attach) {
        std.debug.print("vm started: {s}\n", .{name});
        return;
    }

    stop_requested.store(false, .seq_cst);
    installSignalHandlers() catch |e| {
        errors.die("start failed: {s}", .{@errorName(e)});
    };
    std.debug.print("vm running (Ctrl+C to stop)\n", .{});
    try waitForStopOrSnapshot(allocator, &vm, vm_dir, &cfg_mut);

    vm.stop() catch |e| {
        errors.die("stop failed: {s}", .{@errorName(e)});
    };
    state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}\n", .{name}),
        error.NotFound => errors.die("vm not found: {s}\n", .{name}),
        else => return e,
    };
    std.debug.print("stopped vm: {s}\n", .{name});
}

var stop_requested = std.atomic.Value(bool).init(false);

fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    stop_requested.store(true, .seq_cst);
}

fn installSignalHandlers() !void {
    if (builtin.os.tag == .windows) return;
    const action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);
}

fn waitForStopSignal() void {
    if (builtin.os.tag == .windows) {
        while (true) {
            std.Thread.sleep(250 * std.time.ns_per_ms);
        }
    }
    while (!stop_requested.load(.seq_cst)) {
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
}

const snapshot_request_file = "snapshot.request";
const snapshot_result_file = "snapshot.result";
const restore_request_file = "restore.request";
const restore_result_file = "restore.result";
const stop_request_file = "stop.request";
const vm_action_max_attempts: usize = 600;
const vm_action_poll_ms: u64 = 200;
const request_file_max_bytes: usize = 4096;
const result_file_max_bytes: usize = 1024;

const VmActionWaitResult = union(enum) {
    ok,
    failed: []u8,
    timeout,
};

fn writeStopRequest(vm_dir: std.fs.Dir) !void {
    var req = try vm_dir.createFile(stop_request_file, .{ .truncate = true });
    defer req.close();
    try req.writeAll("1\n");
}

fn hasStopRequest(vm_dir: std.fs.Dir) !bool {
    var file = vm_dir.openFile(stop_request_file, .{}) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return e,
    };
    file.close();
    return true;
}

fn readOptionalTrimmedFile(
    allocator: std.mem.Allocator,
    vm_dir: std.fs.Dir,
    file_name: []const u8,
    max_bytes: usize,
) !?[]u8 {
    var file = vm_dir.openFile(file_name, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();

    const data = try file.readToEndAlloc(allocator, max_bytes);
    defer allocator.free(data);

    const trimmed = std.mem.trim(u8, data, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn readPathRequest(
    allocator: std.mem.Allocator,
    vm_dir: std.fs.Dir,
    request_file: []const u8,
) !?[]u8 {
    return readOptionalTrimmedFile(allocator, vm_dir, request_file, request_file_max_bytes);
}

fn writePathRequest(vm_dir: std.fs.Dir, request_file: []const u8, path: []const u8) !void {
    var req = try vm_dir.createFile(request_file, .{ .truncate = true });
    defer req.close();
    try req.writeAll(path);
}

fn writeResultFile(vm_dir: std.fs.Dir, result_file: []const u8, msg: []const u8) void {
    var file = vm_dir.createFile(result_file, .{ .truncate = true }) catch return;
    defer file.close();
    _ = file.writeAll(msg) catch {};
}

fn waitForVmActionResult(
    allocator: std.mem.Allocator,
    vm_dir: std.fs.Dir,
    result_file: []const u8,
) !VmActionWaitResult {
    var attempts: usize = 0;
    while (attempts < vm_action_max_attempts) : (attempts += 1) {
        const result = try readOptionalTrimmedFile(allocator, vm_dir, result_file, result_file_max_bytes);
        if (result) |msg| {
            vm_dir.deleteFile(result_file) catch {};
            if (std.mem.eql(u8, msg, "ok")) {
                allocator.free(msg);
                return .ok;
            }
            return .{ .failed = msg };
        }
        std.Thread.sleep(vm_action_poll_ms * std.time.ns_per_ms);
    }
    return .timeout;
}

fn waitForStopOrSnapshot(
    allocator: std.mem.Allocator,
    vm: *Vm,
    vm_dir: std.fs.Dir,
    cfg: *const core.config.VmConfig,
) !void {
    if (builtin.os.tag == .windows) {
        waitForStopSignal();
        return;
    }

    while (!stop_requested.load(.seq_cst)) {
        if (try hasStopRequest(vm_dir)) {
            log.info("stop request received", .{});
            stop_requested.store(true, .seq_cst);
            vm_dir.deleteFile(stop_request_file) catch {};
            break;
        }
        if (try readPathRequest(allocator, vm_dir, snapshot_request_file)) |path| {
            defer allocator.free(path);
            log.info("snapshot request path={s}", .{path});
            vm.snapshotFilesystem(cfg.*, path) catch |e| {
                log.warn("snapshot failed: {s}", .{@errorName(e)});
                writeResultFile(vm_dir, snapshot_result_file, @errorName(e));
                vm_dir.deleteFile(snapshot_request_file) catch {};
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            writeResultFile(vm_dir, snapshot_result_file, "ok");
            vm_dir.deleteFile(snapshot_request_file) catch {};
        }
        if (try readPathRequest(allocator, vm_dir, restore_request_file)) |path| {
            defer allocator.free(path);
            log.info("restore request path={s}", .{path});
            vm.restoreFilesystem(cfg.*, path) catch |e| {
                log.warn("restore failed: {s}", .{@errorName(e)});
                writeResultFile(vm_dir, restore_result_file, @errorName(e));
                vm_dir.deleteFile(restore_request_file) catch {};
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            writeResultFile(vm_dir, restore_result_file, "ok");
            vm_dir.deleteFile(restore_request_file) catch {};
        }
        std.Thread.sleep(200 * std.time.ns_per_ms);
    }
}

/// Main entry point for the m80 CLI application.
///
/// This function:
/// 1. Sets up a general-purpose memory allocator with leak detection
/// 2. Initializes logging based on M80_LOG_LEVEL environment variable
/// 3. Parses command-line arguments and dispatches to the appropriate handler
///
/// Memory Management:
///   Uses Zig's GeneralPurposeAllocator which tracks allocations and reports
///   leaks on deinit (in debug builds). All allocated memory is freed via defer.
///
/// Error Handling:
///   - User errors (invalid name, VM not found) call errors.die() which prints
///     a message to stderr and exits with code 1
///   - System errors bubble up as Zig errors
pub fn main() !void {
    // Initialize the general-purpose allocator. This allocator tracks memory
    // allocations and will report leaks when deinit() is called (debug builds).
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Set up logging. Reads M80_LOG_LEVEL env var (debug/info/warn/error).
    // Default level is "info" if not set.
    log.initFromEnv(allocator);

    // Parse command-line arguments into a slice of strings.
    // args[0] is the program name, args[1] is the command, args[2+] are arguments.
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // No command provided - show help
    if (args.len < 2) {
        printHelp();
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        printHelp();
        return;
    }

    // ===== PS COMMAND =====
    // Lists all VMs and their status. Does not require a VM name argument.
    // Output format: "<name>\t<status>" one per line, or "(no vms)" if empty.
    if (std.mem.eql(u8, cmd, "ps")) {
        // Fetch list of all VMs from the data directory
        const vms = try state.listVms(allocator);
        defer {
            // Clean up: free each VM name string, then the slice itself
            for (vms) |r| allocator.free(r.name);
            allocator.free(vms);
        }

        if (vms.len == 0) {
            std.debug.print("(no vms)\n", .{});
            return;
        }

        // Print each VM's name and status in tab-separated format
        for (vms) |r| {
            std.debug.print("{s}\t{s}\n", .{
                r.name,
                switch (r.status) {
                    .running => "running",
                    .stopped => "stopped",
                },
            });
        }
        return;
    }

    // ===== COMMANDS REQUIRING A VM NAME =====
    // All remaining commands (init, start, stop, delete, inspect) require a VM name.
    if (args.len < 3) {
        errors.die("missing <name>", .{});
    }
    const name = args[2];

    // Validate VM name to prevent path traversal attacks and filesystem issues.
    // Valid names: alphanumeric characters, underscores, hyphens only.
    // Invalid: empty, ".", "..", contains "/" or "\", control characters, etc.
    if (!core.paths.validateVmName(name)) {
        errors.die("invalid vm name: {s}", .{name});
    }

    // ===== INIT COMMAND =====
    // Creates a new VM directory with a default m80.conf configuration file.
    // The user should edit m80.conf to set kernel_path, memory, etc. before starting.
    if (std.mem.eql(u8, cmd, "init")) {
        state.initVm(allocator, name) catch |e| switch (e) {
            error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
            error.AlreadyExists => errors.die("vm already exists: {s}", .{name}),
            else => return e,
        };
        std.debug.print("initialized vm: {s}\n", .{name});
        return;
    }

    // ===== DELETE COMMAND =====
    // Removes the VM directory and all its contents (config, status file).
    // Uses safe deletion to prevent escaping the VM directory via symlinks.
    if (std.mem.eql(u8, cmd, "delete")) {
        state.deleteVm(allocator, name) catch |e| switch (e) {
            error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
            error.NotFound => errors.die("vm not found: {s}", .{name}),
            else => return e,
        };
        std.debug.print("deleted vm: {s}\n", .{name});
        return;
    }

    // ===== START COMMAND =====
    // Starts a VM in the background by spawning `m80 run <name>`.
    if (std.mem.eql(u8, cmd, "start")) {
        const ensure = std.mem.eql(u8, name, "deb");
        if (ensure) {
            try ensureDebVmConfig(allocator);
        }

        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);

        var cwd = std.fs.cwd();
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();

        if (readVmPid(vm_dir)) |pid| {
            vm_dir.deleteFile(stop_request_file) catch {};
            if (isPidAlive(pid)) {
                errors.die("vm already running: {s}", .{name});
            }
            clearVmPid(vm_dir);
            state.setStatus(allocator, name, .stopped) catch {};
        }

        const socket_path = try vmConsoleSocketPath(allocator, name);
        defer allocator.free(socket_path);
        std.fs.cwd().deleteFile(socket_path) catch {};
        vm_dir.deleteFile(stop_request_file) catch {};

        const exe_path = try std.fs.selfExePathAlloc(allocator);
        defer allocator.free(exe_path);

        var argv = [_][]const u8{ exe_path, "run", name };
        var child = std.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        if (builtin.os.tag != .windows) {
            child.pgid = 0;
        }

        var env_map = try std.process.getEnvMap(allocator);
        defer env_map.deinit();
        try env_map.put("M80_CONSOLE_SOCKET", socket_path);
        try env_map.put("M80_VIRTIO_CONSOLE", "1");
        const log_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "run.log" });
        defer allocator.free(log_path);
        try env_map.put("M80_LOG_FILE", log_path);
        child.env_map = &env_map;

        try child.spawn();
        if (builtin.os.tag != .windows) {
            try writeVmPid(vm_dir, @intCast(child.id));
        }

        var started = false;
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            const st = core.state.getStatus(vm_dir) catch .stopped;
            if (st == .running) {
                started = true;
                break;
            }
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
        if (started) {
            std.debug.print("vm started: {s}\n", .{name});
        } else {
            std.debug.print("vm starting: {s}\n", .{name});
        }
        return;
    }

    // ===== RUN COMMAND (internal) =====
    // Runs the VM in the foreground; used by `start` to detach.
    if (std.mem.eql(u8, cmd, "run")) {
        const ensure = std.mem.eql(u8, name, "deb");
        if (std.process.getEnvVarOwned(allocator, "M80_CONSOLE_SOCKET") catch null == null) {
            const socket_path = try vmConsoleSocketPath(allocator, name);
            defer allocator.free(socket_path);
            setEnvFlag(allocator, "M80_CONSOLE_SOCKET", socket_path) catch {};
        }
        try startVmCommand(allocator, name, ensure, true);
        return;
    }

    // ===== CONSOLE COMMAND =====
    // Attaches to a running VM's console via Unix socket.
    if (std.mem.eql(u8, cmd, "console")) {
        var cwd = std.fs.cwd();
        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();

        if (readVmPid(vm_dir)) |pid| {
            if (!isPidAlive(pid)) {
                clearVmPid(vm_dir);
                state.setStatus(allocator, name, .stopped) catch {};
                errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
            }
        } else {
            errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
        }

        const socket_path = try vmConsoleSocketPath(allocator, name);
        defer allocator.free(socket_path);

        const raw = enableRawStdin();
        defer if (raw) |tty_state| restoreRawStdin(tty_state);

        var stream = std.net.connectUnixSocket(socket_path) catch |e| {
            errors.die("console connect failed: {s}\ncheck that the VM is running and console.sock exists", .{@errorName(e)});
        };
        defer stream.close();

        const socket_fd = stream.handle;
        const stdin_fd = std.fs.File.stdin().handle;
        const stdout_fd = std.fs.File.stdout().handle;
        var buf: [1024]u8 = undefined;
        var detached = false;
        while (true) {
            var fds = [_]std.posix.pollfd{
                .{ .fd = stdin_fd, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = socket_fd, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const ready = std.posix.poll(fds[0..], -1) catch break;
            if (ready <= 0) continue;
            if ((fds[0].revents & std.posix.POLL.IN) != 0) {
                const n = std.posix.read(stdin_fd, &buf) catch break;
                if (n <= 0) break;
                const chunk = buf[0..@intCast(n)];
                if (std.mem.indexOfScalar(u8, chunk, 0x04)) |eof_index| {
                    if (eof_index > 0) {
                        writeAllFd(socket_fd, chunk[0..eof_index]) catch break;
                    }
                    detached = true;
                    break;
                }
                writeAllFd(socket_fd, chunk) catch break;
            }
            if ((fds[1].revents & std.posix.POLL.IN) != 0) {
                const n = std.posix.read(socket_fd, &buf) catch break;
                if (n <= 0) break;
                writeAllFd(stdout_fd, buf[0..@intCast(n)]) catch break;
            }
        }
        if (detached) {
            std.debug.print("(detached from console)\n", .{});
        }
        return;
    }

    // ===== STOP COMMAND =====
    // Stops a running VM by signaling the hypervisor to terminate.
    // Updates the status file to "stopped" after successful shutdown.
    if (std.mem.eql(u8, cmd, "stop")) {
        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);

        var cwd = std.fs.cwd();
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();

        if (readVmPid(vm_dir)) |pid| {
            vm_dir.deleteFile(stop_request_file) catch {};
            if (builtin.os.tag != .windows) {
                writeStopRequest(vm_dir) catch |e| {
                    log.warn("stop request write failed: {s}", .{@errorName(e)});
                };
                var exited = waitForPidExit(pid, 100, 50);
                if (!exited) {
                    std.posix.kill(pid, std.posix.SIG.TERM) catch |e| switch (e) {
                        error.ProcessNotFound => {},
                        else => errors.die("stop failed: {s}", .{@errorName(e)}),
                    };
                    exited = waitForPidExit(pid, 100, 50);
                }
                if (!exited) {
                    std.posix.kill(pid, std.posix.SIG.KILL) catch {};
                    _ = waitForPidExit(pid, 100, 10);
                }
            }
            clearVmPid(vm_dir);
            vm_dir.deleteFile(stop_request_file) catch {};
        } else {
            // Fallback to in-process stop (legacy behavior).
            var jailer = try Jailer.init(allocator);
            defer jailer.deinit();

            var vm = try Vm.init(allocator, &jailer);
            defer vm.deinit();

            vm.stop() catch |e| {
                errors.die("stop failed: {s}", .{@errorName(e)});
            };
        }

        state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
            error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
            error.NotFound => errors.die("vm not found: {s}", .{name}),
            else => return e,
        };
        std.debug.print("stopped vm: {s}\n", .{name});
        return;
    }

    // ===== INSPECT COMMAND =====
    // Displays information about a VM without modifying anything.
    // Shows: name, directory path, current status, and config file name.
    if (std.mem.eql(u8, cmd, "inspect")) {
        // Get the VM's directory path
        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);

        // Verify the VM exists by opening its directory
        var cwd = std.fs.cwd();
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();

        // Read the current status from .status file (defaults to stopped if missing)
        const st = core.state.getStatus(vm_dir) catch .stopped;

        // Print VM details in a human-readable format
        std.debug.print("name: {s}\n", .{name});
        std.debug.print("dir: {s}\n", .{dir_path});
        std.debug.print("status: {s}\n", .{switch (st) {
            .running => "running",
            .stopped => "stopped",
        }});
        std.debug.print("config: m80.conf\n", .{});
        return;
    }

    // ===== SNAPSHOT COMMAND =====
    // Saves running VM filesystem state (configured block images) to a directory.
    // Usage: m80 snapshot <name> <path>
    if (std.mem.eql(u8, cmd, "snapshot")) {
        if (args.len < 4) {
            errors.die("usage: m80 snapshot <name> <path>", .{});
        }
        const snap_path = args[3];

        // Verify VM exists
        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);
        var cwd = std.fs.cwd();
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();

        if (readVmPid(vm_dir)) |pid| {
            if (!isPidAlive(pid)) {
                clearVmPid(vm_dir);
                state.setStatus(allocator, name, .stopped) catch {};
                errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
            }
            state.setStatus(allocator, name, .running) catch {};
        } else {
            errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
        }

        vm_dir.deleteFile(snapshot_result_file) catch {};
        vm_dir.deleteFile(snapshot_request_file) catch {};

        writePathRequest(vm_dir, snapshot_request_file, snap_path) catch |e| {
            errors.die("snapshot request failed: {s}", .{@errorName(e)});
        };
        switch (waitForVmActionResult(allocator, vm_dir, snapshot_result_file) catch |e| {
            errors.die("snapshot result read failed: {s}", .{@errorName(e)});
        }) {
            .ok => {
                std.debug.print("snapshot saved: {s}\n", .{snap_path});
                return;
            },
            .failed => |msg| errors.die("snapshot failed: {s}", .{msg}),
            .timeout => errors.die("snapshot timed out: {s}", .{snap_path}),
        }
    }

    // ===== RESTORE COMMAND =====
    // Restores VM filesystem state from a snapshot directory.
    // Usage: m80 restore <name> <path>
    if (std.mem.eql(u8, cmd, "restore")) {
        if (args.len < 4) {
            errors.die("usage: m80 restore <name> <path>", .{});
        }
        const snap_path = args[3];

        // Verify VM exists
        const dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(dir_path);
        var cwd = std.fs.cwd();
        var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer vm_dir.close();
        const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| {
            errors.die("invalid config: {s}", .{@errorName(e)});
        };
        var cfg_mut = cfg;
        defer core.config.freeConfig(allocator, &cfg_mut);
        try core.config.resolveRelativePaths(allocator, dir_path, &cfg_mut);

        vm_dir.deleteFile(stop_request_file) catch {};

        if (readVmPid(vm_dir)) |pid| {
            if (isPidAlive(pid)) {
                vm_dir.deleteFile(restore_result_file) catch {};
                vm_dir.deleteFile(restore_request_file) catch {};
                writePathRequest(vm_dir, restore_request_file, snap_path) catch |e| {
                    errors.die("restore request failed: {s}", .{@errorName(e)});
                };

                std.debug.print("filesystem restore started: {s}\n", .{name});
                switch (waitForVmActionResult(allocator, vm_dir, restore_result_file) catch |e| {
                    errors.die("restore result read failed: {s}", .{@errorName(e)});
                }) {
                    .ok => {
                        std.debug.print("filesystem restore complete: {s}\n", .{name});
                        return;
                    },
                    .failed => |msg| errors.die("filesystem restore failed: {s}", .{msg}),
                    .timeout => errors.die("filesystem restore timed out: {s}", .{name}),
                }
            }
            clearVmPid(vm_dir);
            state.setStatus(allocator, name, .stopped) catch {};
        }

        var jailer = try Jailer.init(allocator);
        defer jailer.deinit();

        var vm = try Vm.init(allocator, &jailer);
        defer vm.deinit();
        vm.restoreFilesystem(cfg_mut, snap_path) catch |e| {
            errors.die("filesystem restore failed: {s}", .{@errorName(e)});
        };
        std.debug.print("filesystem restore complete: {s}\n", .{name});
        return;
    }

    // ===== CLONE COMMAND =====
    // Creates a copy of a VM with a new name.
    // Usage: m80 clone <name> <new-name>
    if (std.mem.eql(u8, cmd, "clone")) {
        if (args.len < 4) {
            errors.die("usage: m80 clone <name> <new-name>", .{});
        }
        const new_name = args[3];

        // Validate new name
        if (!core.paths.validateVmName(new_name)) {
            errors.die("invalid vm name: {s}", .{new_name});
        }

        // Verify source VM exists
        const src_dir_path = try core.paths.vmDir(allocator, name);
        defer allocator.free(src_dir_path);
        var cwd = std.fs.cwd();
        var src_dir = cwd.openDir(src_dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
        defer src_dir.close();

        // Create destination VM
        state.initVm(allocator, new_name) catch |e| switch (e) {
            error.InvalidArgs => errors.die("invalid vm name: {s}", .{new_name}),
            error.AlreadyExists => errors.die("vm already exists: {s}", .{new_name}),
            else => return e,
        };

        // Copy config file
        const dst_dir_path = try core.paths.vmDir(allocator, new_name);
        defer allocator.free(dst_dir_path);
        var dst_dir = cwd.openDir(dst_dir_path, .{}) catch errors.die("failed to open new vm dir: {s}", .{new_name});
        defer dst_dir.close();

        // Read source config
        const cfg = core.config.readConfigFile(allocator, src_dir, name) catch |e| {
            errors.die("failed to read source config: {s}", .{@errorName(e)});
        };
        var cfg_mut = cfg;
        defer core.config.freeConfig(allocator, &cfg_mut);

        // Write to destination
        core.config.writeConfigFile(dst_dir, cfg_mut) catch |e| {
            errors.die("failed to write config: {s}", .{@errorName(e)});
        };

        std.debug.print("cloned vm: {s} -> {s}\n", .{ name, new_name });
        return;
    }

    // Unknown command - print error and exit
    errors.die("unknown command: {s}", .{cmd});
}

// =============================================================================
// TESTS
// =============================================================================
// Tests use the "main:" prefix to identify which module they belong to.
// Run all tests with: zig build test

// Verifies that fileSizeIfExists() returns null when given a path to a
// non-existent file. This is the expected behavior - no error, just null.
test "main: fileSizeIfExists returns null for missing file" {
    // Create a temporary directory for the test
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Build an absolute path to a file that doesn't exist
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const missing = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ base, "missing" });
    defer std.testing.allocator.free(missing);

    // Should return null, not error
    try std.testing.expect(fileSizeIfExists(missing) == null);
}

// Verifies that fileSizeIfExists() correctly returns the file size
// when given a path to an existing file.
test "main: fileSizeIfExists returns size for existing file" {
    // Create a temporary directory for the test
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file with 3 bytes of content ("abc")
    {
        var f = try tmp.dir.createFile("blob", .{});
        defer f.close();
        try f.writeAll("abc");
    }

    // Get the absolute path to the file
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, "blob");
    defer std.testing.allocator.free(abs);

    // Should return the file size (3 bytes)
    const size = fileSizeIfExists(abs) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u64, 3), size);
}

test "main: stop request helpers round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect(!(try hasStopRequest(tmp.dir)));
    try writeStopRequest(tmp.dir);
    try std.testing.expect(try hasStopRequest(tmp.dir));
    tmp.dir.deleteFile(stop_request_file) catch {};
    try std.testing.expect(!(try hasStopRequest(tmp.dir)));
}

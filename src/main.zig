//! m80 CLI Entry Point
//!
//! This is the main entry point for the m80 microVM manager. It provides a command-line
//! interface for managing lightweight virtual machines across Windows, macOS, and Linux.
//!
//! ## Supported Commands
//! - `init <name>`: Create a new VM with the given name (creates directory and default config)
//! - `start <name>`: Start an existing VM (loads config, sets up jailer, launches hypervisor)
//! - `start-deb`: Start the Debian NoCloud dev VM (auto-configures "deb" if missing)
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

const Vm = @import("vm/vm.zig").Vm;
const Jailer = @import("jailer/jailer.zig").Jailer;

/// Writes the help text to the provided writer.
/// This is separated from printHelp() so tests can capture the output.
///
/// Parameters:
///   - writer: Any type that implements the Writer interface (e.g., stderr, a buffer)
pub fn writeHelp(writer: anytype) !void {
    // Minimal CLI surface for now; config format is intentionally simple.
    try writer.print(
        \\m80 - windows-native microvm/sandbox manager (scaffold)
        \\
        \\usage:
        \\  m80 init <name>
        \\  m80 start <name>
        \\  m80 start-deb
        \\  m80 stop <name>
        \\  m80 delete <name>
        \\  m80 ps
        \\  m80 inspect <name>
        \\  m80 help
        \\  
    , .{});
}

/// Convenience wrapper that prints help text to stderr.
/// Silently ignores any write errors (stderr might be closed/redirected).
fn printHelp() void {
    var buf: [1024]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    writeHelp(&w.interface) catch {};
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
    const kernel_path = try std.fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "debian-trixie-arm64-linux" });
    defer allocator.free(kernel_path);
    const initrd_path = try std.fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "debian-trixie-arm64-initrd.gz" });
    defer allocator.free(initrd_path);
    const disk_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "debian-12-nocloud-arm64-20250316-2053.raw" },
    );
    defer allocator.free(disk_path);
    const seed_path = try std.fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "debian-nocloud-seed.iso" });
    defer allocator.free(seed_path);

    if (cfg_mut.kernel_path == null) {
        cfg_mut.kernel_path = try allocator.dupe(u8, kernel_path);
    }
    if (cfg_mut.initrd_path == null) {
        cfg_mut.initrd_path = try allocator.dupe(u8, initrd_path);
    }
    if (cfg_mut.disk_path == null) {
        cfg_mut.disk_path = try allocator.dupe(u8, disk_path);
    }
    if (cfg_mut.seed_path == null) {
        cfg_mut.seed_path = try allocator.dupe(u8, seed_path);
    }
    if (cfg_mut.kernel_cmdline == null) {
        cfg_mut.kernel_cmdline = try allocator.dupe(
            u8,
            "earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw loglevel=3 systemd.show_status=no systemd.log_level=warning fsck.mode=skip fsck.repair=no",
        );
    }

    try core.config.writeConfigFile(vm_dir, cfg_mut);
}

fn startVmCommand(allocator: std.mem.Allocator, name: []const u8, ensure_deb: bool) !void {
    if (ensure_deb) {
        try ensureDebVmConfig(allocator);
    }
    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    try jailer.prepare();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

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

    logStartPreflight(&cfg_mut);

    core.config.validateStartConfig(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };
    core.config.validateStartFiles(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };

    vm.start(cfg_mut) catch |e| {
        errors.die("start failed: {s}", .{@errorName(e)});
    };

    state.setStatus(allocator, name, .running) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}\n", .{name}),
        error.NotFound => errors.die("vm not found: {s}\n", .{name}),
        else => return e,
    };
    installSignalHandlers() catch |e| {
        errors.die("start failed: {s}", .{@errorName(e)});
    };
    std.debug.print("vm running (Ctrl+C to stop)\n", .{});
    waitForStopSignal();

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

    if (std.mem.eql(u8, cmd, "start-deb")) {
        try startVmCommand(allocator, "deb", true);
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
    // Starts a VM with the following steps:
    // 1. Initialize the Jailer (security sandbox) and drop privileges
    // 2. Initialize the VM with platform-specific hypervisor backend
    // 3. Load and validate the configuration from m80.conf
    // 4. Resolve relative paths (kernel, initrd) to absolute paths
    // 5. Launch the VM via the hypervisor
    // 6. Update status file to "running"
    if (std.mem.eql(u8, cmd, "start")) {
        try startVmCommand(allocator, name, false);
        return;
    }

    // ===== STOP COMMAND =====
    // Stops a running VM by signaling the hypervisor to terminate.
    // Updates the status file to "stopped" after successful shutdown.
    if (std.mem.eql(u8, cmd, "stop")) {
        // Initialize Jailer and VM (needed to access hypervisor APIs)
        var jailer = try Jailer.init(allocator);
        defer jailer.deinit();

        var vm = try Vm.init(allocator, &jailer);
        defer vm.deinit();

        // Send stop signal to the hypervisor
        vm.stop() catch |e| {
            errors.die("stop failed: {s}", .{@errorName(e)});
        };

        // Update status file to reflect stopped state
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

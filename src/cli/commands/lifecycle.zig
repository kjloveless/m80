const std = @import("std");
const sync = @import("../../util/sync.zig");
const fs = @import("../../util/fs.zig");
const builtin = @import("builtin");
const core = @import("../../core.zig");
const errors = core.errors;
const state = core.state;
const log = @import("../../util/log.zig");
const util_env = @import("../../util/env.zig");
const mounts = @import("../../fs/mounts.zig");
const runtime = @import("../runtime.zig");
const daemon_cmd = @import("daemon.zig");
const daemon_client = @import("../../daemon/client.zig");

const Vm = @import("../../vm/vm.zig").Vm;
const Jailer = @import("../../jailer/jailer.zig").Jailer;

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

var stop_requested = std.atomic.Value(bool).init(false);

fn setEnvFlag(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (builtin.os.tag == .windows) return;
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);
    _ = setenv(name_z, value_z, 1);
}

fn fileSizeIfExists(path_opt: ?[]const u8) ?u64 {
    if (path_opt == null) return null;
    const path = path_opt.?;
    const file = if (fs.path.isAbsolute(path))
        fs.openFileAbsolute(path, .{})
    else
        fs.cwd().openFile(path, .{});

    if (file) |f| {
        defer f.close();
        const stat = f.stat() catch return null;
        return stat.size;
    } else |_| {
        return null;
    }
}

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

fn logStartPreflight(cfg: *const core.config.VmConfig) void {
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

fn collectGuestMountPaths(allocator: std.mem.Allocator, cfg: *const core.config.VmConfig) ![][]const u8 {
    const result = try allocator.alloc([]const u8, cfg.mounts.len);
    for (result) |*entry| entry.* = "";
    errdefer {
        for (result) |path| {
            if (path.len != 0) allocator.free(path);
        }
        allocator.free(result);
    }

    for (cfg.mounts, 0..) |mount_cfg, i| {
        result[i] = try allocator.dupe(u8, mount_cfg.guest_path);
    }
    return result;
}

fn freeGuestMountPaths(allocator: std.mem.Allocator, mounts_list: [][]const u8) void {
    for (mounts_list) |path| allocator.free(path);
    if (mounts_list.len > 0) allocator.free(mounts_list);
}

fn unregisterVmBestEffort(allocator: std.mem.Allocator, vm_dir: fs.Dir, name: []const u8) void {
    daemon_client.unregisterVm(allocator, name) catch |e| {
        log.warn("daemon unregister failed: {s}", .{@errorName(e)});
    };
    runtime.clearGuestCid(vm_dir);
}

fn requestGuestShutdownBestEffort(allocator: std.mem.Allocator, name: []const u8) bool {
    daemon_client.requestVmShutdown(allocator, name) catch |e| {
        log.warn("daemon guest shutdown request failed: {s}", .{@errorName(e)});
        return false;
    };
    return true;
}

fn defaultServiceInitrdPath(allocator: std.mem.Allocator) ![]u8 {
    const override = util_env.getVarOwned(allocator, "M80_SERVICE_INITRD") catch null;
    if (override) |path| {
        return path;
    }

    const cwd_path = try fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    return try fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "m80-initramfs.cpio.gz" });
}

fn copyFileInto(target: *fs.File, source_path: []const u8) !void {
    var source = if (fs.path.isAbsolute(source_path))
        try fs.openFileAbsolute(source_path, .{})
    else
        try fs.cwd().openFile(source_path, .{});
    defer source.close();

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try source.read(&buf);
        if (n == 0) break;
        try target.writeAll(buf[0..n]);
    }
}

fn ensureServiceInitrd(
    allocator: std.mem.Allocator,
    vm_dir: fs.Dir,
    vm_dir_path: []const u8,
    cfg: *core.config.VmConfig,
) !void {
    if (cfg.network_services.len == 0 and cfg.network_mode == .locked_down) return;

    const service_initrd = try defaultServiceInitrdPath(allocator);
    defer allocator.free(service_initrd);

    if (cfg.initrd_path) |current_initrd| {
        if (std.mem.eql(u8, current_initrd, service_initrd)) return;

        const bundle_name = "services-initrd.cpio.gz";
        var bundle_file = try vm_dir.createFile(bundle_name, .{ .truncate = true });
        defer bundle_file.close();

        try copyFileInto(&bundle_file, service_initrd);
        try copyFileInto(&bundle_file, current_initrd);

        const bundle_path = try fs.path.join(allocator, &[_][]const u8{ vm_dir_path, bundle_name });
        if (cfg.initrd_path) |old_path| allocator.free(old_path);
        cfg.initrd_path = bundle_path;
        return;
    }

    cfg.initrd_path = try allocator.dupe(u8, service_initrd);
}

fn hasNetworkService(services: []const core.config.Service, service: core.config.Service) bool {
    for (services) |candidate| {
        if (candidate == service) return true;
    }
    return false;
}

fn ensureDebNetworkServices(allocator: std.mem.Allocator, cfg: *core.config.VmConfig) !void {
    const wants = [_]core.config.Service{ .dns, .metadata };
    var missing: usize = 0;
    for (wants) |service| {
        if (!hasNetworkService(cfg.network_services, service)) missing += 1;
    }
    if (missing == 0) return;

    const old_services = cfg.network_services;
    const services = try allocator.alloc(core.config.Service, old_services.len + missing);
    @memcpy(services[0..old_services.len], old_services);

    var i = old_services.len;
    for (wants) |service| {
        if (!hasNetworkService(old_services, service)) {
            services[i] = service;
            i += 1;
        }
    }

    if (old_services.len > 0) allocator.free(old_services);
    cfg.network_services = services;
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
        error.MetadataFileNotFound => errors.die(
            "network_metadata_file not found: {s}. Check the path or remove network_metadata_file.",
            .{optPath(cfg.network_metadata_file)},
        ),
        error.MetadataFileUnreadable => errors.die(
            "network_metadata_file not readable: {s}. Check permissions (chmod +r) or ownership.",
            .{optPath(cfg.network_metadata_file)},
        ),
        error.OpenNetworkNotAllowed => errors.die(
            "network_mode=open requires M80_ALLOW_OPEN_NETWORK=1. Use network_mode=allowlist unless full egress is intentional.",
            .{},
        ),
        error.InvalidNetworkAllowedDomainSpec => errors.die(
            "network_allowed_domains contains an invalid entry. Use domains like example.com, *.example.com, or example.com:443.",
            .{},
        ),
        error.InvalidNetworkAllowedIpSpec => errors.die(
            "network_allowed_ips contains an invalid entry. Use IPv4 literals or CIDR ranges like 192.0.2.10 or 192.0.2.0/24.",
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

fn dieConfigReadError(err: anyerror) noreturn {
    switch (err) {
        error.RemovedNetworkKey => errors.die(
            "legacy networking keys are no longer supported. Use `network_mode=locked_down|allowlist|open`, `network_services=dns,metadata`, `network_metadata_file=...`, `network_allowed_domains=...`, and `network_allowed_ips=...`.",
            .{},
        ),
        else => errors.die("invalid config: {s}", .{@errorName(err)}),
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

    var cwd = fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| dieConfigReadError(e);
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);

    const cwd_path = try cwd.realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    const kernel_path = try fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "debian-kernels", "boot", "vmlinuz-6.1.0-42-cloud-arm64" },
    );
    defer allocator.free(kernel_path);
    const initrd_path = try fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "m80-initramfs.cpio.gz" },
    );
    defer allocator.free(initrd_path);
    const disk_path = try fs.path.join(
        allocator,
        &[_][]const u8{ cwd_path, "images", "debian-12-nocloud-arm64-20250703-2162.raw" },
    );
    defer allocator.free(disk_path);
    const seed_path = try fs.path.join(allocator, &[_][]const u8{ cwd_path, "images", "debian-nocloud-seed.iso" });
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
        "console=ttyAMA0 root=/dev/vda1 rootwait rootfstype=ext4 rw devtmpfs.mount=1 systemd.mask=boot-efi.mount systemd.mask=systemd-boot-update.service quiet loglevel=3 systemd.show_status=false systemd.log_level=warning systemd.log_color=no fsck.mode=skip fsck.repair=no",
    );
    try ensureDebNetworkServices(allocator, &cfg_mut);

    if (cfg_mut.mounts.len == 0) {
        if (cfg_mut.mount_roots.len > 0) {
            for (cfg_mut.mount_roots) |root| allocator.free(root);
            allocator.free(cfg_mut.mount_roots);
            cfg_mut.mount_roots = &[_][]const u8{};
        }

        const mount_root = fs.path.dirname(cwd_path) orelse cwd_path;
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

fn handleSignal(sig: std.posix.SIG) callconv(.c) void {
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
            sync.sleep(250 * std.time.ns_per_ms);
        }
    }
    while (!stop_requested.load(.seq_cst)) {
        sync.sleep(200 * std.time.ns_per_ms);
    }
}

fn waitForStopOrSnapshot(
    allocator: std.mem.Allocator,
    vm: *Vm,
    vm_dir: fs.Dir,
    cfg: *const core.config.VmConfig,
) !void {
    if (builtin.os.tag == .windows) {
        waitForStopSignal();
        return;
    }

    while (!stop_requested.load(.seq_cst)) {
        if (!vm.isRunning()) {
            log.info("vm exited", .{});
            break;
        }
        if (try runtime.hasStopRequest(vm_dir)) {
            log.info("stop request received", .{});
            stop_requested.store(true, .seq_cst);
            vm_dir.deleteFile(runtime.stop_request_file) catch {};
            break;
        }
        if (try runtime.readPathRequest(allocator, vm_dir, runtime.snapshot_request_file)) |path| {
            defer allocator.free(path);
            log.info("snapshot request path={s}", .{path});
            vm.snapshotFilesystem(cfg.*, path) catch |e| {
                log.warn("snapshot failed: {s}", .{@errorName(e)});
                runtime.writeResultFile(vm_dir, runtime.snapshot_result_file, @errorName(e));
                vm_dir.deleteFile(runtime.snapshot_request_file) catch {};
                sync.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            runtime.writeResultFile(vm_dir, runtime.snapshot_result_file, "ok");
            vm_dir.deleteFile(runtime.snapshot_request_file) catch {};
        }
        if (try runtime.readPathRequest(allocator, vm_dir, runtime.restore_request_file)) |path| {
            defer allocator.free(path);
            log.info("restore request path={s}", .{path});
            vm.restoreFilesystem(cfg.*, path) catch |e| {
                log.warn("restore failed: {s}", .{@errorName(e)});
                runtime.writeResultFile(vm_dir, runtime.restore_result_file, @errorName(e));
                vm_dir.deleteFile(runtime.restore_request_file) catch {};
                sync.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            runtime.writeResultFile(vm_dir, runtime.restore_result_file, "ok");
            vm_dir.deleteFile(runtime.restore_request_file) catch {};
        }
        sync.sleep(200 * std.time.ns_per_ms);
    }
}

fn startVmCommand(allocator: std.mem.Allocator, name: []const u8, ensure_deb: bool, attach: bool) !void {
    if (ensure_deb) {
        try ensureDebVmConfig(allocator);
    }

    try daemon_cmd.ensureStarted(allocator);

    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const st = core.state.getStatus(vm_dir) catch .stopped;
    if (st == .running) {
        errors.die(
            "vm already running: {s}\nuse `m80 stop {s}` to stop it",
            .{ name, name },
        );
    }

    const cfg = core.config.readConfigFile(allocator, vm_dir, name) catch |e| dieConfigReadError(e);
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);

    if ((cfg_mut.network_services.len > 0 or cfg_mut.network_mode != .locked_down) and builtin.os.tag != .macos) {
        errors.die("network_* guest networking is currently supported only on the HVF backend (NotSupported).", .{});
    }

    try core.config.resolveRelativePaths(allocator, dir_path, &cfg_mut);
    ensureServiceInitrd(allocator, vm_dir, dir_path, &cfg_mut) catch |e| {
        errors.die("service initramfs prepare failed: {s}", .{@errorName(e)});
    };

    logStartPreflight(&cfg_mut);

    core.config.validateStartConfig(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };
    core.config.validateStartFiles(&cfg_mut) catch |e| {
        dieStartConfigError(e, &cfg_mut);
    };

    const guest_mounts = try collectGuestMountPaths(allocator, &cfg_mut);
    defer freeGuestMountPaths(allocator, guest_mounts);

    var registration = daemon_client.registerVm(allocator, .{
        .name = cfg_mut.name,
        .memory_mb = cfg_mut.memory_mb,
        .cpu_cores = cfg_mut.cpu_cores,
        .network_mode = cfg_mut.network_mode,
        .network_services = cfg_mut.network_services,
        .network_metadata_file = cfg_mut.network_metadata_file,
        .network_allowed_domains = cfg_mut.network_allowed_domains,
        .network_allowed_ips = cfg_mut.network_allowed_ips,
        .mounts = guest_mounts,
        .started_at = sync.timestamp(),
    }) catch |e| {
        errors.die("daemon registration failed: {s}", .{@errorName(e)});
    };
    defer registration.deinit(allocator);
    errdefer unregisterVmBestEffort(allocator, vm_dir, cfg_mut.name);

    const guest_cid = registration.guest_cid;
    runtime.writeGuestCid(vm_dir, guest_cid) catch |e| {
        unregisterVmBestEffort(allocator, vm_dir, cfg_mut.name);
        errors.die("failed to persist guest cid: {s}", .{@errorName(e)});
    };
    cfg_mut.assigned_guest_cid = guest_cid;
    cfg_mut.assigned_guest_session_socket_path = try allocator.dupe(u8, registration.guest_socket_path);

    jailer.prepareForVm(dir_path, &cfg_mut) catch |e| {
        unregisterVmBestEffort(allocator, vm_dir, cfg_mut.name);
        errors.die("jailer prepare failed: {s}", .{@errorName(e)});
    };

    vm.start(cfg_mut) catch |e| {
        unregisterVmBestEffort(allocator, vm_dir, cfg_mut.name);
        switch (e) {
            error.MountsInvalid => errors.die(
                "mounts rejected. Ensure mount_roots includes the host path and no path traversal is present.",
                .{},
            ),
            error.MountsUnsupported => errors.die(
                "mounts not supported in this configuration. Use a single virtiofs mount.",
                .{},
            ),
            else => errors.die("start failed: {s}", .{@errorName(e)}),
        }
    };

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
    unregisterVmBestEffort(allocator, vm_dir, cfg_mut.name);
    state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}\n", .{name}),
        error.NotFound => errors.die("vm not found: {s}\n", .{name}),
        else => return e,
    };
    std.debug.print("stopped vm: {s}\n", .{name});
}

pub fn runStart(allocator: std.mem.Allocator, name: []const u8) !void {
    const ensure = std.mem.eql(u8, name, "deb");
    if (ensure) {
        try ensureDebVmConfig(allocator);
    }

    try daemon_cmd.ensureStarted(allocator);

    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    if (runtime.readVmPid(vm_dir)) |pid| {
        vm_dir.deleteFile(runtime.stop_request_file) catch {};
        if (runtime.isPidAlive(pid)) {
            errors.die("vm already running: {s}", .{name});
        }
        runtime.clearVmPid(vm_dir);
        state.setStatus(allocator, name, .stopped) catch {};
    }

    const socket_path = try runtime.vmConsoleSocketPath(allocator, name);
    defer allocator.free(socket_path);
    fs.cwd().deleteFile(socket_path) catch {};
    vm_dir.deleteFile(runtime.stop_request_file) catch {};

    const exe_path = try fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    var argv = [_][]const u8{ exe_path, "run", name };
    var env_map = try util_env.getMap(allocator);
    defer env_map.deinit();
    try env_map.put("M80_CONSOLE_SOCKET", socket_path);
    const log_path = try fs.path.join(allocator, &[_][]const u8{ dir_path, "run.log" });
    defer allocator.free(log_path);
    try env_map.put("M80_LOG_FILE", log_path);
    var threaded_io = std.Io.Threaded.init(allocator, .{});
    defer threaded_io.deinit();
    const child = try std.process.spawn(threaded_io.io(), .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .pgid = if (builtin.os.tag != .windows) 0 else null,
        .environ_map = &env_map,
    });
    if (builtin.os.tag != .windows) {
        try runtime.writeVmPid(vm_dir, @intCast(child.id.?));
    }

    var started = false;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const st = core.state.getStatus(vm_dir) catch .stopped;
        if (st == .running) {
            started = true;
            break;
        }
        sync.sleep(100 * std.time.ns_per_ms);
    }
    if (started) {
        std.debug.print("vm started: {s}\n", .{name});
    } else {
        std.debug.print("vm starting: {s}\n", .{name});
    }
}

pub fn runRun(allocator: std.mem.Allocator, name: []const u8) !void {
    const ensure = std.mem.eql(u8, name, "deb");
    const existing_socket = util_env.getVarOwned(allocator, "M80_CONSOLE_SOCKET") catch null;
    defer if (existing_socket) |value| allocator.free(value);
    if (existing_socket == null) {
        const socket_path = try runtime.vmConsoleSocketPath(allocator, name);
        defer allocator.free(socket_path);
        setEnvFlag(allocator, "M80_CONSOLE_SOCKET", socket_path) catch {};
    }
    try startVmCommand(allocator, name, ensure, true);
}

pub fn runStop(allocator: std.mem.Allocator, name: []const u8) !void {
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    if (runtime.readVmPid(vm_dir)) |pid| {
        vm_dir.deleteFile(runtime.stop_request_file) catch {};
        if (builtin.os.tag != .windows) {
            var exited = false;
            if (requestGuestShutdownBestEffort(allocator, name)) {
                exited = runtime.waitForPidExit(pid, 100, 200);
            }
            if (!exited) {
                runtime.writeStopRequest(vm_dir) catch |e| {
                    log.warn("stop request write failed: {s}", .{@errorName(e)});
                };
                exited = runtime.waitForPidExit(pid, 100, 50);
            }
            if (!exited) {
                std.posix.kill(pid, std.posix.SIG.TERM) catch |e| switch (e) {
                    error.ProcessNotFound => {},
                    else => errors.die("stop failed: {s}", .{@errorName(e)}),
                };
                exited = runtime.waitForPidExit(pid, 100, 50);
            }
            if (!exited) {
                std.posix.kill(pid, std.posix.SIG.KILL) catch {};
                _ = runtime.waitForPidExit(pid, 100, 10);
            }
        }
        runtime.clearVmPid(vm_dir);
        vm_dir.deleteFile(runtime.stop_request_file) catch {};
    } else {
        var jailer = try Jailer.init(allocator);
        defer jailer.deinit();

        var vm = try Vm.init(allocator, &jailer);
        defer vm.deinit();

        vm.stop() catch |e| {
            errors.die("stop failed: {s}", .{@errorName(e)});
        };
    }

    daemon_client.unregisterVm(allocator, name) catch |e| {
        log.warn("daemon unregister failed: {s}", .{@errorName(e)});
    };
    runtime.clearGuestCid(vm_dir);

    state.setStatus(allocator, name, .stopped) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
        error.NotFound => errors.die("vm not found: {s}", .{name}),
        else => return e,
    };
    std.debug.print("stopped vm: {s}\n", .{name});
}

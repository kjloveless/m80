const std = @import("std");
const core = @import("../../core.zig");
const state = core.state;
const errors = core.errors;
const Jailer = @import("../../jailer/jailer.zig").Jailer;
const Vm = @import("../../vm/vm.zig").Vm;
const runtime = @import("../runtime.zig");

pub fn runSnapshot(allocator: std.mem.Allocator, name: []const u8, snap_path: []const u8) !void {
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    if (runtime.readVmPid(vm_dir)) |pid| {
        if (!runtime.isPidAlive(pid)) {
            runtime.clearVmPid(vm_dir);
            state.setStatus(allocator, name, .stopped) catch {};
            errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
        }
        state.setStatus(allocator, name, .running) catch {};
    } else {
        errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
    }

    vm_dir.deleteFile(runtime.snapshot_result_file) catch {};
    vm_dir.deleteFile(runtime.snapshot_request_file) catch {};

    runtime.writePathRequest(vm_dir, runtime.snapshot_request_file, snap_path) catch |e| {
        errors.die("snapshot request failed: {s}", .{@errorName(e)});
    };

    switch (runtime.waitForVmActionResult(allocator, vm_dir, runtime.snapshot_result_file) catch |e| {
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

pub fn runRestore(allocator: std.mem.Allocator, name: []const u8, snap_path: []const u8) !void {
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

    vm_dir.deleteFile(runtime.stop_request_file) catch {};

    if (runtime.readVmPid(vm_dir)) |pid| {
        if (runtime.isPidAlive(pid)) {
            vm_dir.deleteFile(runtime.restore_result_file) catch {};
            vm_dir.deleteFile(runtime.restore_request_file) catch {};
            runtime.writePathRequest(vm_dir, runtime.restore_request_file, snap_path) catch |e| {
                errors.die("restore request failed: {s}", .{@errorName(e)});
            };

            std.debug.print("filesystem restore started: {s}\n", .{name});
            switch (runtime.waitForVmActionResult(allocator, vm_dir, runtime.restore_result_file) catch |e| {
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
        runtime.clearVmPid(vm_dir);
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
}

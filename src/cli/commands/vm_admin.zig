const std = @import("std");
const core = @import("../../core.zig");
const state = core.state;
const errors = core.errors;

pub fn runPs(allocator: std.mem.Allocator) !void {
    const vms = try state.listVms(allocator);
    defer {
        for (vms) |r| allocator.free(r.name);
        allocator.free(vms);
    }

    if (vms.len == 0) {
        std.debug.print("(no vms)\n", .{});
        return;
    }

    for (vms) |r| {
        std.debug.print("{s}\t{s}\n", .{
            r.name,
            switch (r.status) {
                .running => "running",
                .stopped => "stopped",
            },
        });
    }
}

pub fn runInit(allocator: std.mem.Allocator, name: []const u8) !void {
    state.initVm(allocator, name) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
        error.AlreadyExists => errors.die("vm already exists: {s}", .{name}),
        else => return e,
    };
    std.debug.print("initialized vm: {s}\n", .{name});
}

pub fn runDelete(allocator: std.mem.Allocator, name: []const u8) !void {
    state.deleteVm(allocator, name) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}", .{name}),
        error.NotFound => errors.die("vm not found: {s}", .{name}),
        else => return e,
    };
    std.debug.print("deleted vm: {s}\n", .{name});
}

pub fn runInspect(allocator: std.mem.Allocator, name: []const u8) !void {
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var cwd = std.fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    const st = core.state.getStatus(vm_dir) catch .stopped;

    std.debug.print("name: {s}\n", .{name});
    std.debug.print("dir: {s}\n", .{dir_path});
    std.debug.print("status: {s}\n", .{switch (st) {
        .running => "running",
        .stopped => "stopped",
    }});
    std.debug.print("config: m80.conf\n", .{});
}

pub fn runClone(allocator: std.mem.Allocator, name: []const u8, new_name: []const u8) !void {
    const src_dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(src_dir_path);
    var cwd = std.fs.cwd();
    var src_dir = cwd.openDir(src_dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer src_dir.close();

    state.initVm(allocator, new_name) catch |e| switch (e) {
        error.InvalidArgs => errors.die("invalid vm name: {s}", .{new_name}),
        error.AlreadyExists => errors.die("vm already exists: {s}", .{new_name}),
        else => return e,
    };

    const dst_dir_path = try core.paths.vmDir(allocator, new_name);
    defer allocator.free(dst_dir_path);
    var dst_dir = cwd.openDir(dst_dir_path, .{}) catch errors.die("failed to open new vm dir: {s}", .{new_name});
    defer dst_dir.close();

    const cfg = core.config.readConfigFile(allocator, src_dir, name) catch |e| {
        errors.die("failed to read source config: {s}", .{@errorName(e)});
    };
    var cfg_mut = cfg;
    defer core.config.freeConfig(allocator, &cfg_mut);

    core.config.writeConfigFile(dst_dir, cfg_mut) catch |e| {
        errors.die("failed to write config: {s}", .{@errorName(e)});
    };

    std.debug.print("cloned vm: {s} -> {s}\n", .{ name, new_name });
}

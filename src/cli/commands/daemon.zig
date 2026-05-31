const std = @import("std");
const sync = @import("../../util/sync.zig");
const fs = @import("../../util/fs.zig");
const builtin = @import("builtin");
const core = @import("../../core.zig");
const errors = core.errors;
const dispatch = @import("../dispatch.zig");
const runtime = @import("../runtime.zig");
const util_env = @import("../../util/env.zig");
const protocol = @import("../../daemon/protocol.zig");
const server = @import("../../daemon/server.zig");

const poll_attempts: usize = 50;
const poll_sleep_ms: u64 = 100;

fn readDaemonPid(allocator: std.mem.Allocator) ?i32 {
    const pid_path = core.paths.daemonPidPath(allocator) catch return null;
    defer allocator.free(pid_path);

    var file = if (fs.path.isAbsolute(pid_path))
        fs.openFileAbsolute(pid_path, .{}) catch return null
    else
        fs.cwd().openFile(pid_path, .{}) catch return null;
    defer file.close();

    var buf: [32]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(i32, trimmed, 10) catch null;
}

fn parseRpcResponse(allocator: std.mem.Allocator, payload: []const u8) !std.json.Parsed(std.json.Value) {
    return try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
}

fn expectOkResponse(allocator: std.mem.Allocator, payload: []const u8) !void {
    var parsed = try parseRpcResponse(allocator, payload);
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidResponse,
    };
    const ok_value = root.get("ok") orelse return error.InvalidResponse;
    switch (ok_value) {
        .bool => |ok| if (ok) return,
        else => {},
    }

    if (root.get("error")) |err_value| {
        if (err_value == .string) {
            errors.die("daemon request failed: {s}", .{err_value.string});
        }
    }
    return error.InvalidResponse;
}

fn ping(allocator: std.mem.Allocator) bool {
    const control_path = core.paths.daemonControlSocketPath(allocator) catch return false;
    defer allocator.free(control_path);

    const payload = protocol.buildRequestPayload(allocator, 1, "daemon.ping", struct {}{}) catch return false;
    defer allocator.free(payload);

    const response = protocol.rpc(allocator, control_path, payload) catch return false;
    defer allocator.free(response);

    expectOkResponse(allocator, response) catch return false;
    return true;
}

fn waitForDaemonReady(allocator: std.mem.Allocator) bool {
    var attempts: usize = 0;
    while (attempts < poll_attempts) : (attempts += 1) {
        if (ping(allocator)) return true;
        sync.sleep(poll_sleep_ms * std.time.ns_per_ms);
    }
    return false;
}

fn spawnDaemonProcess(allocator: std.mem.Allocator) !void {
    const exe_path = try fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    const daemon_dir = try core.paths.daemonDir(allocator);
    defer allocator.free(daemon_dir);
    try fs.cwd().makePath(daemon_dir);
    if (builtin.os.tag != .windows) {
        fs.chmodAt(std.posix.AT.FDCWD, daemon_dir, 0o700, 0) catch {};
    }

    const log_path = try fs.path.join(allocator, &[_][]const u8{ daemon_dir, "daemon.log" });
    defer allocator.free(log_path);

    var argv = [_][]const u8{ exe_path, "daemon", "run" };
    var env_map = try util_env.getMap(allocator);
    defer env_map.deinit();
    try env_map.put("M80_LOG_FILE", log_path);

    var threaded_io = std.Io.Threaded.init(allocator, .{});
    defer threaded_io.deinit();
    _ = try std.process.spawn(threaded_io.io(), .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .pgid = if (builtin.os.tag != .windows) 0 else null,
        .environ_map = &env_map,
    });
}

pub fn ensureStarted(allocator: std.mem.Allocator) !void {
    if (ping(allocator)) return;
    try spawnDaemonProcess(allocator);
    if (!waitForDaemonReady(allocator)) {
        return error.DaemonUnavailable;
    }
}

fn runStart(allocator: std.mem.Allocator) !void {
    if (ping(allocator)) {
        std.debug.print("daemon already running\n", .{});
        return;
    }
    try ensureStarted(allocator);
    std.debug.print("daemon started\n", .{});
}

fn runStop(allocator: std.mem.Allocator) !void {
    const control_path = try core.paths.daemonControlSocketPath(allocator);
    defer allocator.free(control_path);

    const payload = try protocol.buildRequestPayload(allocator, 1, "daemon.shutdown", struct {}{});
    defer allocator.free(payload);

    const response = protocol.rpc(allocator, control_path, payload) catch |e| switch (e) {
        error.FileNotFound, error.ConnectionRefused => {
            std.debug.print("daemon stopped\n", .{});
            return;
        },
        else => return e,
    };
    defer allocator.free(response);
    try expectOkResponse(allocator, response);

    if (readDaemonPid(allocator)) |pid| {
        _ = runtime.waitForPidExit(pid, poll_sleep_ms, poll_attempts);
    }
    std.debug.print("daemon stopped\n", .{});
}

fn runStatus(allocator: std.mem.Allocator) !void {
    if (!ping(allocator)) {
        std.debug.print("daemon stopped\n", .{});
        return;
    }
    if (readDaemonPid(allocator)) |pid| {
        std.debug.print("daemon running (pid {d})\n", .{pid});
        return;
    }
    std.debug.print("daemon running\n", .{});
}

pub fn run(allocator: std.mem.Allocator, cmd: dispatch.DaemonCommand) !void {
    switch (cmd) {
        .run => try server.run(allocator),
        .start => try runStart(allocator),
        .stop => try runStop(allocator),
        .status => try runStatus(allocator),
    }
}

const std = @import("std");
const builtin = @import("builtin");
const core = @import("../core.zig");

pub const snapshot_request_file = "snapshot.request";
pub const snapshot_result_file = "snapshot.result";
pub const restore_request_file = "restore.request";
pub const restore_result_file = "restore.result";
pub const stop_request_file = "stop.request";
pub const vm_action_max_attempts: usize = 600;
pub const vm_action_poll_ms: u64 = 200;
pub const request_file_max_bytes: usize = 4096;
pub const result_file_max_bytes: usize = 1024;

pub const VmActionWaitResult = union(enum) {
    ok,
    failed: []u8,
    timeout,
};

pub fn vmConsoleSocketPath(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);
    return try std.fs.path.join(allocator, &[_][]const u8{ dir_path, "console.sock" });
}

pub fn readVmPid(vm_dir: std.fs.Dir) ?i32 {
    var file = vm_dir.openFile("pid", .{}) catch return null;
    defer file.close();
    var buf: [32]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(i32, trimmed, 10) catch null;
}

pub fn writeVmPid(vm_dir: std.fs.Dir, pid: i32) !void {
    var file = try vm_dir.createFile("pid", .{ .truncate = true });
    defer file.close();
    var buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    try file.writeAll(pid_str);
}

pub fn clearVmPid(vm_dir: std.fs.Dir) void {
    vm_dir.deleteFile("pid") catch {};
}

pub fn waitForPidExit(pid: i32, sleep_ms: u64, max_attempts: usize) bool {
    var attempts: usize = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        if (!isPidAlive(pid)) return true;
        std.Thread.sleep(sleep_ms * std.time.ns_per_ms);
    }
    return !isPidAlive(pid);
}

pub fn isPidAlive(pid: i32) bool {
    if (builtin.os.tag == .windows) return false;
    if (pid <= 0) return false;
    std.posix.kill(pid, 0) catch |e| switch (e) {
        error.ProcessNotFound => return false,
        else => return true,
    };
    return true;
}

pub fn writeStopRequest(vm_dir: std.fs.Dir) !void {
    var req = try vm_dir.createFile(stop_request_file, .{ .truncate = true });
    defer req.close();
    try req.writeAll("1\n");
}

pub fn hasStopRequest(vm_dir: std.fs.Dir) !bool {
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

pub fn readPathRequest(
    allocator: std.mem.Allocator,
    vm_dir: std.fs.Dir,
    request_file: []const u8,
) !?[]u8 {
    return readOptionalTrimmedFile(allocator, vm_dir, request_file, request_file_max_bytes);
}

pub fn writePathRequest(vm_dir: std.fs.Dir, request_file: []const u8, path: []const u8) !void {
    var req = try vm_dir.createFile(request_file, .{ .truncate = true });
    defer req.close();
    try req.writeAll(path);
}

pub fn writeResultFile(vm_dir: std.fs.Dir, result_file: []const u8, msg: []const u8) void {
    var file = vm_dir.createFile(result_file, .{ .truncate = true }) catch return;
    defer file.close();
    _ = file.writeAll(msg) catch {};
}

pub fn waitForVmActionResult(
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

test "cli runtime: stop request helpers round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect(!(try hasStopRequest(tmp.dir)));
    try writeStopRequest(tmp.dir);
    try std.testing.expect(try hasStopRequest(tmp.dir));
    tmp.dir.deleteFile(stop_request_file) catch {};
    try std.testing.expect(!(try hasStopRequest(tmp.dir)));
}

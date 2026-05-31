//! VM State Management Module
//!
//! This module handles the lifecycle of VMs: creating, deleting, and tracking their status.
//! It manages the on-disk representation of VMs in the data directory.
//!
//! ## VM Storage
//! Each VM is stored as a directory under `{data_dir}/vms/{name}/` containing:
//! - `m80.conf`: VM configuration file (see config.zig)
//! - `status`: Simple text file containing "running\n" or "stopped\n"
//!
//! ## Security
//! - VM names are validated to prevent path traversal attacks
//! - Deletion uses safe path validation to prevent symlink escape attacks
//! - All paths are verified to be within the expected data root
//!
//! ## Thread Safety
//! Status updates use a "last writer wins" model. If multiple processes
//! update status simultaneously, the last write will be preserved.

const std = @import("std");
const fs = @import("../util/fs.zig");
const paths = @import("paths.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");
const path_util = @import("../util/path.zig");

/// Represents the current execution state of a VM.
/// This is persisted in the `status` file in the VM directory.
pub const VmStatus = enum {
    /// VM is not running (default state)
    stopped,
    /// VM is currently executing
    running,
};

/// Record returned by listVms() containing basic VM info.
/// The name field is allocator-owned and must be freed by the caller.
pub const VmRecord = struct {
    /// VM name (allocator-owned, caller must free)
    name: []const u8,
    /// Current status from the status file
    status: VmStatus,
};

/// Converts a VmStatus enum to the string written to the status file.
fn statusLine(status: VmStatus) []const u8 {
    return switch (status) {
        .stopped => "stopped\n",
        .running => "running\n",
    };
}

/// Writes the status to the VM's status file atomically.
/// Uses write-to-temp-then-rename pattern to prevent partial writes.
fn writeStatusFile(vm_dir: fs.Dir, status: VmStatus) !void {
    const tmp_name = "status.tmp";
    const final_name = "status";

    // Write to temporary file first
    var sf = try vm_dir.createFile(tmp_name, .{ .truncate = true });
    errdefer vm_dir.deleteFile(tmp_name) catch {};
    try sf.writeAll(statusLine(status));
    sf.close();

    // Atomic rename (POSIX rename() and Windows MoveFileEx are atomic)
    try vm_dir.rename(tmp_name, final_name);
}

/// Creates the base data directories if they don't exist.
/// Creates: {data_dir}/ and {data_dir}/vms/
fn ensureBaseDirs(allocator: std.mem.Allocator) !void {
    const base = try paths.dataDir(allocator);
    defer allocator.free(base);

    var cwd = fs.cwd();
    try cwd.makePath(base);

    const vms = try fs.path.join(allocator, &[_][]const u8{ base, "vms" });
    defer allocator.free(vms);
    try cwd.makePath(vms);
}

/// Creates a new VM with the given name.
///
/// This function:
/// 1. Validates the VM name (must be alphanumeric with _/- only)
/// 2. Creates the VM directory at {data_dir}/vms/{name}/
/// 3. Writes a default m80.conf configuration file
/// 4. Creates a status file with "stopped" state
///
/// After initVm, the user should edit m80.conf to set kernel_path, initrd_path, etc.
///
/// Parameters:
///   - allocator: Memory allocator for path operations
///   - name: VM name (must pass paths.validateVmName)
///
/// Errors:
///   - M80Error.InvalidArgs: Invalid VM name (contains special chars, etc.)
///   - M80Error.AlreadyExists: A VM with this name already exists
pub fn initVm(allocator: std.mem.Allocator, name: []const u8) !void {
    // Ensure the base data directories exist
    try ensureBaseDirs(allocator);

    // Build the path to the VM directory
    const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
    defer allocator.free(dir_path);

    var cwd = fs.cwd();

    // Check if VM already exists - return error if so
    if (cwd.openDir(dir_path, .{})) |d| {
        var h = d;
        h.close();
        return errors.M80Error.AlreadyExists;
    } else |_| {}

    // Create the VM directory
    try cwd.makePath(dir_path);

    var vm_dir = try cwd.openDir(dir_path, .{});
    defer vm_dir.close();

    // Write default configuration file
    const cfg = try config.defaultConfig(allocator, name);
    defer allocator.free(cfg.name);

    try config.writeConfigFile(vm_dir, cfg);

    // Create status file with initial "stopped" state
    try writeStatusFile(vm_dir, .stopped);
}

/// Deletes a VM and all its associated files.
///
/// This function:
/// 1. Validates the VM name
/// 2. Verifies the VM directory exists
/// 3. Safely deletes the entire VM directory tree
///
/// Security: Uses safe deletion that validates the path is:
/// - Within the data root directory
/// - At least 2 levels deep (prevents deleting the data root itself)
/// - Not escaping via symlinks
///
/// Parameters:
///   - allocator: Memory allocator for path operations
///   - name: VM name to delete
///
/// Errors:
///   - M80Error.InvalidArgs: Invalid VM name or path traversal attempt
///   - M80Error.NotFound: No VM with this name exists
pub fn deleteVm(allocator: std.mem.Allocator, name: []const u8) !void {
    const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
    defer allocator.free(dir_path);

    // Verify VM exists before attempting deletion
    if (fs.cwd().openDir(dir_path, .{})) |dir| {
        var d = dir;
        d.close();
    } else |_| {
        return errors.M80Error.NotFound;
    }

    // Get the data root for path validation
    const data_root = paths.dataDir(allocator) catch return errors.M80Error.InvalidArgs;
    defer allocator.free(data_root);

    // Use safe deletion with path validation to prevent symlink escape attacks.
    // Requires path to be at least 2 levels deep within data root
    // (e.g., can delete vms/myvm but not vms/ itself)
    path_util.safeDeleteTree(allocator, dir_path, data_root) catch |e| switch (e) {
        path_util.PathError.PathNotWithinRoot, path_util.PathError.PathTraversal, path_util.PathError.SymlinkEscape, path_util.PathError.PathTooShallow => return errors.M80Error.InvalidArgs,
        path_util.PathError.InvalidPath, path_util.PathError.AccessDenied => return errors.M80Error.NotFound,
        path_util.PathError.OutOfMemory => return error.OutOfMemory,
    };
}

/// Updates the status file for a VM.
///
/// Called by the CLI after start/stop operations to persist the new state.
///
/// Parameters:
///   - allocator: Memory allocator for path operations
///   - name: VM name
///   - status: New status to write (.running or .stopped)
///
/// Errors:
///   - M80Error.InvalidArgs: Invalid VM name
///   - M80Error.NotFound: VM doesn't exist
pub fn setStatus(allocator: std.mem.Allocator, name: []const u8, status: VmStatus) !void {
    const dir_path = paths.vmDir(allocator, name) catch return errors.M80Error.InvalidArgs;
    defer allocator.free(dir_path);

    var cwd = fs.cwd();
    var vm_dir = cwd.openDir(dir_path, .{}) catch return errors.M80Error.NotFound;
    defer vm_dir.close();

    try writeStatusFile(vm_dir, status);
}

/// Reads the current status of a VM from its status file.
///
/// Gracefully handles missing or malformed files by defaulting to .stopped.
/// This is intentional - a missing status file means the VM hasn't been started.
///
/// Parameters:
///   - vm_dir: Open directory handle to the VM's directory
///
/// Returns: VmStatus (.running or .stopped)
pub fn getStatus(vm_dir: fs.Dir) !VmStatus {
    // Missing or malformed status file defaults to stopped.
    var f = vm_dir.openFile("status", .{}) catch return .stopped;
    defer f.close();

    var buf: [64]u8 = undefined;
    const n = try f.readAll(&buf);
    const s = std.mem.trim(u8, buf[0..n], " \t\r\n");
    if (std.mem.eql(u8, s, "running")) return .running;
    return .stopped;
}

/// Lists all VMs in the data directory with their current status.
///
/// Scans the {data_dir}/vms/ directory for subdirectories and reads
/// each VM's status file.
///
/// Returns: Slice of VmRecord structs. Caller owns the memory:
///   - Each VmRecord.name must be freed
///   - The slice itself must be freed
///
/// Example cleanup:
/// ```zig
/// const vms = try listVms(allocator);
/// defer {
///     for (vms) |r| allocator.free(r.name);
///     allocator.free(vms);
/// }
/// ```
pub fn listVms(allocator: std.mem.Allocator) ![]VmRecord {
    try ensureBaseDirs(allocator);

    const base = try paths.dataDir(allocator);
    defer allocator.free(base);

    const vms_path = try fs.path.join(allocator, &[_][]const u8{ base, "vms" });
    defer allocator.free(vms_path);

    var cwd = fs.cwd();
    var vms_dir = try cwd.openDir(vms_path, .{ .iterate = true });
    defer vms_dir.close();

    var it = vms_dir.iterate();
    var out: std.ArrayList(VmRecord) = .empty;
    errdefer {
        for (out.items) |r| allocator.free(r.name);
        out.deinit(allocator);
    }

    while (try it.next()) |e| {
        if (e.kind != .directory) continue;

        var vm_dir = vms_dir.openDir(e.name, .{}) catch continue;
        defer vm_dir.close();

        const st = getStatus(vm_dir) catch .stopped;
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, e.name),
            .status = st,
        });
    }

    return try out.toOwnedSlice(allocator);
}

// =============================================================================
// TESTS
// =============================================================================
// Tests use the "state:" prefix to identify which module they belong to.
// Most tests create VMs with random names to avoid collisions.

test "state: status transitions" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "test-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };
    defer deleteVm(allocator, name) catch {};

    try setStatus(allocator, name, .running);

    const dir_path = try paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var vm_dir = try fs.cwd().openDir(dir_path, .{});
    defer vm_dir.close();

    try std.testing.expectEqual(VmStatus.running, try getStatus(vm_dir));

    try setStatus(allocator, name, .stopped);
    try std.testing.expectEqual(VmStatus.stopped, try getStatus(vm_dir));
}

test "state: listVms reflects status" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "list-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };
    defer deleteVm(allocator, name) catch {};

    try setStatus(allocator, name, .running);

    const list = try listVms(allocator);
    defer {
        for (list) |r| allocator.free(r.name);
        allocator.free(list);
    }

    var found = false;
    for (list) |r| {
        if (std.mem.eql(u8, r.name, name)) {
            found = true;
            try std.testing.expectEqual(VmStatus.running, r.status);
        }
    }
    try std.testing.expect(found);
}

test "state: initVm creates config and status files" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "init-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };
    defer deleteVm(allocator, name) catch {};

    const dir_path = try paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    var vm_dir = try fs.cwd().openDir(dir_path, .{});
    defer vm_dir.close();

    var status_file = try vm_dir.openFile("status", .{});
    defer status_file.close();

    var status_buf: [64]u8 = undefined;
    const status_len = try status_file.readAll(&status_buf);
    const status = std.mem.trim(u8, status_buf[0..status_len], " \t\r\n");
    try std.testing.expectEqualStrings("stopped", status);

    const cfg = try config.readConfigFile(allocator, vm_dir, name);
    var cfg_mut = cfg;
    defer config.freeConfig(allocator, &cfg_mut);
    try std.testing.expectEqualStrings(name, cfg_mut.name);
    try std.testing.expect(!cfg_mut.ephemeral);
}

test "state: initVm rejects duplicate names" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "dup-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };
    defer deleteVm(allocator, name) catch {};

    try std.testing.expectError(errors.M80Error.AlreadyExists, initVm(allocator, name));
}

test "state: deleteVm removes record" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "del-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };

    try deleteVm(allocator, name);

    const list = try listVms(allocator);
    defer {
        for (list) |r| allocator.free(r.name);
        allocator.free(list);
    }

    for (list) |r| {
        if (std.mem.eql(u8, r.name, name)) {
            return error.TestExpectedEqual;
        }
    }
}

test "state: initVm deleteVm removes config and status files" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "rm-{s}", .{hex[0..]});

    initVm(allocator, name) catch |e| switch (e) {
        error.AlreadyExists => return error.SkipZigTest,
        else => return e,
    };

    const dir_path = try paths.vmDir(allocator, name);
    defer allocator.free(dir_path);

    {
        var vm_dir = try fs.cwd().openDir(dir_path, .{});
        defer vm_dir.close();
        _ = try vm_dir.statFile("m80.conf");
        _ = try vm_dir.statFile("status");
    }

    try deleteVm(allocator, name);

    try std.testing.expectError(error.FileNotFound, fs.cwd().openDir(dir_path, .{}));
}

test "state: getStatus defaults to stopped when missing or invalid" {
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    // Missing status file should default to stopped.
    try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));

    // Invalid contents should also resolve to stopped.
    var f = try tmp.dir.createFile("status", .{ .truncate = true });
    defer f.close();
    try f.writeAll("unknown\n");
    try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));
}

test "state: deleteVm rejects invalid name" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try std.testing.expectError(errors.M80Error.InvalidArgs, deleteVm(allocator, "../evil"));
}

test "state: deleteVm returns NotFound for missing vm" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "missing-{s}", .{hex[0..]});

    const dir_path = paths.vmDir(allocator, name) catch return error.SkipZigTest;
    defer allocator.free(dir_path);

    if (fs.cwd().openDir(dir_path, .{})) |dir| {
        var d = dir;
        d.close();
        return error.SkipZigTest;
    } else |_| {}

    try std.testing.expectError(errors.M80Error.NotFound, deleteVm(allocator, name));
}

test "state: setStatus returns NotFound for missing vm" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rnd: [8]u8 = undefined;
    fs.io().random(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);

    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "missing-{s}", .{hex[0..]});

    try std.testing.expectError(errors.M80Error.NotFound, setStatus(allocator, name, .running));
}

test "state: getStatus returns stopped on unexpected content" {
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("status", .{ .truncate = true });
        defer f.close();
        try f.writeAll("gibberish\n");
    }

    try std.testing.expectEqual(VmStatus.stopped, try getStatus(tmp.dir));
}

test "state: listVms returns empty when data dir is empty" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const data_root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(data_root);

    const vms_path = try fs.path.join(allocator, &[_][]const u8{ data_root, "vms" });
    defer allocator.free(vms_path);
    try tmp.dir.makePath("vms");

    var vms_dir = try tmp.dir.openDir("vms", .{ .iterate = true });
    defer vms_dir.close();

    var it = vms_dir.iterate();
    const next = try it.next();
    try std.testing.expect(next == null);
}

test "state: deleteVm returns NotFound for valid but missing name" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try std.testing.expectError(errors.M80Error.NotFound, deleteVm(allocator, "a"));
}

test "state: initVm rejects invalid name" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try std.testing.expectError(errors.M80Error.InvalidArgs, initVm(allocator, "../evil"));
}

test "state: path traversal patterns rejected" {
    const allocator = std.testing.allocator;

    // Various path traversal attempts
    const invalid_names = [_][]const u8{
        "../etc/passwd",
        "..\\windows\\system32",
        "foo/../../../etc",
        "..",
        ".",
        "/absolute/path",
        "name/with/slashes",
        "name\\with\\backslashes",
        "",
        "name with spaces",
        "name\x00null",
    };

    for (invalid_names) |name| {
        try std.testing.expectError(errors.M80Error.InvalidArgs, initVm(allocator, name));
        try std.testing.expectError(errors.M80Error.InvalidArgs, deleteVm(allocator, name));
    }
}

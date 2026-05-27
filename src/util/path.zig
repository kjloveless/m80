//! Secure Path Validation
//!
//! This module provides utilities for safely validating and manipulating
//! filesystem paths. It's critical for preventing path traversal attacks
//! that could allow VM operations outside designated directories.
//!
//! ## Security Features
//! - **Path Traversal Detection**: Rejects `..` in paths
//! - **Symlink Escape Detection**: Prevents symlinks pointing outside allowed roots
//! - **Depth Validation**: Ensures paths are sufficiently nested (prevents deleting root)
//! - **Root Containment**: Validates paths are within allowed directories
//!
//! ## Key Functions
//! - `validateSafePath`: Full validation with all checks
//! - `containsTraversal`: Quick check for `..` components
//! - `isWithinRoot`: Check if path starts with root prefix
//! - `safeDeleteTree`: Delete directory only if it passes validation
//!
//! ## Path Canonicalization
//! Paths are canonicalized (resolved) before validation:
//! - `.` components are removed
//! - `..` components are resolved
//! - Symlinks in intermediate directories are resolved

const std = @import("std");
const fs = @import("fs.zig");
const builtin = @import("builtin");

pub const PathError = error{
    PathTraversal,
    SymlinkEscape,
    PathTooShallow,
    PathNotWithinRoot,
    InvalidPath,
    OutOfMemory,
    AccessDenied,
};

pub const ValidateOptions = struct {
    allowed_root: []const u8,
    min_depth: u8 = 2,
    follow_symlinks: bool = false,
};

fn isPathSeparator(ch: u8) bool {
    return ch == '/' or ch == '\\';
}

fn preferredPathSeparator(path: []const u8) u8 {
    if (std.mem.indexOfScalar(u8, path, '/')) |_| return '/';
    if (std.mem.indexOfScalar(u8, path, '\\')) |_| return '\\';
    return fs.path.sep;
}

fn rootPrefixLen(path: []const u8) usize {
    if (path.len >= 3 and std.ascii.isAlphabetic(path[0]) and path[1] == ':' and isPathSeparator(path[2])) {
        return 3;
    }
    if (path.len >= 2 and isPathSeparator(path[0]) and isPathSeparator(path[1])) {
        return 2;
    }
    if (path.len >= 1 and isPathSeparator(path[0])) {
        return 1;
    }
    return 0;
}

fn trimTrailingSeparators(path: []const u8) []const u8 {
    const min_len = rootPrefixLen(path);
    var end = path.len;
    while (end > min_len and isPathSeparator(path[end - 1])) {
        end -= 1;
    }
    return path[0..end];
}

/// Validates that a path is safe for operations like deletion.
/// - Canonicalizes the path (resolves . and ..)
/// - Detects path traversal attempts
/// - Detects symlink escapes (optional)
/// - Ensures path is at least min_depth levels below allowed_root
pub fn validateSafePath(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: ValidateOptions,
) PathError![]u8 {
    if (path.len == 0) return PathError.InvalidPath;

    // Get canonical path of the root first
    const canonical_root = canonicalizePath(allocator, options.allowed_root) catch |e| switch (e) {
        error.OutOfMemory => return PathError.OutOfMemory,
        else => return PathError.InvalidPath,
    };
    defer allocator.free(canonical_root);

    // Canonicalize the target path
    const canonical_path = canonicalizePath(allocator, path) catch |e| switch (e) {
        error.OutOfMemory => return PathError.OutOfMemory,
        else => return PathError.InvalidPath,
    };
    errdefer allocator.free(canonical_path);

    // Check if path is inside the canonical root on a path-component boundary.
    if (!isWithinRoot(canonical_path, canonical_root)) {
        return PathError.PathNotWithinRoot;
    }

    // Check that path is sufficiently deep below root
    const relative = canonical_path[canonical_root.len..];
    const depth = countPathDepth(relative);
    if (depth < options.min_depth) {
        return PathError.PathTooShallow;
    }

    // Optionally check for symlink escapes
    if (!options.follow_symlinks) {
        const escape = checkSymlinkEscape(allocator, canonical_path, canonical_root) catch {
            return PathError.OutOfMemory;
        };
        if (escape) {
            return PathError.SymlinkEscape;
        }
    }

    return canonical_path;
}

/// Canonicalizes a path by resolving . and .. components
/// Does NOT follow symlinks (for security)
fn canonicalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0) return error.InvalidPath;

    // If path is absolute, get realpath without following final symlink
    if (fs.path.isAbsolute(path)) {
        // Try to get the real path from the filesystem
        // This handles symlinks in intermediate directories
        const real = fs.cwd().realpathAlloc(allocator, path) catch |e| switch (e) {
            error.FileNotFound => {
                // Path doesn't exist yet - normalize it manually
                return normalizePathComponents(allocator, path);
            },
            else => return e,
        };
        return real;
    }

    // Relative path - join with cwd first
    const cwd_path = try fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const joined = try fs.path.join(allocator, &[_][]const u8{ cwd_path, path });
    defer allocator.free(joined);

    const real = fs.cwd().realpathAlloc(allocator, joined) catch |e| switch (e) {
        error.FileNotFound => {
            return normalizePathComponents(allocator, joined);
        },
        else => return e,
    };
    return real;
}

/// Normalizes path components without filesystem access
/// Removes . and resolves .. components
fn normalizePathComponents(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);

    const prefix_len = rootPrefixLen(path);
    const prefix = path[0..prefix_len];
    const is_absolute = prefix_len > 0;
    const sep = preferredPathSeparator(path);

    var idx: usize = prefix_len;
    while (idx < path.len) {
        while (idx < path.len and isPathSeparator(path[idx])) : (idx += 1) {}
        const start = idx;
        while (idx < path.len and !isPathSeparator(path[idx])) : (idx += 1) {}
        if (start == idx) continue;
        const component = path[start..idx];
        if (component.len == 0 or std.mem.eql(u8, component, ".")) {
            continue;
        }
        if (std.mem.eql(u8, component, "..")) {
            if (components.items.len > 0) {
                _ = components.pop();
            } else if (!is_absolute) {
                try components.append(allocator, component);
            }
            continue;
        }
        try components.append(allocator, component);
    }

    if (components.items.len == 0) {
        if (is_absolute) {
            return try allocator.dupe(u8, prefix);
        }
        return try allocator.dupe(u8, ".");
    }

    // Calculate total length
    var total_len: usize = prefix.len;
    for (components.items) |c| {
        total_len += c.len;
    }
    total_len += components.items.len - 1;

    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    if (is_absolute) {
        @memcpy(result[pos..][0..prefix.len], prefix);
        pos += prefix.len;
    }

    for (components.items, 0..) |c, i| {
        if (i > 0) {
            result[pos] = sep;
            pos += 1;
        }
        @memcpy(result[pos..][0..c.len], c);
        pos += c.len;
    }

    return result[0..pos];
}

/// Counts the depth of path components below a root
fn countPathDepth(relative_path: []const u8) u8 {
    if (relative_path.len == 0) return 0;

    var depth: u8 = 0;
    var idx: usize = 0;
    while (idx < relative_path.len) {
        while (idx < relative_path.len and isPathSeparator(relative_path[idx])) : (idx += 1) {}
        const start = idx;
        while (idx < relative_path.len and !isPathSeparator(relative_path[idx])) : (idx += 1) {}
        if (start == idx) continue;
        const component = relative_path[start..idx];
        if (component.len > 0 and !std.mem.eql(u8, component, ".")) {
            depth += 1;
        }
    }
    return depth;
}

/// Checks if any component of the path is a symlink that escapes the allowed root
fn checkSymlinkEscape(
    allocator: std.mem.Allocator,
    path: []const u8,
    allowed_root: []const u8,
) !bool {
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);

    const prefix_len = rootPrefixLen(path);
    const sep = preferredPathSeparator(path);
    var idx: usize = prefix_len;
    while (idx < path.len) {
        while (idx < path.len and isPathSeparator(path[idx])) : (idx += 1) {}
        const start = idx;
        while (idx < path.len and !isPathSeparator(path[idx])) : (idx += 1) {}
        if (start == idx) continue;
        const component = path[start..idx];
        try components.append(allocator, component);
    }

    // Build up path progressively and check each level
    var current_path: std.ArrayList(u8) = .empty;
    defer current_path.deinit(allocator);

    // Start with the root prefix if absolute.
    if (prefix_len > 0) {
        try current_path.appendSlice(allocator, path[0..prefix_len]);
    }

    for (components.items) |component| {
        if (current_path.items.len > 0 and !isPathSeparator(current_path.items[current_path.items.len - 1])) {
            try current_path.append(allocator, sep);
        }
        try current_path.appendSlice(allocator, component);

        // Check if this is a symlink without following it where possible.
        const stat = if (builtin.os.tag == .windows) blk: {
            break :blk fs.cwd().statFileNoFollow(current_path.items) catch continue;
        } else blk: {
            const posix_stat = fs.statAt(
                std.posix.AT.FDCWD,
                current_path.items,
                std.posix.AT.SYMLINK_NOFOLLOW,
            ) catch continue;
            break :blk posix_stat;
        };
        if (stat.kind == .sym_link) {
            // Resolve the symlink and check if it escapes
            const target = readLinkAlloc(allocator, current_path.items) catch continue;
            defer allocator.free(target);

            var resolved: []u8 = undefined;
            if (fs.path.isAbsolute(target)) {
                resolved = try allocator.dupe(u8, target);
            } else {
                // Relative symlink - resolve from parent directory
                const parent = fs.path.dirname(current_path.items) orelse path[0..prefix_len];
                resolved = try fs.path.join(allocator, &[_][]const u8{ parent, target });
            }
            defer allocator.free(resolved);

            const canonical = canonicalizePath(allocator, resolved) catch continue;
            defer allocator.free(canonical);

            if (!isWithinRoot(canonical, allowed_root)) {
                return true;
            }
        }
    }

    return false;
}

fn readLinkAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var buf_len: usize = 256;
    while (true) {
        const buf = try allocator.alloc(u8, buf_len);
        errdefer allocator.free(buf);
        const res = fs.cwd().readLink(path, buf) catch |e| switch (e) {
            error.NameTooLong => {
                allocator.free(buf);
                buf_len *= 2;
                continue;
            },
            else => return e,
        };
        const out = try allocator.dupe(u8, buf[0..res]);
        allocator.free(buf);
        return out;
    }
}

/// Safely deletes a directory tree after validating the path
pub fn safeDeleteTree(
    allocator: std.mem.Allocator,
    path: []const u8,
    allowed_root: []const u8,
) PathError!void {
    // Validate and canonicalize first to avoid deleting outside allowed_root.
    const validated = try validateSafePath(allocator, path, .{
        .allowed_root = allowed_root,
        .min_depth = 2,
        .follow_symlinks = false,
    });
    defer allocator.free(validated);

    fs.cwd().deleteTree(validated) catch |e| switch (e) {
        error.AccessDenied => return PathError.AccessDenied,
        else => return PathError.InvalidPath,
    };
}

/// Checks if a path contains any path traversal patterns
pub fn containsTraversal(path: []const u8) bool {
    var idx: usize = 0;
    while (idx < path.len) {
        while (idx < path.len and isPathSeparator(path[idx])) : (idx += 1) {}
        const start = idx;
        while (idx < path.len and !isPathSeparator(path[idx])) : (idx += 1) {}
        if (std.mem.eql(u8, path[start..idx], "..")) return true;
    }

    return false;
}

/// Validates that a path is within a given root without filesystem access
/// Useful for quick pre-validation before more expensive checks
pub fn isWithinRoot(path: []const u8, root: []const u8) bool {
    const normalized_root = trimTrailingSeparators(root);
    if (normalized_root.len == 0) return false;
    if (path.len < normalized_root.len) return false;

    const prefix = path[0..normalized_root.len];
    const matches = if (builtin.os.tag == .windows)
        std.ascii.eqlIgnoreCase(prefix, normalized_root)
    else
        std.mem.eql(u8, prefix, normalized_root);
    if (!matches) return false;

    // Must have a separator after root (or be exactly the root)
    if (path.len == normalized_root.len) return true;
    if (isPathSeparator(normalized_root[normalized_root.len - 1])) return true;
    if (isPathSeparator(path[normalized_root.len])) return true;

    return false;
}

// =============================================================================
// TESTS
// =============================================================================

test "path: validateSafePath rejects traversal" {
    const allocator = std.testing.allocator;

    // Create a temporary directory structure for testing
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    // Create nested structure
    try tmp.dir.makePath("level1/level2/level3");

    const valid_path = try fs.path.join(allocator, &[_][]const u8{ root, "level1", "level2" });
    defer allocator.free(valid_path);

    const result = try validateSafePath(allocator, valid_path, .{
        .allowed_root = root,
        .min_depth = 2,
    });
    defer allocator.free(result);

    try std.testing.expect(std.mem.startsWith(u8, result, root));
}

test "path: validateSafePath rejects shallow paths" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    try tmp.dir.makePath("level1");

    const shallow_path = try fs.path.join(allocator, &[_][]const u8{ root, "level1" });
    defer allocator.free(shallow_path);

    try std.testing.expectError(PathError.PathTooShallow, validateSafePath(allocator, shallow_path, .{
        .allowed_root = root,
        .min_depth = 2,
    }));
}

test "path: validateSafePath rejects paths outside root" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    try std.testing.expectError(PathError.PathNotWithinRoot, validateSafePath(allocator, "/tmp/outside", .{
        .allowed_root = root,
        .min_depth = 2,
    }));
}

test "path: countPathDepth" {
    try std.testing.expectEqual(@as(u8, 0), countPathDepth(""));
    try std.testing.expectEqual(@as(u8, 1), countPathDepth("/foo"));
    try std.testing.expectEqual(@as(u8, 2), countPathDepth("/foo/bar"));
    try std.testing.expectEqual(@as(u8, 3), countPathDepth("/foo/bar/baz"));
}

test "path: containsTraversal" {
    try std.testing.expect(containsTraversal("../foo"));
    try std.testing.expect(containsTraversal("foo/../bar"));
    try std.testing.expect(containsTraversal("foo/.."));
    try std.testing.expect(!containsTraversal("foo/bar"));
    try std.testing.expect(!containsTraversal("/absolute/path"));
}

test "path: isWithinRoot" {
    try std.testing.expect(isWithinRoot("/home/user/data", "/home/user"));
    try std.testing.expect(isWithinRoot("/home/user", "/home/user"));
    try std.testing.expect(!isWithinRoot("/home/user2", "/home/user"));
    try std.testing.expect(!isWithinRoot("/other/path", "/home/user"));
}

test "path: normalizePathComponents" {
    const allocator = std.testing.allocator;

    {
        const result = try normalizePathComponents(allocator, "/foo/bar/../baz");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/foo/baz", result);
    }

    {
        const result = try normalizePathComponents(allocator, "/foo/./bar/./baz");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/foo/bar/baz", result);
    }

    {
        const result = try normalizePathComponents(allocator, "/foo/bar/../../baz");
        defer allocator.free(result);
        try std.testing.expectEqualStrings("/baz", result);
    }
}

test "path: containsTraversal detects windows separators" {
    try std.testing.expect(containsTraversal("..\\evil"));
    try std.testing.expect(containsTraversal("foo\\..\\bar"));
    try std.testing.expect(!containsTraversal("foo\\bar"));
}

test "path: isWithinRoot enforces separator boundary" {
    try std.testing.expect(!isWithinRoot("/home/user2", "/home/user"));
    try std.testing.expect(isWithinRoot("/home/user", "/home/user"));
    try std.testing.expect(isWithinRoot("/home/user/sub", "/home/user"));
}

test "path: validateSafePath rejects when root missing" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(PathError.PathNotWithinRoot, validateSafePath(allocator, "/tmp/thing", .{
        .allowed_root = "/definitely/missing/root",
        .min_depth = 2,
    }));
}

test "path: validateSafePath rejects symlink escape" {
    const allocator = std.testing.allocator;

    if (builtin.os.tag == .windows) return error.SkipZigTest;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("root/child");
    try tmp.dir.makePath("outside");
    try tmp.dir.symLink("../outside", "root/link", .{});

    const root = try tmp.dir.realpathAlloc(allocator, "root");
    defer allocator.free(root);

    const target = try fs.path.join(allocator, &[_][]const u8{ root, "link" });
    defer allocator.free(target);

    const result = validateSafePath(allocator, target, .{
        .allowed_root = root,
        .min_depth = 1,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        PathError.SymlinkEscape,
        PathError.PathNotWithinRoot,
        => return,
        else => return err,
    };
    allocator.free(result);
    return error.TestExpectedError;
}

test "path: safeDeleteTree rejects shallow paths" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("root/child");
    const root = try tmp.dir.realpathAlloc(allocator, "root");
    defer allocator.free(root);

    const target = try fs.path.join(allocator, &[_][]const u8{ root, "child" });
    defer allocator.free(target);

    try std.testing.expectError(PathError.PathTooShallow, safeDeleteTree(allocator, target, root));
}

test "path: safeDeleteTree deletes deep tree" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("root/a/b");
    {
        var f = try tmp.dir.createFile("root/a/b/file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const root = try tmp.dir.realpathAlloc(allocator, "root");
    defer allocator.free(root);

    const target = try fs.path.join(allocator, &[_][]const u8{ root, "a", "b" });
    defer allocator.free(target);

    try safeDeleteTree(allocator, target, root);

    try std.testing.expectError(error.FileNotFound, fs.cwd().openDir(target, .{}));
}

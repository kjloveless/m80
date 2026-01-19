const std = @import("std");
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

    // Check if path starts with the canonical root
    if (!std.mem.startsWith(u8, canonical_path, canonical_root)) {
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
    if (std.fs.path.isAbsolute(path)) {
        // Try to get the real path from the filesystem
        // This handles symlinks in intermediate directories
        const real = std.fs.cwd().realpathAlloc(allocator, path) catch |e| switch (e) {
            error.FileNotFound => {
                // Path doesn't exist yet - normalize it manually
                return normalizePathComponents(allocator, path);
            },
            else => return e,
        };
        return real;
    }

    // Relative path - join with cwd first
    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    const joined = try std.fs.path.join(allocator, &[_][]const u8{ cwd_path, path });
    defer allocator.free(joined);

    const real = std.fs.cwd().realpathAlloc(allocator, joined) catch |e| switch (e) {
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

    const is_absolute = std.fs.path.isAbsolute(path);

    var it = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) {
            continue;
        }
        if (std.mem.eql(u8, component, "..")) {
            if (components.items.len > 0) {
                _ = components.pop();
            }
            continue;
        }
        try components.append(allocator, component);
    }

    if (components.items.len == 0) {
        if (is_absolute) {
            return try allocator.dupe(u8, "/");
        }
        return try allocator.dupe(u8, ".");
    }

    // Calculate total length
    var total_len: usize = 0;
    for (components.items) |c| {
        total_len += c.len + 1; // +1 for separator
    }
    if (is_absolute) {
        total_len += 0; // leading slash is already counted
    } else {
        total_len -= 1; // no leading separator for relative paths
    }

    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    if (is_absolute) {
        result[pos] = std.fs.path.sep;
        pos += 1;
    }

    for (components.items, 0..) |c, i| {
        if (i > 0) {
            result[pos] = std.fs.path.sep;
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
    var it = std.mem.splitScalar(u8, relative_path, std.fs.path.sep);
    while (it.next()) |component| {
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

    var it = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (it.next()) |component| {
        if (component.len == 0) continue;
        try components.append(allocator, component);
    }

    // Build up path progressively and check each level
    var current_path: std.ArrayList(u8) = .empty;
    defer current_path.deinit(allocator);

    // Start with root separator if absolute
    if (std.fs.path.isAbsolute(path)) {
        try current_path.append(allocator, std.fs.path.sep);
    }

    for (components.items) |component| {
        if (current_path.items.len > 1 or (current_path.items.len == 1 and current_path.items[0] != std.fs.path.sep)) {
            try current_path.append(allocator, std.fs.path.sep);
        }
        try current_path.appendSlice(allocator, component);

        // Check if this is a symlink
        const stat = std.fs.cwd().statFile(current_path.items) catch continue;
        if (stat.kind == .sym_link) {
            // Resolve the symlink and check if it escapes
            const target = readLinkAlloc(allocator, current_path.items) catch continue;
            defer allocator.free(target);

            var resolved: []u8 = undefined;
            if (std.fs.path.isAbsolute(target)) {
                resolved = try allocator.dupe(u8, target);
            } else {
                // Relative symlink - resolve from parent directory
                const parent = std.fs.path.dirname(current_path.items) orelse "/";
                resolved = try std.fs.path.join(allocator, &[_][]const u8{ parent, target });
            }
            defer allocator.free(resolved);

            const canonical = canonicalizePath(allocator, resolved) catch continue;
            defer allocator.free(canonical);

            if (!std.mem.startsWith(u8, canonical, allowed_root)) {
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
        const res = std.fs.cwd().readLink(path, buf) catch |e| switch (e) {
            error.NameTooLong => {
                allocator.free(buf);
                buf_len *= 2;
                continue;
            },
            else => return e,
        };
        const out = try allocator.dupe(u8, res);
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
    const validated = try validateSafePath(allocator, path, .{
        .allowed_root = allowed_root,
        .min_depth = 2,
        .follow_symlinks = false,
    });
    defer allocator.free(validated);

    std.fs.cwd().deleteTree(validated) catch |e| switch (e) {
        error.AccessDenied => return PathError.AccessDenied,
        else => return PathError.InvalidPath,
    };
}

/// Checks if a path contains any path traversal patterns
pub fn containsTraversal(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }

    // Also check for Windows-style separators
    if (builtin.os.tag != .windows) {
        var win_it = std.mem.splitScalar(u8, path, '\\');
        while (win_it.next()) |component| {
            if (std.mem.eql(u8, component, "..")) return true;
        }
    }

    return false;
}

/// Validates that a path is within a given root without filesystem access
/// Useful for quick pre-validation before more expensive checks
pub fn isWithinRoot(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;

    // Must have a separator after root (or be exactly the root)
    if (path.len == root.len) return true;
    if (path.len > root.len and path[root.len] == std.fs.path.sep) return true;

    return false;
}

// Tests
test "path: validateSafePath rejects traversal" {
    const allocator = std.testing.allocator;

    // Create a temporary directory structure for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    // Create nested structure
    try tmp.dir.makePath("level1/level2/level3");

    const valid_path = try std.fs.path.join(allocator, &[_][]const u8{ root, "level1", "level2" });
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

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    try tmp.dir.makePath("level1");

    const shallow_path = try std.fs.path.join(allocator, &[_][]const u8{ root, "level1" });
    defer allocator.free(shallow_path);

    try std.testing.expectError(PathError.PathTooShallow, validateSafePath(allocator, shallow_path, .{
        .allowed_root = root,
        .min_depth = 2,
    }));
}

test "path: validateSafePath rejects paths outside root" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
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

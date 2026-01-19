const std = @import("std");
const path_util = @import("../util/path.zig");

/// Access level for mounted filesystems
pub const MountAccess = enum {
    read_only,
    read_write,

    pub fn fromString(s: []const u8) ?MountAccess {
        if (std.mem.eql(u8, s, "ro") or std.mem.eql(u8, s, "read_only")) return .read_only;
        if (std.mem.eql(u8, s, "rw") or std.mem.eql(u8, s, "read_write")) return .read_write;
        return null;
    }

    pub fn toString(self: MountAccess) []const u8 {
        return switch (self) {
            .read_only => "ro",
            .read_write => "rw",
        };
    }
};

/// Type of filesystem sharing protocol
pub const MountType = enum {
    virtio_fs,
    plan9,

    pub fn fromString(s: []const u8) ?MountType {
        if (std.mem.eql(u8, s, "virtio_fs") or std.mem.eql(u8, s, "virtiofs")) return .virtio_fs;
        if (std.mem.eql(u8, s, "9p") or std.mem.eql(u8, s, "plan9")) return .plan9;
        return null;
    }

    pub fn toString(self: MountType) []const u8 {
        return switch (self) {
            .virtio_fs => "virtiofs",
            .plan9 => "9p",
        };
    }
};

/// Configuration for a single filesystem mount
pub const MountConfig = struct {
    /// Tag visible inside the guest for mounting
    tag: []const u8,
    /// Host directory path
    host_path: []const u8,
    /// Suggested mount point inside guest
    guest_path: []const u8,
    /// Access level (default: read_only)
    access: MountAccess = .read_only,
    /// Sharing protocol
    mount_type: MountType = .virtio_fs,
    /// Maximum file size in bytes (0 = unlimited)
    max_file_size: u64 = 0,
    /// Whether to allow execution of files
    allow_exec: bool = false,
};

pub const MountError = error{
    PathNotAllowed,
    PathOutsideAllowedRoots,
    PathTraversal,
    InvalidPath,
    DuplicateTag,
    TooManyMounts,
    OutOfMemory,
    WriteNotAllowed,
};

/// Maximum number of mounts allowed
pub const MAX_MOUNTS = 16;

/// Manages filesystem mounts and validates access
pub const MountManager = struct {
    allocator: std.mem.Allocator,
    /// Configured mounts
    mounts: std.ArrayList(MountConfig),
    /// Allowed root directories for host paths
    allowed_roots: std.ArrayList([]const u8),
    /// Whether to validate paths strictly
    strict_validation: bool = true,

    pub fn init(allocator: std.mem.Allocator) MountManager {
        return .{
            .allocator = allocator,
            .mounts = .empty,
            .allowed_roots = .empty,
        };
    }

    pub fn deinit(self: *MountManager) void {
        // Free mount strings
        for (self.mounts.items) |mount| {
            self.allocator.free(mount.tag);
            self.allocator.free(mount.host_path);
            self.allocator.free(mount.guest_path);
        }
        self.mounts.deinit(self.allocator);

        // Free allowed roots
        for (self.allowed_roots.items) |root| {
            self.allocator.free(root);
        }
        self.allowed_roots.deinit(self.allocator);
    }

    /// Adds a directory to the list of allowed mount roots
    pub fn addAllowedRoot(self: *MountManager, path: []const u8) !void {
        const owned = try self.allocator.dupe(u8, path);
        try self.allowed_roots.append(self.allocator, owned);
    }

    /// Adds a mount configuration (clones all strings for ownership).
    pub fn addMount(self: *MountManager, config: MountConfig) MountError!void {
        if (self.mounts.items.len >= MAX_MOUNTS) {
            return MountError.TooManyMounts;
        }

        // Check for duplicate tags
        for (self.mounts.items) |existing| {
            if (std.mem.eql(u8, existing.tag, config.tag)) {
                return MountError.DuplicateTag;
            }
        }

        // Validate host path is within allowed roots when strict mode is on.
        if (self.strict_validation) {
            if (!self.isPathWithinAllowedRoots(config.host_path)) {
                return MountError.PathOutsideAllowedRoots;
            }
        }

        // Check for path traversal (applies even if strict validation is off).
        if (path_util.containsTraversal(config.host_path)) {
            return MountError.PathTraversal;
        }

        // Clone strings for ownership
        const owned_tag = self.allocator.dupe(u8, config.tag) catch return MountError.OutOfMemory;
        errdefer self.allocator.free(owned_tag);

        const owned_host_path = self.allocator.dupe(u8, config.host_path) catch return MountError.OutOfMemory;
        errdefer self.allocator.free(owned_host_path);

        const owned_guest_path = self.allocator.dupe(u8, config.guest_path) catch return MountError.OutOfMemory;
        errdefer self.allocator.free(owned_guest_path);

        self.mounts.append(self.allocator, .{
            .tag = owned_tag,
            .host_path = owned_host_path,
            .guest_path = owned_guest_path,
            .access = config.access,
            .mount_type = config.mount_type,
            .max_file_size = config.max_file_size,
            .allow_exec = config.allow_exec,
        }) catch return MountError.OutOfMemory;
    }

    /// Checks if a host path is within allowed roots
    pub fn isPathWithinAllowedRoots(self: *const MountManager, path: []const u8) bool {
        if (self.allowed_roots.items.len == 0) {
            // No roots configured - nothing is allowed in strict mode
            return false;
        }

        for (self.allowed_roots.items) |root| {
            if (path_util.isWithinRoot(path, root)) {
                return true;
            }
        }
        return false;
    }

    /// Checks if a path can be accessed with the given write permission.
    /// Returns false if no mount owns the path.
    pub fn isPathAccessAllowed(
        self: *const MountManager,
        path: []const u8,
        write_access: bool,
    ) MountError!bool {
        // Find which mount this path belongs to
        for (self.mounts.items) |mount| {
            if (path_util.isWithinRoot(path, mount.host_path)) {
                // Check write permission
                if (write_access and mount.access == .read_only) {
                    return MountError.WriteNotAllowed;
                }
                return true;
            }
        }
        return false;
    }

    /// Gets a mount by its tag
    pub fn getMountByTag(self: *const MountManager, tag: []const u8) ?*const MountConfig {
        for (self.mounts.items) |*mount| {
            if (std.mem.eql(u8, mount.tag, tag)) {
                return mount;
            }
        }
        return null;
    }

    /// Gets a mount by guest path
    pub fn getMountByGuestPath(self: *const MountManager, guest_path: []const u8) ?*const MountConfig {
        for (self.mounts.items) |*mount| {
            if (std.mem.eql(u8, mount.guest_path, guest_path)) {
                return mount;
            }
        }
        return null;
    }

    /// Validates a file operation against mount permissions
    pub fn validateFileOperation(
        self: *const MountManager,
        mount_tag: []const u8,
        relative_path: []const u8,
        operation: FileOperation,
    ) MountError!void {
        const mount = self.getMountByTag(mount_tag) orelse return MountError.InvalidPath;

        // Check for path traversal in relative path
        if (path_util.containsTraversal(relative_path)) {
            return MountError.PathTraversal;
        }

        // Check write permission for write operations
        switch (operation) {
            .read, .stat, .readdir => {},
            .write, .create, .delete, .rename => {
                if (mount.access == .read_only) {
                    return MountError.WriteNotAllowed;
                }
            },
        }
    }

    /// Returns the number of configured mounts
    pub fn mountCount(self: *const MountManager) usize {
        return self.mounts.items.len;
    }
};

/// File operations that can be performed on mounted filesystems
pub const FileOperation = enum {
    read,
    write,
    create,
    delete,
    rename,
    stat,
    readdir,

    pub fn isWrite(self: FileOperation) bool {
        return switch (self) {
            .read, .stat, .readdir => false,
            .write, .create, .delete, .rename => true,
        };
    }
};

/// Parses mount configuration from a string
/// Format: "tag:host_path:guest_path:access:type"
pub fn parseMountConfig(s: []const u8) ?MountConfig {
    var parts = std.mem.splitScalar(u8, s, ':');

    const tag = parts.next() orelse return null;
    const host_path = parts.next() orelse return null;
    const guest_path = parts.next() orelse return null;

    var config = MountConfig{
        .tag = tag,
        .host_path = host_path,
        .guest_path = guest_path,
    };

    // Optional: access level
    if (parts.next()) |access_str| {
        config.access = MountAccess.fromString(access_str) orelse return null;
    }

    // Optional: mount type
    if (parts.next()) |type_str| {
        config.mount_type = MountType.fromString(type_str) orelse return null;
    }

    return config;
}

/// Formats a mount configuration to a string
pub fn formatMountConfig(allocator: std.mem.Allocator, config: *const MountConfig) ![]u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{s}:{s}:{s}:{s}:{s}",
        .{
            config.tag,
            config.host_path,
            config.guest_path,
            config.access.toString(),
            config.mount_type.toString(),
        },
    );
}

// Tests
test "mounts: MountAccess fromString/toString" {
    try std.testing.expectEqual(MountAccess.read_only, MountAccess.fromString("ro").?);
    try std.testing.expectEqual(MountAccess.read_only, MountAccess.fromString("read_only").?);
    try std.testing.expectEqual(MountAccess.read_write, MountAccess.fromString("rw").?);
    try std.testing.expect(MountAccess.fromString("invalid") == null);

    try std.testing.expectEqualStrings("ro", MountAccess.read_only.toString());
    try std.testing.expectEqualStrings("rw", MountAccess.read_write.toString());
}

test "mounts: MountType fromString/toString" {
    try std.testing.expectEqual(MountType.virtio_fs, MountType.fromString("virtiofs").?);
    try std.testing.expectEqual(MountType.virtio_fs, MountType.fromString("virtio_fs").?);
    try std.testing.expectEqual(MountType.plan9, MountType.fromString("9p").?);
    try std.testing.expect(MountType.fromString("invalid") == null);
}

test "mounts: parseMountConfig" {
    const config = parseMountConfig("shared:/home/user/data:/mnt/data:ro:virtiofs").?;
    try std.testing.expectEqualStrings("shared", config.tag);
    try std.testing.expectEqualStrings("/home/user/data", config.host_path);
    try std.testing.expectEqualStrings("/mnt/data", config.guest_path);
    try std.testing.expectEqual(MountAccess.read_only, config.access);
    try std.testing.expectEqual(MountType.virtio_fs, config.mount_type);
}

test "mounts: parseMountConfig rejects missing fields" {
    try std.testing.expect(parseMountConfig("onlytag") == null);
    try std.testing.expect(parseMountConfig("tag:/host") == null);
}

test "mounts: invalid access or type rejects parse" {
    try std.testing.expect(parseMountConfig("t:/h:/g:bad") == null);
    try std.testing.expect(parseMountConfig("t:/h:/g:ro:badtype") == null);
}

test "mounts: strict_validation blocks mounts when no roots" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try std.testing.expectError(MountError.PathOutsideAllowedRoots, manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data",
        .guest_path = "/mnt/data",
    }));
}

test "mounts: non-strict allows mounts outside roots" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();
    manager.strict_validation = false;

    try manager.addMount(.{
        .tag = "data",
        .host_path = "/outside/root",
        .guest_path = "/mnt/data",
    });
    try std.testing.expectEqual(@as(usize, 1), manager.mountCount());
}

test "mounts: validateFileOperation rejects unknown tag" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try std.testing.expectError(
        MountError.InvalidPath,
        manager.validateFileOperation("missing", "file.txt", .read),
    );
}

test "mounts: getMountByGuestPath finds entry" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();
    manager.strict_validation = false;

    try manager.addMount(.{
        .tag = "data",
        .host_path = "/outside/root",
        .guest_path = "/mnt/data",
    });

    const mount = manager.getMountByGuestPath("/mnt/data").?;
    try std.testing.expectEqualStrings("data", mount.tag);
}

test "mounts: MountManager basic operations" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    // Add allowed root
    try manager.addAllowedRoot("/home/user");

    // Add a mount
    try manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data",
        .guest_path = "/mnt/data",
        .access = .read_only,
    });

    try std.testing.expectEqual(@as(usize, 1), manager.mountCount());

    const mount = manager.getMountByTag("data").?;
    try std.testing.expectEqualStrings("/home/user/data", mount.host_path);
}

test "mounts: MountManager rejects paths outside allowed roots" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");

    // Should fail - path outside allowed roots
    try std.testing.expectError(MountError.PathOutsideAllowedRoots, manager.addMount(.{
        .tag = "evil",
        .host_path = "/etc/passwd",
        .guest_path = "/mnt/passwd",
    }));
}

test "mounts: MountManager rejects path traversal" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");

    // Should fail - path traversal
    try std.testing.expectError(MountError.PathTraversal, manager.addMount(.{
        .tag = "evil",
        .host_path = "/home/user/../../../etc",
        .guest_path = "/mnt/etc",
    }));
}

test "mounts: MountManager rejects duplicate tags" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");

    try manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data1",
        .guest_path = "/mnt/data1",
    });

    // Should fail - duplicate tag
    try std.testing.expectError(MountError.DuplicateTag, manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data2",
        .guest_path = "/mnt/data2",
    }));
}

test "mounts: validateFileOperation write to read-only" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");

    try manager.addMount(.{
        .tag = "readonly",
        .host_path = "/home/user/readonly",
        .guest_path = "/mnt/ro",
        .access = .read_only,
    });

    // Read should succeed
    try manager.validateFileOperation("readonly", "file.txt", .read);

    // Write should fail
    try std.testing.expectError(
        MountError.WriteNotAllowed,
        manager.validateFileOperation("readonly", "file.txt", .write),
    );
}

test "mounts: FileOperation isWrite" {
    try std.testing.expect(!FileOperation.read.isWrite());
    try std.testing.expect(!FileOperation.stat.isWrite());
    try std.testing.expect(!FileOperation.readdir.isWrite());
    try std.testing.expect(FileOperation.write.isWrite());
    try std.testing.expect(FileOperation.create.isWrite());
    try std.testing.expect(FileOperation.delete.isWrite());
    try std.testing.expect(FileOperation.rename.isWrite());
}

test "mounts: isPathAccessAllowed returns false for unknown path" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");
    try manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data",
        .guest_path = "/mnt/data",
        .access = .read_only,
    });

    try std.testing.expectEqual(false, try manager.isPathAccessAllowed("/other/path", false));
}

test "mounts: isPathAccessAllowed rejects write on read-only mount" {
    const allocator = std.testing.allocator;

    var manager = MountManager.init(allocator);
    defer manager.deinit();

    try manager.addAllowedRoot("/home/user");
    try manager.addMount(.{
        .tag = "data",
        .host_path = "/home/user/data",
        .guest_path = "/mnt/data",
        .access = .read_only,
    });

    try std.testing.expectError(
        MountError.WriteNotAllowed,
        manager.isPathAccessAllowed("/home/user/data/file.txt", true),
    );
}

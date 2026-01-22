//! VirtIO-FS Device Emulation
//!
//! This module implements a VirtIO filesystem device that uses the FUSE
//! protocol to share host directories with the guest VM. The guest kernel
//! sends FUSE requests, and this module handles them by performing
//! corresponding operations on the host filesystem.
//!
//! ## FUSE Protocol Overview
//! FUSE (Filesystem in Userspace) uses a request/response protocol:
//! - Guest sends `FuseInHeader` + operation-specific payload
//! - Host responds with `FuseOutHeader` + response data
//! - Each request has a unique ID for matching responses
//!
//! ## Supported Operations
//! - INIT: Protocol version negotiation
//! - LOOKUP: Resolve file/directory by name
//! - GETATTR: Get file attributes (stat)
//! - OPEN/RELEASE: Open and close files
//! - READ/WRITE: Read and write file data
//! - OPENDIR/READDIR/RELEASEDIR: Directory listing
//! - DESTROY: Cleanup on unmount
//!
//! ## Node and Handle Management
//! - Nodes: Map inode numbers to host paths (allocated on LOOKUP)
//! - Handles: Track open files/directories (allocated on OPEN/OPENDIR)
//! - Node ID 1 is reserved for root in FUSE; we start at 2
//!
//! ## Security
//! - Path traversal ("..") is rejected in LOOKUP
//! - Mount permissions are checked via MountManager
//! - Invalid handles return EBADF (-9)

const std = @import("std");
const mounts = @import("mounts.zig");
const path_util = @import("../util/path.zig");

pub const VirtioFsError = error{
    InvalidRequest,
    OperationNotSupported,
    PathNotAllowed,
    IoError,
    OutOfMemory,
    InvalidHandle,
    NotFound,
    PermissionDenied,
};

pub const VirtioFeatures = struct {
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_FS_F_NOTIFICATION: u64 = 1 << 0;
};

pub const FuseOpcode = enum(u32) {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    FUSE_SETUPMAPPING = 48,
    FUSE_REMOVEMAPPING = 49,
    _,

    pub fn fromInt(value: u32) FuseOpcode {
        return @enumFromInt(value);
    }
};

pub const FuseInHeader = extern struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    padding: u32,
};

pub const FuseOutHeader = extern struct {
    len: u32,
    @"error": i32,
    unique: u64,
};

pub const FuseInitIn = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
};

pub const FuseInitOut = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    unused: [8]u32,
};

pub const FuseAttr = extern struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    padding: u32,
};

pub const FuseAttrOut = extern struct {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: FuseAttr,
};

pub const FuseEntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
};

pub const FuseOpenIn = extern struct {
    flags: u32,
    unused: u32,
};

pub const FuseOpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    padding: u32,
};

pub const FuseReadIn = extern struct {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
};

pub const FuseWriteIn = extern struct {
    fh: u64,
    offset: u64,
    size: u32,
    write_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
};

pub const FuseWriteOut = extern struct {
    size: u32,
    padding: u32,
};

pub const FuseReleaseIn = extern struct {
    fh: u64,
    flags: u32,
    release_flags: u32,
    lock_owner: u64,
};

pub const FuseDirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    @"type": u32,
};

pub const NodeHandle = struct {
    inode: u64,
    path: []const u8,
    is_dir: bool,
};

pub const FileHandle = struct {
    handle_id: u64,
    node: *NodeHandle,
    file: ?std.fs.File,
    dir: ?std.fs.Dir,
};

pub const VirtioFsDevice = struct {
    allocator: std.mem.Allocator,
    mount_manager: *mounts.MountManager,
    tag: []const u8,
    next_nodeid: u64,
    next_fh: u64,
    nodes: std.AutoHashMap(u64, NodeHandle),
    handles: std.AutoHashMap(u64, FileHandle),
    features: u64,

    pub fn init(allocator: std.mem.Allocator, mount_manager: *mounts.MountManager, tag: []const u8) VirtioFsDevice {
        // Node IDs start at 2 (1 is root in FUSE).
        return .{
            .allocator = allocator,
            .mount_manager = mount_manager,
            .tag = tag,
            .next_nodeid = 2,
            .next_fh = 1,
            .nodes = std.AutoHashMap(u64, NodeHandle).init(allocator),
            .handles = std.AutoHashMap(u64, FileHandle).init(allocator),
            .features = VirtioFeatures.VIRTIO_F_VERSION_1,
        };
    }

    pub fn deinit(self: *VirtioFsDevice) void {
        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| {
            self.allocator.free(node.path);
        }
        self.nodes.deinit();

        var handle_it = self.handles.valueIterator();
        while (handle_it.next()) |handle| {
            if (handle.file) |f| f.close();
            if (handle.dir) |*d| {
                var dir = d.*;
                dir.close();
            }
        }
        self.handles.deinit();
    }

    pub fn handleRequest(
        self: *VirtioFsDevice,
        request: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        // Requests are raw FUSE messages; this stub only supports a small subset.
        if (request.len < @sizeOf(FuseInHeader)) {
            return VirtioFsError.InvalidRequest;
        }

        var header: FuseInHeader = undefined;
        @memcpy(std.mem.asBytes(&header), request[0..@sizeOf(FuseInHeader)]);
        const opcode = FuseOpcode.fromInt(header.opcode);
        const payload = request[@sizeOf(FuseInHeader)..];

        return switch (opcode) {
            .FUSE_INIT => self.handleInit(&header, payload, response_buf),
            .FUSE_LOOKUP => self.handleLookup(&header, payload, response_buf),
            .FUSE_GETATTR => self.handleGetattr(&header, response_buf),
            .FUSE_OPEN => self.handleOpen(&header, payload, response_buf),
            .FUSE_READ => self.handleRead(&header, payload, response_buf),
            .FUSE_WRITE => self.handleWrite(&header, payload, response_buf),
            .FUSE_RELEASE => self.handleRelease(&header, payload, response_buf),
            .FUSE_OPENDIR => self.handleOpendir(&header, payload, response_buf),
            .FUSE_READDIR => self.handleReaddir(&header, payload, response_buf),
            .FUSE_RELEASEDIR => self.handleReleasedir(&header, payload, response_buf),
            .FUSE_DESTROY => self.handleDestroy(&header, response_buf),
            else => self.sendError(&header, -38, response_buf), // ENOSYS
        };
    }

    fn handleInit(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseInitIn)) {
            return self.sendError(header, -22, response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        const out_init_size = @sizeOf(FuseInitOut);
        const total_size = out_header_size + out_init_size;

        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const out_init: *FuseInitOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out_init.* = .{
            .major = 7,
            .minor = 31,
            .max_readahead = 131072,
            .flags = 0,
            .max_background = 0,
            .congestion_threshold = 0,
            .max_write = 131072,
            .time_gran = 1,
            .max_pages = 0,
            .map_alignment = 0,
            .unused = std.mem.zeroes([8]u32),
        };

        return total_size;
    }

    fn handleLookup(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        const name_end = std.mem.indexOfScalar(u8, payload, 0) orelse payload.len;
        const name = payload[0..name_end];

        if (name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }

        // Reject traversal attempts from the guest.
        if (path_util.containsTraversal(name)) {
            return self.sendError(header, -1, response_buf);
        }

        const parent_node = self.nodes.get(header.nodeid);
        const parent_path = if (parent_node) |n| n.path else "";

        const full_path = std.fs.path.join(self.allocator, &[_][]const u8{ parent_path, name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        const stat = std.fs.cwd().statFile(full_path) catch {
            return self.sendError(header, -2, response_buf);
        };

        const nodeid = self.allocateNode(full_path, stat.kind == .directory) catch {
            return self.sendError(header, -12, response_buf);
        };

        return self.sendEntryOut(header, nodeid, &stat, response_buf);
    }

    fn handleGetattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const stat = std.fs.cwd().statFile(node.path) catch {
            return self.sendError(header, -2, response_buf);
        };

        return self.sendAttrOut(header, &stat, response_buf);
    }

    fn handleOpen(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = payload;

        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const file = std.fs.cwd().openFile(node.path, .{ .mode = .read_write }) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const fh = self.allocateFileHandle(header.nodeid, file) catch {
            file.close();
            return self.sendError(header, -12, response_buf);
        };

        return self.sendOpenOut(header, fh, response_buf);
    }

    fn handleRead(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseReadIn)) {
            return self.sendError(header, -22, response_buf);
        }

        var read_in: FuseReadIn = undefined;
        @memcpy(std.mem.asBytes(&read_in), payload[0..@sizeOf(FuseReadIn)]);
        // Validate file handle before touching host filesystem.
        const handle = self.handles.get(read_in.fh) orelse {
            return self.sendError(header, -9, response_buf);
        };

        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size) {
            return VirtioFsError.IoError;
        }
        // Cap reads to the response buffer capacity.
        const max_data = @min(read_in.size, @as(u32, @intCast(response_buf.len - out_header_size)));

        var f = file;
        f.seekTo(read_in.offset) catch return self.sendError(header, -5, response_buf);
        const bytes_read = f.read(response_buf[out_header_size..][0..max_data]) catch return self.sendError(header, -5, response_buf);

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + bytes_read);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        return out_header_size + bytes_read;
    }

    fn handleWrite(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseWriteIn)) {
            return self.sendError(header, -22, response_buf);
        }

        var write_in: FuseWriteIn = undefined;
        @memcpy(std.mem.asBytes(&write_in), payload[0..@sizeOf(FuseWriteIn)]);
        // Validate file handle before touching host filesystem.
        const handle = self.handles.get(write_in.fh) orelse {
            return self.sendError(header, -9, response_buf);
        };

        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        const data_offset = @sizeOf(FuseWriteIn);
        if (payload.len < data_offset + write_in.size) {
            return self.sendError(header, -22, response_buf);
        }

        const data = payload[data_offset..][0..write_in.size];

        var f = file;
        f.seekTo(write_in.offset) catch return self.sendError(header, -5, response_buf);
        const bytes_written = f.write(data) catch return self.sendError(header, -5, response_buf);

        return self.sendWriteOut(header, @intCast(bytes_written), response_buf);
    }

    fn handleRelease(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseReleaseIn)) {
            return self.sendError(header, -22, response_buf);
        }

        var release_in: FuseReleaseIn = undefined;
        @memcpy(std.mem.asBytes(&release_in), payload[0..@sizeOf(FuseReleaseIn)]);

        if (self.handles.fetchRemove(release_in.fh)) |kv| {
            if (kv.value.file) |f| f.close();
        }

        return self.sendError(header, 0, response_buf);
    }

    fn handleOpendir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = payload;

        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        if (!node.is_dir) {
            return self.sendError(header, -20, response_buf);
        }

        const dir = std.fs.cwd().openDir(node.path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const fh = self.allocateDirHandle(header.nodeid, dir) catch {
            var d = dir;
            d.close();
            return self.sendError(header, -12, response_buf);
        };

        return self.sendOpenOut(header, fh, response_buf);
    }

    fn handleReaddir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseReadIn)) {
            return self.sendError(header, -22, response_buf);
        }

        var read_in: FuseReadIn = undefined;
        @memcpy(std.mem.asBytes(&read_in), payload[0..@sizeOf(FuseReadIn)]);

        const handle = self.handles.get(read_in.fh) orelse {
            return self.sendError(header, -9, response_buf);
        };
        const dir = handle.dir orelse return self.sendError(header, -9, response_buf);

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size) {
            return VirtioFsError.IoError;
        }
        const max_data = @min(read_in.size, @as(u32, @intCast(response_buf.len - out_header_size)));

        // Only support offset=0 in this stub.
        if (read_in.offset != 0) {
            const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
            out_header.len = @intCast(out_header_size);
            out_header.@"error" = 0;
            out_header.unique = header.unique;
            return out_header_size;
        }

        const DT_DIR: u32 = 4;
        const DT_REG: u32 = 8;

        var pos: usize = out_header_size;
        var d = dir;
        var it = d.iterate();
        while (true) {
            const entry = it.next() catch return self.sendError(header, -5, response_buf);
            if (entry == null) break;
            const entry_val = entry.?;
            const name_len: u32 = @intCast(entry_val.name.len);
            const entry_size = @sizeOf(FuseDirent) + entry_val.name.len;
            const padded_size = std.mem.alignForward(usize, entry_size, 8);
            if (pos + padded_size > out_header_size + max_data) break;

            var dirent = FuseDirent{
                .ino = 1,
                .off = 0,
                .namelen = name_len,
                .@"type" = switch (entry_val.kind) {
                    .directory => DT_DIR,
                    .file => DT_REG,
                    else => 0,
                },
            };
            @memcpy(response_buf[pos..][0..@sizeOf(FuseDirent)], std.mem.asBytes(&dirent));
            @memcpy(
                response_buf[pos + @sizeOf(FuseDirent) ..][0..entry_val.name.len],
                entry_val.name,
            );
            @memset(
                response_buf[pos + entry_size ..][0..(padded_size - entry_size)],
                0,
            );
            pos += padded_size;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(pos);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        return pos;
    }

    fn handleReleasedir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseReleaseIn)) {
            return self.sendError(header, -22, response_buf);
        }

        var release_in: FuseReleaseIn = undefined;
        @memcpy(std.mem.asBytes(&release_in), payload[0..@sizeOf(FuseReleaseIn)]);

        if (self.handles.fetchRemove(release_in.fh)) |kv| {
            if (kv.value.dir) |*d| {
                var dir = d.*;
                dir.close();
            }
        }

        return self.sendError(header, 0, response_buf);
    }

    fn handleDestroy(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @sizeOf(FuseOutHeader);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        return @sizeOf(FuseOutHeader);
    }

    fn sendError(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        err: i32,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        if (response_buf.len < @sizeOf(FuseOutHeader)) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @sizeOf(FuseOutHeader);
        out_header.@"error" = err;
        out_header.unique = header.unique;

        return @sizeOf(FuseOutHeader);
    }

    fn sendAttrOut(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        stat: *const std.fs.File.Stat,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseAttrOut);
        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const attr_out: *FuseAttrOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        attr_out.attr_valid = 1;
        attr_out.attr_valid_nsec = 0;
        attr_out.dummy = 0;
        attr_out.attr = statToFuseAttr(header.nodeid, stat);

        return total_size;
    }

    fn sendEntryOut(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        nodeid: u64,
        stat: *const std.fs.File.Stat,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut);
        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const entry_out: *FuseEntryOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        entry_out.nodeid = nodeid;
        entry_out.generation = 1;
        entry_out.entry_valid = 1;
        entry_out.attr_valid = 1;
        entry_out.entry_valid_nsec = 0;
        entry_out.attr_valid_nsec = 0;
        entry_out.attr = statToFuseAttr(nodeid, stat);

        return total_size;
    }

    fn sendOpenOut(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        fh: u64,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut);
        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const open_out: *FuseOpenOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        open_out.fh = fh;
        open_out.open_flags = 0;
        open_out.padding = 0;

        return total_size;
    }

    fn sendWriteOut(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        size: u32,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = self;
        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseWriteOut);
        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const write_out: *FuseWriteOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        write_out.size = size;
        write_out.padding = 0;

        return total_size;
    }

    fn allocateNode(self: *VirtioFsDevice, path: []const u8, is_dir: bool) !u64 {
        // Nodes are reference-counted by kernel; we store path and type.
        const nodeid = self.next_nodeid;
        self.next_nodeid += 1;

        const owned_path = try self.allocator.dupe(u8, path);
        try self.nodes.put(nodeid, .{
            .inode = nodeid,
            .path = owned_path,
            .is_dir = is_dir,
        });

        return nodeid;
    }

    fn allocateFileHandle(self: *VirtioFsDevice, nodeid: u64, file: std.fs.File) !u64 {
        const fh = self.next_fh;
        self.next_fh += 1;

        const node = self.nodes.getPtr(nodeid) orelse return error.InvalidHandle;
        try self.handles.put(fh, .{
            .handle_id = fh,
            .node = node,
            .file = file,
            .dir = null,
        });

        return fh;
    }

    fn allocateDirHandle(self: *VirtioFsDevice, nodeid: u64, dir: std.fs.Dir) !u64 {
        const fh = self.next_fh;
        self.next_fh += 1;

        const node = self.nodes.getPtr(nodeid) orelse return error.InvalidHandle;
        try self.handles.put(fh, .{
            .handle_id = fh,
            .node = node,
            .file = null,
            .dir = dir,
        });

        return fh;
    }
};

fn statToFuseAttr(nodeid: u64, stat: *const std.fs.File.Stat) FuseAttr {
    var mode: u32 = 0o644;
    if (stat.kind == .directory) {
        mode = 0o755 | 0o040000;
    } else {
        mode = 0o644 | 0o100000;
    }

    return .{
        .ino = nodeid,
        .size = stat.size,
        .blocks = (stat.size + 511) / 512,
        .atime = @intCast(@divFloor(stat.atime, std.time.ns_per_s)),
        .mtime = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
        .ctime = @intCast(@divFloor(stat.ctime, std.time.ns_per_s)),
        .atimensec = @intCast(@mod(stat.atime, std.time.ns_per_s)),
        .mtimensec = @intCast(@mod(stat.mtime, std.time.ns_per_s)),
        .ctimensec = @intCast(@mod(stat.ctime, std.time.ns_per_s)),
        .mode = mode,
        .nlink = 1,
        .uid = 0,
        .gid = 0,
        .rdev = 0,
        .blksize = 4096,
        .padding = 0,
    };
}

// =============================================================================
// TESTS
// =============================================================================

test "virtio_fs: FuseOpcode fromInt" {
    try std.testing.expectEqual(FuseOpcode.FUSE_INIT, FuseOpcode.fromInt(26));
    try std.testing.expectEqual(FuseOpcode.FUSE_LOOKUP, FuseOpcode.fromInt(1));
    try std.testing.expectEqual(FuseOpcode.FUSE_READ, FuseOpcode.fromInt(15));
}

test "virtio_fs: VirtioFsDevice init/deinit" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    try std.testing.expectEqual(@as(u64, 2), device.next_nodeid);
    try std.testing.expectEqual(@as(u64, 1), device.next_fh);
}

test "virtio_fs: FuseInHeader size" {
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(FuseInHeader));
}

test "virtio_fs: FuseOutHeader size" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(FuseOutHeader));
}

test "virtio_fs: handleInit" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var request: [@sizeOf(FuseInHeader) + @sizeOf(FuseInitIn)]u8 = undefined;
    const header: *FuseInHeader = @ptrCast(@alignCast(&request));
    header.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseInitIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_INIT),
        .unique = 1,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    const init_in: *FuseInitIn = @ptrCast(@alignCast(request[@sizeOf(FuseInHeader)..]));
    init_in.* = .{
        .major = 7,
        .minor = 31,
        .max_readahead = 131072,
        .flags = 0,
    };

    var response: [256]u8 = undefined;
    const len = try device.handleRequest(&request, &response);

    try std.testing.expect(len >= @sizeOf(FuseOutHeader));

    const out_header: *const FuseOutHeader = @ptrCast(@alignCast(&response));
    try std.testing.expectEqual(@as(i32, 0), out_header.@"error");
    try std.testing.expectEqual(@as(u64, 1), out_header.unique);
}

test "virtio_fs: handleInit accepts unaligned request" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var request_buf: [@sizeOf(FuseInHeader) + @sizeOf(FuseInitIn) + 1]u8 = undefined;
    const request = request_buf[1..];

    var header = FuseInHeader{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseInitIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_INIT),
        .unique = 101,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    @memcpy(request[0..@sizeOf(FuseInHeader)], std.mem.asBytes(&header));

    var init_in = FuseInitIn{
        .major = 7,
        .minor = 31,
        .max_readahead = 131072,
        .flags = 0,
    };
    @memcpy(
        request[@sizeOf(FuseInHeader)..][0..@sizeOf(FuseInitIn)],
        std.mem.asBytes(&init_in),
    );

    var response: [256]u8 = undefined;
    const len = try device.handleRequest(request, &response);
    try std.testing.expect(len >= @sizeOf(FuseOutHeader));

    const out_header: *const FuseOutHeader = @ptrCast(@alignCast(&response));
    try std.testing.expectEqual(@as(i32, 0), out_header.@"error");
    try std.testing.expectEqual(@as(u64, 101), out_header.unique);
}

test "virtio_fs: lookup open read write release roundtrip" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("hi");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    // LOOKUP
    const name_len = abs.len;
    const lookup_len = @sizeOf(FuseInHeader) + name_len + 1;
    const lookup_req = try allocator.alloc(u8, lookup_len);
    defer allocator.free(lookup_req);

    const lookup_hdr: *FuseInHeader = @ptrCast(@alignCast(lookup_req.ptr));
    lookup_hdr.* = .{
        .len = @intCast(lookup_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_LOOKUP),
        .unique = 11,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    @memcpy(lookup_req[@sizeOf(FuseInHeader)..][0..name_len], abs);
    lookup_req[@sizeOf(FuseInHeader) + name_len] = 0;

    var lookup_resp: [512]u8 = undefined;
    const lookup_resp_len = try device.handleRequest(lookup_req, &lookup_resp);
    try std.testing.expect(lookup_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut));

    const lookup_out: *const FuseOutHeader = @ptrCast(@alignCast(&lookup_resp));
    try std.testing.expectEqual(@as(i32, 0), lookup_out.@"error");
    const entry_out: *const FuseEntryOut = @ptrCast(@alignCast(lookup_resp[@sizeOf(FuseOutHeader)..]));
    const nodeid = entry_out.nodeid;
    try std.testing.expectEqual(@as(u64, 2), nodeid);
    try std.testing.expectEqual(@as(u64, 2), entry_out.attr.size);

    // OPEN
    var open_req: [@sizeOf(FuseInHeader)]u8 = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 12,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    var open_resp: [256]u8 = undefined;
    const open_resp_len = try device.handleRequest(&open_req, &open_resp);
    try std.testing.expect(open_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut));
    const open_out: *const FuseOpenOut = @ptrCast(@alignCast(open_resp[@sizeOf(FuseOutHeader)..]));
    const fh = open_out.fh;

    // WRITE "abc"
    const write_data = "abc";
    const write_len = @sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) + write_data.len;
    const write_req = try allocator.alloc(u8, write_len);
    defer allocator.free(write_req);
    const write_hdr: *FuseInHeader = @ptrCast(@alignCast(write_req.ptr));
    write_hdr.* = .{
        .len = @intCast(write_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_WRITE),
        .unique = 13,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const write_in: *FuseWriteIn = @ptrCast(@alignCast(write_req[@sizeOf(FuseInHeader)..]));
    write_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = @intCast(write_data.len),
        .write_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    @memcpy(write_req[@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn)..][0..write_data.len], write_data);
    var write_resp: [256]u8 = undefined;
    const write_resp_len = try device.handleRequest(write_req, &write_resp);
    try std.testing.expect(write_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseWriteOut));
    const write_out: *const FuseWriteOut = @ptrCast(@alignCast(write_resp[@sizeOf(FuseOutHeader)..]));
    try std.testing.expectEqual(@as(u32, 3), write_out.size);

    // READ back "abc"
    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 14,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const read_in: *FuseReadIn = @ptrCast(@alignCast(read_req[@sizeOf(FuseInHeader)..]));
    read_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = 3,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    var read_resp: [256]u8 = undefined;
    const read_resp_len = try device.handleRequest(&read_req, &read_resp);
    try std.testing.expect(read_resp_len >= @sizeOf(FuseOutHeader) + 3);
    try std.testing.expectEqualStrings(
        "abc",
        read_resp[@sizeOf(FuseOutHeader)..][0..3],
    );

    // RELEASE
    const release_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReleaseIn);
    var release_req: [release_len]u8 = undefined;
    const release_hdr: *FuseInHeader = @ptrCast(@alignCast(&release_req));
    release_hdr.* = .{
        .len = release_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_RELEASE),
        .unique = 15,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const release_in: *FuseReleaseIn = @ptrCast(@alignCast(release_req[@sizeOf(FuseInHeader)..]));
    release_in.* = .{
        .fh = fh,
        .flags = 0,
        .release_flags = 0,
        .lock_owner = 0,
    };
    var release_resp: [256]u8 = undefined;
    const release_resp_len = try device.handleRequest(&release_req, &release_resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), release_resp_len);

    // READ after release should fail with EBADF (-9).
    var read_again_resp: [256]u8 = undefined;
    const read_again_len = try device.handleRequest(&read_req, &read_again_resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), read_again_len);
    const read_again_out: *const FuseOutHeader = @ptrCast(@alignCast(&read_again_resp));
    try std.testing.expectEqual(@as(i32, -9), read_again_out.@"error");
}

test "virtio_fs: lookup rejects traversal" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const name = "..";
    const req_len = @sizeOf(FuseInHeader) + name.len + 1;
    const req = try allocator.alloc(u8, req_len);
    defer allocator.free(req);

    const hdr: *FuseInHeader = @ptrCast(@alignCast(req.ptr));
    hdr.* = .{
        .len = @intCast(req_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_LOOKUP),
        .unique = 21,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    @memcpy(req[@sizeOf(FuseInHeader)..][0..name.len], name);
    req[@sizeOf(FuseInHeader) + name.len] = 0;

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -1), out.@"error");
}

test "virtio_fs: read rejects short payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + 2]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @intCast(req.len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 31,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: handleOpen returns not found for missing node" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 32,
        .nodeid = 999,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -2), out.@"error");
}

test "virtio_fs: handleRead rejects invalid handle" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 41,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const read_in: *FuseReadIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    read_in.* = .{
        .fh = 999,
        .offset = 0,
        .size = 1,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -9), out.@"error");
}

test "virtio_fs: handleRead errors on short response buffer" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try std.fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file);

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 91,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const read_in: *FuseReadIn = @ptrCast(@alignCast(read_req[@sizeOf(FuseInHeader)..]));
    read_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = 1,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };

    var small_resp: [8]u8 = undefined;
    try std.testing.expectError(VirtioFsError.IoError, device.handleRequest(&read_req, &small_resp));
}

test "virtio_fs: handleWrite rejects short payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) - 1]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_WRITE),
        .unique = 51,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: handleRead maps io error on write-only file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try std.fs.cwd().openFile(abs, .{ .mode = .write_only });
    const fh = try device.allocateFileHandle(nodeid, file);

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 111,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const read_in: *FuseReadIn = @ptrCast(@alignCast(read_req[@sizeOf(FuseInHeader)..]));
    read_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = 1,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&read_req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -5), out.@"error");

    _ = device.handles.fetchRemove(fh);
}

test "virtio_fs: handleWrite maps io error on read-only file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try std.fs.cwd().openFile(abs, .{ .mode = .read_only });
    const fh = try device.allocateFileHandle(nodeid, file);

    const write_data = "x";
    const write_len = @sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) + write_data.len;
    const write_req = try allocator.alloc(u8, write_len);
    defer allocator.free(write_req);

    const write_hdr: *FuseInHeader = @ptrCast(@alignCast(write_req.ptr));
    write_hdr.* = .{
        .len = @intCast(write_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_WRITE),
        .unique = 112,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const write_in: *FuseWriteIn = @ptrCast(@alignCast(write_req[@sizeOf(FuseInHeader)..]));
    write_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = @intCast(write_data.len),
        .write_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    @memcpy(
        write_req[@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn)..][0..write_data.len],
        write_data,
    );

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(write_req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -5), out.@"error");

    _ = device.handles.fetchRemove(fh);
}

test "virtio_fs: handleOpendir rejects non-dir node" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);

    var req: [@sizeOf(FuseInHeader)]u8 = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPENDIR),
        .unique = 61,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -20), out.@"error");
}

test "virtio_fs: handleReleasedir rejects short payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + 1]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_RELEASEDIR),
        .unique = 62,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: handleRelease closes file handle" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try std.fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file);
    try std.testing.expect(device.handles.contains(fh));

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseReleaseIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_RELEASE),
        .unique = 71,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const release_in: *FuseReleaseIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    release_in.* = .{
        .fh = fh,
        .flags = 0,
        .release_flags = 0,
        .lock_owner = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    try std.testing.expect(!device.handles.contains(fh));
}

test "virtio_fs: handleReaddir rejects short payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + 2]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READDIR),
        .unique = 81,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: handleReaddir returns entries" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("data");
    {
        var f = try tmp.dir.createFile("data/a.txt", .{});
        defer f.close();
        try f.writeAll("a");
    }
    {
        var f = try tmp.dir.createFile("data/b.txt", .{});
        defer f.close();
        try f.writeAll("b");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "data");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test");
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, true);

    // OPENDIR
    var open_req: [@sizeOf(FuseInHeader)]u8 = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPENDIR),
        .unique = 201,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };

    var open_resp: [256]u8 = undefined;
    const open_resp_len = try device.handleRequest(&open_req, &open_resp);
    try std.testing.expect(open_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut));
    const open_out: *const FuseOpenOut = @ptrCast(@alignCast(open_resp[@sizeOf(FuseOutHeader)..]));
    const fh = open_out.fh;

    // READDIR
    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READDIR),
        .unique = 202,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .padding = 0,
    };
    const read_in: *FuseReadIn = @ptrCast(@alignCast(read_req[@sizeOf(FuseInHeader)..]));
    read_in.* = .{
        .fh = fh,
        .offset = 0,
        .size = 512,
        .read_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };

    var read_resp: [512]u8 = undefined;
    const read_resp_len = try device.handleRequest(&read_req, &read_resp);
    try std.testing.expect(read_resp_len >= @sizeOf(FuseOutHeader));

    var found_a = false;
    var found_b = false;
    var pos: usize = @sizeOf(FuseOutHeader);
    while (pos + @sizeOf(FuseDirent) <= read_resp_len) {
        var dirent: FuseDirent = undefined;
        @memcpy(
            std.mem.asBytes(&dirent),
            read_resp[pos..][0..@sizeOf(FuseDirent)],
        );
        const name_start = pos + @sizeOf(FuseDirent);
        const name_end = name_start + dirent.namelen;
        if (name_end > read_resp_len) break;
        const name = read_resp[name_start..name_end];
        if (std.mem.eql(u8, name, "a.txt")) found_a = true;
        if (std.mem.eql(u8, name, "b.txt")) found_b = true;

        const entry_size = @sizeOf(FuseDirent) + dirent.namelen;
        const entry_end = pos + entry_size;
        pos = std.mem.alignForward(usize, entry_end, 8);
    }

    try std.testing.expect(found_a and found_b);
}

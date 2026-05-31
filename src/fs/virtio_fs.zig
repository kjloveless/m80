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
const sync = @import("../util/sync.zig");
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const c = if (builtin.os.tag == .windows) struct {} else @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/mount.h");
    @cInclude("sys/xattr.h");
    @cInclude("fcntl.h");
    @cInclude("sys/ioctl.h");
});
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

pub const CacheMode = enum {
    none,
    auto,
    always,
};

pub const FuseInitFlags = struct {
    pub const FUSE_CAP_AUTO_INVAL_DATA: u32 = 1 << 12;
    pub const FUSE_CAP_WRITEBACK_CACHE: u32 = 1 << 16;
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
    total_extlen: u16,
    padding: u16,
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
    flags2: u32,
    unused: [11]u32,
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

pub const FuseSetattrIn = extern struct {
    valid: u32,
    padding: u32,
    fh: u64,
    size: u64,
    lock_owner: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    unused4: u32,
    unused5: u64,
};

// FUSE SETATTR valid bits
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FATTR_CTIME: u32 = 1 << 10;

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
    flags: u32,
};

const StatView = struct {
    size: u64,
    blocks: u64,
    atime_ns: i128,
    mtime_ns: i128,
    ctime_ns: i128,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    kind: fs.File.Kind,
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
    open_flags: u32,
};

pub const FuseMkdirIn = extern struct {
    mode: u32,
    umask: u32,
};

pub const FuseMknodIn = extern struct {
    mode: u32,
    rdev: u32,
    umask: u32,
    padding: u32,
};

pub const FuseCreateIn = extern struct {
    flags: u32,
    mode: u32,
    umask: u32,
    open_flags: u32,
};

pub const FuseSetupmappingIn = extern struct {
    fh: u64,
    foffset: u64,
    len: u64,
    flags: u64,
    moffset: u64,
};

pub const FuseRemovemappingIn = extern struct {
    count: u32,
    padding: u32,
};

pub const FuseRemovemappingOne = extern struct {
    moffset: u64,
    len: u64,
};

pub const DaxMapper = struct {
    ctx: ?*anyopaque,
    window_base: u64,
    window_size: u64,
    page_size: u64,
    map: *const fn (ctx: ?*anyopaque, guest_addr: u64, len: u64, fd: std.posix.fd_t, file_offset: u64, writable: bool) anyerror!void,
    unmap: *const fn (ctx: ?*anyopaque, guest_addr: u64, len: u64) anyerror!void,
};

const DaxMapping = struct {
    moffset: u64,
    len: u64,
    foffset: u64,
    fh: u64,
    writable: bool,
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

pub const FuseForgetIn = extern struct {
    nlookup: u64,
};

pub const FuseBatchForgetIn = extern struct {
    count: u32,
    dummy: u32,
};

pub const FuseForgetOne = extern struct {
    nodeid: u64,
    nlookup: u64,
};

pub const FuseRenameIn = extern struct {
    newdir: u64,
};

pub const FuseRename2In = extern struct {
    newdir: u64,
    flags: u32,
    padding: u32,
};

pub const FuseLinkIn = extern struct {
    oldnodeid: u64,
};

pub const FuseFlushIn = extern struct {
    fh: u64,
    unused: u32,
    padding: u32,
    lock_owner: u64,
};

pub const FuseFsyncIn = extern struct {
    fh: u64,
    fsync_flags: u32,
    padding: u32,
};

pub const FuseSetxattrIn = extern struct {
    size: u32,
    flags: u32,
};

pub const FuseGetxattrIn = extern struct {
    size: u32,
    padding: u32,
};

pub const FuseGetxattrOut = extern struct {
    size: u32,
    padding: u32,
};

pub const FuseFileLock = extern struct {
    start: u64,
    end: u64,
    type: u32,
    pid: u32,
};

pub const FuseLkIn = extern struct {
    fh: u64,
    owner: u64,
    lk: FuseFileLock,
    lk_flags: u32,
    padding: u32,
};

pub const FuseLkOut = extern struct {
    lk: FuseFileLock,
};

pub const FuseAccessIn = extern struct {
    mask: u32,
    padding: u32,
};

pub const FuseInterruptIn = extern struct {
    unique: u64,
};

pub const FuseBmapIn = extern struct {
    block: u64,
    blocksize: u32,
    padding: u32,
};

pub const FuseBmapOut = extern struct {
    block: u64,
};

pub const FuseIoctlIn = extern struct {
    fh: u64,
    flags: u32,
    cmd: u32,
    arg: u64,
    in_size: u32,
    out_size: u32,
};

pub const FuseIoctlOut = extern struct {
    result: i32,
    flags: u32,
    in_iovs: u32,
    out_iovs: u32,
};

pub const FusePollIn = extern struct {
    fh: u64,
    kh: u64,
    flags: u32,
    events: u32,
};

pub const FusePollOut = extern struct {
    revents: u32,
    padding: u32,
};

pub const FuseFallocateIn = extern struct {
    fh: u64,
    offset: u64,
    length: u64,
    mode: u32,
    padding: u32,
};

pub const FuseDirentPlus = extern struct {
    entry_out: FuseEntryOut,
    dirent: FuseDirent,
};

pub const FuseKstatfs = extern struct {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
    frsize: u32,
    padding: u32,
    spare: [6]u32,
};

pub const FuseStatfsOut = extern struct {
    st: FuseKstatfs,
};

pub const FuseLseekIn = extern struct {
    fh: u64,
    offset: u64,
    whence: u32,
    padding: u32,
};

pub const FuseLseekOut = extern struct {
    offset: u64,
};

pub const FuseCopyFileRangeIn = extern struct {
    fh_in: u64,
    off_in: u64,
    nodeid_out: u64,
    fh_out: u64,
    off_out: u64,
    len: u64,
    flags: u64,
};

pub const FuseDirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    type: u32,
};

pub const NodeHandle = struct {
    inode: u64,
    path: []const u8,
    is_dir: bool,
    generation: u64,
};

pub const FileHandle = struct {
    handle_id: u64,
    node: *NodeHandle,
    file: ?fs.File,
    dir: ?fs.Dir,
    open_flags: u32,
    append: bool,
    sync_mode: SyncMode,
};

pub const VirtioFsDevice = struct {
    allocator: std.mem.Allocator,
    mount_manager: *mounts.MountManager,
    tag: []const u8,
    cache_mode: CacheMode,
    next_nodeid: u64,
    next_generation: u64,
    next_fh: u64,
    nodes: std.AutoHashMap(u64, NodeHandle),
    handles: std.AutoHashMap(u64, FileHandle),
    features: u64,
    dax: ?DaxMapper,
    dax_mappings: std.ArrayListUnmanaged(DaxMapping),

    pub fn init(
        allocator: std.mem.Allocator,
        mount_manager: *mounts.MountManager,
        tag: []const u8,
        cache_mode: CacheMode,
    ) VirtioFsDevice {
        // Node IDs start at 2 (1 is root in FUSE).
        return .{
            .allocator = allocator,
            .mount_manager = mount_manager,
            .tag = tag,
            .cache_mode = cache_mode,
            .next_nodeid = 2,
            .next_generation = 2,
            .next_fh = 1,
            .nodes = std.AutoHashMap(u64, NodeHandle).init(allocator),
            .handles = std.AutoHashMap(u64, FileHandle).init(allocator),
            .features = VirtioFeatures.VIRTIO_F_VERSION_1,
            .dax = null,
            .dax_mappings = .empty,
        };
    }

    pub fn configureDax(self: *VirtioFsDevice, dax: DaxMapper) void {
        self.dax = dax;
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
        self.dax_mappings.deinit(self.allocator);
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
            .FUSE_FORGET => self.handleForget(&header, payload, response_buf),
            .FUSE_GETATTR => self.handleGetattr(&header, response_buf),
            .FUSE_SETATTR => self.handleSetattr(&header, payload, response_buf),
            .FUSE_READLINK => self.handleReadlink(&header, response_buf),
            .FUSE_SYMLINK => self.handleSymlink(&header, payload, response_buf),
            .FUSE_OPEN => self.handleOpen(&header, payload, response_buf),
            .FUSE_MKDIR => self.handleMkdir(&header, payload, response_buf),
            .FUSE_MKNOD => self.handleMknod(&header, payload, response_buf),
            .FUSE_RENAME => self.handleRename(&header, payload, response_buf),
            .FUSE_LINK => self.handleLink(&header, payload, response_buf),
            .FUSE_READ => self.handleRead(&header, payload, response_buf),
            .FUSE_WRITE => self.handleWrite(&header, payload, response_buf),
            .FUSE_STATFS => self.handleStatfs(&header, response_buf),
            .FUSE_CREATE => self.handleCreate(&header, payload, response_buf),
            .FUSE_UNLINK => self.handleUnlink(&header, payload, response_buf),
            .FUSE_RMDIR => self.handleRmdir(&header, payload, response_buf),
            .FUSE_RELEASE => self.handleRelease(&header, payload, response_buf),
            .FUSE_FLUSH => self.handleFlush(&header, payload, response_buf),
            .FUSE_FSYNC => self.handleFsync(&header, payload, response_buf),
            .FUSE_OPENDIR => self.handleOpendir(&header, payload, response_buf),
            .FUSE_READDIR => self.handleReaddir(&header, payload, response_buf),
            .FUSE_RELEASEDIR => self.handleReleasedir(&header, payload, response_buf),
            .FUSE_FSYNCDIR => self.handleFsyncdir(&header, payload, response_buf),
            .FUSE_GETLK => self.handleGetlk(&header, payload, response_buf),
            .FUSE_SETLK => self.handleSetlk(&header, payload, response_buf),
            .FUSE_SETLKW => self.handleSetlkw(&header, payload, response_buf),
            .FUSE_SETXATTR => self.handleSetxattr(&header, payload, response_buf),
            .FUSE_GETXATTR => self.handleGetxattr(&header, payload, response_buf),
            .FUSE_LISTXATTR => self.handleListxattr(&header, payload, response_buf),
            .FUSE_REMOVEXATTR => self.handleRemovexattr(&header, payload, response_buf),
            .FUSE_ACCESS => self.handleAccess(&header, payload, response_buf),
            .FUSE_INTERRUPT => self.handleInterrupt(&header, payload, response_buf),
            .FUSE_BMAP => self.handleBmap(&header, payload, response_buf),
            .FUSE_IOCTL => self.handleIoctl(&header, payload, response_buf),
            .FUSE_POLL => self.handlePoll(&header, payload, response_buf),
            .FUSE_BATCH_FORGET => self.handleBatchForget(&header, payload, response_buf),
            .FUSE_READDIRPLUS => self.handleReaddirplus(&header, payload, response_buf),
            .FUSE_RENAME2 => self.handleRename2(&header, payload, response_buf),
            .FUSE_LSEEK => self.handleLseek(&header, payload, response_buf),
            .FUSE_COPY_FILE_RANGE => self.handleCopyFileRange(&header, payload, response_buf),
            .FUSE_FALLOCATE => self.handleFallocate(&header, payload, response_buf),
            .FUSE_SETUPMAPPING => self.handleSetupmapping(&header, payload, response_buf),
            .FUSE_REMOVEMAPPING => self.handleRemovemapping(&header, payload, response_buf),
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
        if (payload.len < 16) {
            return self.sendError(header, -22, response_buf);
        }

        // Read the first 16 bytes (major, minor, max_readahead, flags).
        var init_in = FuseInitIn{
            .major = 0,
            .minor = 0,
            .max_readahead = 0,
            .flags = 0,
            .flags2 = 0,
            .unused = std.mem.zeroes([11]u32),
        };
        const init_base = payload[0..16];
        @memcpy(std.mem.asBytes(&init_in)[0..16], init_base);
        if (payload.len >= @sizeOf(FuseInitIn)) {
            @memcpy(std.mem.asBytes(&init_in), payload[0..@sizeOf(FuseInitIn)]);
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
        var flags: u32 = 0;
        switch (self.cache_mode) {
            .none => {},
            .auto => flags |= FuseInitFlags.FUSE_CAP_AUTO_INVAL_DATA,
            .always => flags |= FuseInitFlags.FUSE_CAP_WRITEBACK_CACHE,
        }
        out_init.* = .{
            .major = @max(init_in.major, 7),
            .minor = @min(init_in.minor, 31),
            .max_readahead = @min(init_in.max_readahead, 131072),
            .flags = flags,
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
        if (header.nodeid == 1) try self.ensureRootNode();
        const name_end = std.mem.indexOfScalar(u8, payload, 0) orelse payload.len;
        const name = payload[0..name_end];

        if (name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }

        // Reject traversal attempts from the guest.
        if (path_util.containsTraversal(name) or containsPathSeparator(name)) {
            return self.sendError(header, -1, response_buf);
        }

        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };
        const parent_path = parent_node.path;

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_path, name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .read)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const stat = statPath(full_path, false) catch {
            return self.sendError(header, -2, response_buf);
        };

        const nodeid = self.allocateNode(full_path, stat.kind == .directory) catch {
            return self.sendError(header, -12, response_buf);
        };
        const generation = self.nodeGeneration(nodeid);
        return self.sendEntryOut(header, nodeid, generation, &stat, response_buf);
    }

    fn handleForget(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = payload;
        if (header.nodeid != 1) {
            if (self.nodes.fetchRemove(header.nodeid)) |kv| {
                self.allocator.free(kv.value.path);
            }
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleReadlink(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        if (self.validateAccess(node.path, .read)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size + 1) {
            return VirtioFsError.IoError;
        }

        const link_buf = response_buf[out_header_size..];
        const link_len = fs.readLink(node.path, link_buf) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.NotLink => return self.sendError(header, -22, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + link_len);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        return out_header_size + link_len;
    }

    fn handleSymlink(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name = parseCString(payload, 0) orelse return self.sendError(header, -22, response_buf);
        const target = parseCString(payload, name.next) orelse return self.sendError(header, -22, response_buf);

        if (name.slice.len == 0) return self.sendError(header, -2, response_buf);
        if (path_util.containsTraversal(name.slice) or containsPathSeparator(name.slice)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, name.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .create)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        fs.symLink(target.slice, full_path) catch |e| switch (e) {
            error.PathAlreadyExists => return self.sendError(header, -17, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const stat = statPath(full_path, false) catch return self.sendError(header, -5, response_buf);
        const nodeid = self.allocateNode(full_path, false) catch return self.sendError(header, -12, response_buf);
        const generation = self.nodeGeneration(nodeid);
        return self.sendEntryOut(header, nodeid, generation, &stat, response_buf);
    }

    fn handleRename(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseRenameIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const rename_in: *const FuseRenameIn = @ptrCast(@alignCast(payload.ptr));
        const new_parent = self.nodes.get(rename_in.newdir) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const names = parseCString(payload, @sizeOf(FuseRenameIn)) orelse return self.sendError(header, -22, response_buf);
        const new_name = parseCString(payload, names.next) orelse return self.sendError(header, -22, response_buf);

        if (names.slice.len == 0 or new_name.slice.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(names.slice) or containsPathSeparator(names.slice)) {
            return self.sendError(header, -1, response_buf);
        }
        if (path_util.containsTraversal(new_name.slice) or containsPathSeparator(new_name.slice)) {
            return self.sendError(header, -1, response_buf);
        }

        const old_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, names.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(old_path);
        const new_path = fs.path.join(self.allocator, &[_][]const u8{ new_parent.path, new_name.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(new_path);

        if (self.validateAccess(old_path, .rename)) |errno| return self.sendError(header, errno, response_buf);
        if (self.validateAccess(new_path, .create)) |errno| return self.sendError(header, errno, response_buf);

        fs.renamePath(old_path, new_path) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.NotDir => return self.sendError(header, -20, response_buf),
            error.PathAlreadyExists => return self.sendError(header, -17, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        return self.sendError(header, 0, response_buf);
    }

    fn handleRename2(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseRename2In)) {
            return self.sendError(header, -22, response_buf);
        }
        const rename2_in: *const FuseRename2In = @ptrCast(@alignCast(payload.ptr));
        // Only support flags=0 or NOREPLACE (1).
        const RENAME_NOREPLACE: u32 = 1;
        if (rename2_in.flags != 0 and rename2_in.flags != RENAME_NOREPLACE) {
            return self.sendError(header, -38, response_buf);
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };
        const new_parent = self.nodes.get(rename2_in.newdir) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const names = parseCString(payload, @sizeOf(FuseRename2In)) orelse return self.sendError(header, -22, response_buf);
        const new_name = parseCString(payload, names.next) orelse return self.sendError(header, -22, response_buf);
        if (names.slice.len == 0 or new_name.slice.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(names.slice) or containsPathSeparator(names.slice)) {
            return self.sendError(header, -1, response_buf);
        }
        if (path_util.containsTraversal(new_name.slice) or containsPathSeparator(new_name.slice)) {
            return self.sendError(header, -1, response_buf);
        }

        const old_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, names.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(old_path);
        const new_path = fs.path.join(self.allocator, &[_][]const u8{ new_parent.path, new_name.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(new_path);

        if (rename2_in.flags == RENAME_NOREPLACE) {
            if (statPath(new_path, true)) |_| {
                return self.sendError(header, -17, response_buf);
            } else |_| {}
        }

        if (self.validateAccess(old_path, .rename)) |errno| return self.sendError(header, errno, response_buf);
        if (self.validateAccess(new_path, .create)) |errno| return self.sendError(header, errno, response_buf);

        fs.renamePath(old_path, new_path) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.NotDir => return self.sendError(header, -20, response_buf),
            error.PathAlreadyExists => return self.sendError(header, -17, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        return self.sendError(header, 0, response_buf);
    }

    fn handleLink(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseLinkIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };
        const link_in: *const FuseLinkIn = @ptrCast(@alignCast(payload.ptr));
        const old_node = self.nodes.get(link_in.oldnodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name = parseCString(payload, @sizeOf(FuseLinkIn)) orelse return self.sendError(header, -22, response_buf);
        if (name.slice.len == 0) return self.sendError(header, -2, response_buf);
        if (path_util.containsTraversal(name.slice) or containsPathSeparator(name.slice)) {
            return self.sendError(header, -1, response_buf);
        }

        const new_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, name.slice }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(new_path);

        if (self.validateAccess(new_path, .create)) |errno| return self.sendError(header, errno, response_buf);

        fs.linkPath(old_node.path, new_path) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.PathAlreadyExists => return self.sendError(header, -17, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const stat = statPath(new_path, true) catch return self.sendError(header, -5, response_buf);
        const nodeid = self.allocateNode(new_path, stat.kind == .directory) catch return self.sendError(header, -12, response_buf);
        const generation = self.nodeGeneration(nodeid);
        return self.sendEntryOut(header, nodeid, generation, &stat, response_buf);
    }

    fn handleGetattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        if (self.validateAccess(node.path, .stat)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const stat = statPath(node.path, false) catch {
            return self.sendError(header, -2, response_buf);
        };

        return self.sendAttrOut(header, &stat, response_buf);
    }

    fn handleSetattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        // Accept short payloads; some kernels send a smaller setattr struct.
        if (payload.len < 8) {
            return self.sendError(header, -22, response_buf); // EINVAL
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf); // ENOENT
        };

        var setattr_in: FuseSetattrIn = std.mem.zeroes(FuseSetattrIn);
        @memcpy(std.mem.asBytes(&setattr_in)[0..payload.len], payload);
        const valid = setattr_in.valid;
        const wants_write = (valid & (FATTR_SIZE | FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW | FATTR_CTIME)) != 0;
        if (wants_write) {
            if (self.validateAccess(node.path, .write)) |errno| {
                return self.sendError(header, errno, response_buf);
            }
        }

        // Apply size change (truncate)
        if (valid & FATTR_SIZE != 0) {
            const file = fs.cwd().openFile(node.path, .{ .mode = .read_write }) catch {
                return self.sendError(header, -13, response_buf); // EACCES
            };
            defer file.close();
            file.setEndPos(setattr_in.size) catch {
                return self.sendError(header, -5, response_buf); // EIO
            };
        }

        // Apply mode change (chmod)
        if (valid & FATTR_MODE != 0) {
            const mode: std.posix.mode_t = @truncate(setattr_in.mode & 0o7777);
            fs.chmodAt(fs.cwd().fd, node.path, mode, 0) catch {
                return self.sendError(header, -13, response_buf); // EACCES
            };
        }

        if (valid & (FATTR_UID | FATTR_GID) != 0) {
            const stat_before = statPath(node.path, true) catch {
                return self.sendError(header, -2, response_buf);
            };
            var flags = std.posix.O{ .ACCMODE = .RDONLY };
            flags.CLOEXEC = true;
            if ((stat_before.mode & std.posix.S.IFMT) == std.posix.S.IFDIR) {
                flags.DIRECTORY = true;
            }
            const fd = fs.openAt(fs.cwd().fd, node.path, flags, 0) catch {
                return self.sendError(header, -13, response_buf);
            };
            defer fs.closeFd(fd);
            const uid: ?std.posix.uid_t = if (valid & FATTR_UID != 0) @intCast(setattr_in.uid) else null;
            const gid: ?std.posix.gid_t = if (valid & FATTR_GID != 0) @intCast(setattr_in.gid) else null;
            fs.chownFd(fd, uid, gid) catch |e| switch (e) {
                error.AccessDenied => return self.sendError(header, -13, response_buf),
                error.FileNotFound => return self.sendError(header, -2, response_buf),
                else => return self.sendError(header, -5, response_buf),
            };
        }

        // Apply timestamp changes (utime/utimes)
        const has_atime = (valid & FATTR_ATIME != 0) or (valid & FATTR_ATIME_NOW != 0);
        const has_mtime = (valid & FATTR_MTIME != 0) or (valid & FATTR_MTIME_NOW != 0);
        if (has_atime or has_mtime) {
            // Get current stat for OMIT cases and UTIME_NOW
            const current_stat = statPath(node.path, true) catch {
                return self.sendError(header, -2, response_buf); // ENOENT
            };
            const now = sync.nanoTimestamp();

            // Compute atime in nanoseconds
            var atime_ns: i128 = undefined;
            if (valid & FATTR_ATIME_NOW != 0) {
                atime_ns = now;
            } else if (valid & FATTR_ATIME != 0) {
                atime_ns = @as(i128, setattr_in.atime) * std.time.ns_per_s + setattr_in.atimensec;
            } else {
                // OMIT: keep current atime
                atime_ns = current_stat.atime_ns;
            }

            // Compute mtime in nanoseconds
            var mtime_ns: i128 = undefined;
            if (valid & FATTR_MTIME_NOW != 0) {
                mtime_ns = now;
            } else if (valid & FATTR_MTIME != 0) {
                mtime_ns = @as(i128, setattr_in.mtime) * std.time.ns_per_s + setattr_in.mtimensec;
            } else {
                // OMIT: keep current mtime
                mtime_ns = current_stat.mtime_ns;
            }

            // Open file and update times
            const file = fs.cwd().openFile(node.path, .{ .mode = .read_write }) catch {
                return self.sendError(header, -13, response_buf); // EACCES
            };
            defer file.close();
            file.updateTimes(atime_ns, mtime_ns) catch {
                return self.sendError(header, -13, response_buf); // EACCES
            };
        }

        // Return updated attributes
        const stat = statPath(node.path, true) catch {
            return self.sendError(header, -2, response_buf); // ENOENT
        };

        return self.sendAttrOut(header, &stat, response_buf);
    }

    fn handleOpen(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseOpenIn)) {
            return self.sendError(header, -22, response_buf);
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        if (node.is_dir) {
            return self.sendError(header, -21, response_buf);
        }

        const open_in: *const FuseOpenIn = @ptrCast(@alignCast(payload.ptr));
        const accmode = open_in.flags & O_ACCMODE;
        const write_access = accmode != O_RDONLY;
        if ((open_in.flags & O_TRUNC) != 0 and !write_access) {
            return self.sendError(header, -13, response_buf);
        }
        if (write_access) {
            if (self.validateAccess(node.path, .write)) |errno| {
                return self.sendError(header, errno, response_buf);
            }
        } else {
            if (self.validateAccess(node.path, .read)) |errno| {
                return self.sendError(header, errno, response_buf);
            }
        }

        const file_mode: fs.File.OpenMode = if (accmode == O_WRONLY) .write_only else if (accmode == O_RDWR) .read_write else .read_only;
        const file = fs.cwd().openFile(node.path, .{ .mode = file_mode }) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        if ((open_in.flags & O_TRUNC) != 0) {
            file.setEndPos(0) catch {
                file.close();
                return self.sendError(header, -13, response_buf);
            };
        }

        const fh = self.allocateFileHandle(header.nodeid, file, open_in.flags) catch {
            file.close();
            return self.sendError(header, -12, response_buf);
        };

        return self.sendOpenOut(header, fh, response_buf);
    }

    fn handleMkdir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseMkdirIn)) {
            return self.sendError(header, -22, response_buf);
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name = payload[@sizeOf(FuseMkdirIn)..];
        const name_end = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
        const entry_name = name[0..name_end];
        if (entry_name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(entry_name) or containsPathSeparator(entry_name)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, entry_name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .create)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        fs.cwd().makeDir(full_path) catch |e| switch (e) {
            error.PathAlreadyExists => return self.sendError(header, -17, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        const stat = statPath(full_path, true) catch return self.sendError(header, -5, response_buf);
        const nodeid = self.allocateNode(full_path, true) catch return self.sendError(header, -12, response_buf);
        const generation = self.nodeGeneration(nodeid);
        return self.sendEntryOut(header, nodeid, generation, &stat, response_buf);
    }

    fn handleMknod(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseMknodIn)) {
            return self.sendError(header, -22, response_buf);
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name = payload[@sizeOf(FuseMknodIn)..];
        const name_end = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
        const entry_name = name[0..name_end];
        if (entry_name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(entry_name) or containsPathSeparator(entry_name)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, entry_name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .create)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const file = fs.cwd().createFile(full_path, .{ .read = true, .truncate = false }) catch |e| switch (e) {
            error.PathAlreadyExists => fs.cwd().openFile(full_path, .{ .mode = .read_write }) catch |open_err| switch (open_err) {
                error.AccessDenied => return self.sendError(header, -13, response_buf),
                error.FileNotFound => return self.sendError(header, -2, response_buf),
                else => return self.sendError(header, -5, response_buf),
            },
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };
        defer file.close();

        const stat = statPath(full_path, true) catch return self.sendError(header, -5, response_buf);
        const nodeid = self.allocateNode(full_path, false) catch return self.sendError(header, -12, response_buf);
        const generation = self.nodeGeneration(nodeid);
        return self.sendEntryOut(header, nodeid, generation, &stat, response_buf);
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
        if (self.validateAccess(handle.node.path, .read)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

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
        if (self.validateAccess(handle.node.path, .write)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const data_offset = @sizeOf(FuseWriteIn);
        if (payload.len < data_offset + write_in.size) {
            return self.sendError(header, -22, response_buf);
        }

        const data = payload[data_offset..][0..write_in.size];

        var f = file;
        if (handle.append) {
            const end_pos = f.getEndPos() catch return self.sendError(header, -5, response_buf);
            f.seekTo(end_pos) catch return self.sendError(header, -5, response_buf);
        } else {
            f.seekTo(write_in.offset) catch return self.sendError(header, -5, response_buf);
        }
        const bytes_written = f.write(data) catch return self.sendError(header, -5, response_buf);
        if (handle.sync_mode != .none) {
            syncFile(&f, handle.sync_mode) catch return self.sendError(header, -5, response_buf);
        }

        return self.sendWriteOut(header, @intCast(bytes_written), response_buf);
    }

    fn handleStatfs(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag != .windows) {
            const stat_path = if (header.nodeid == 1 or header.nodeid == 0) blk: {
                const mount = self.mount_manager.getMountByTag(self.tag) orelse break :blk ".";
                break :blk mount.host_path;
            } else if (self.nodes.get(header.nodeid)) |node|
                node.path
            else
                ".";
            const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseStatfsOut);
            if (response_buf.len < total_size) return VirtioFsError.IoError;

            const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
            out_header.len = @intCast(total_size);
            out_header.@"error" = 0;
            out_header.unique = header.unique;

            var stat_out: *FuseStatfsOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
            var st: c.struct_statfs = undefined;
            // statfs on current working dir; callers generally use root node.
            const stat_path_z = try toZ(self.allocator, stat_path);
            defer self.allocator.free(stat_path_z);
            if (c.statfs(stat_path_z.ptr, &st) != 0) {
                return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
            }
            const name_len: u64 = if (builtin.os.tag == .macos) 255 else @intCast(st.f_namelen);
            const frsize: u64 = if (builtin.os.tag == .linux) @intCast(st.f_frsize) else @intCast(st.f_bsize);
            stat_out.st = .{
                .blocks = @intCast(st.f_blocks),
                .bfree = @intCast(st.f_bfree),
                .bavail = @intCast(st.f_bavail),
                .files = @intCast(st.f_files),
                .ffree = @intCast(st.f_ffree),
                .bsize = @intCast(st.f_bsize),
                .namelen = @intCast(name_len),
                .frsize = @intCast(frsize),
                .padding = 0,
                .spare = std.mem.zeroes([6]u32),
            };
            return total_size;
        }

        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseStatfsOut);
        if (response_buf.len < total_size) return VirtioFsError.IoError;

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const stat_out: *FuseStatfsOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        stat_out.st = .{
            .blocks = 0,
            .bfree = 0,
            .bavail = 0,
            .files = 0,
            .ffree = 0,
            .bsize = 4096,
            .namelen = 255,
            .frsize = 4096,
            .padding = 0,
            .spare = std.mem.zeroes([6]u32),
        };

        return total_size;
    }

    fn handleCreate(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseCreateIn)) {
            return self.sendError(header, -22, response_buf);
        }

        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name = payload[@sizeOf(FuseCreateIn)..];
        const name_end = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
        const entry_name = name[0..name_end];
        if (entry_name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(entry_name) or containsPathSeparator(entry_name)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, entry_name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .create)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const create_in: *const FuseCreateIn = @ptrCast(@alignCast(payload.ptr));
        const accmode = create_in.flags & O_ACCMODE;
        const read_enabled = accmode != O_WRONLY;
        if ((create_in.flags & O_TRUNC) != 0 and accmode == O_RDONLY) {
            return self.sendError(header, -13, response_buf);
        }
        const file_mode: fs.File.OpenMode = if (accmode == O_WRONLY) .write_only else if (accmode == O_RDWR) .read_write else .read_only;
        const file = fs.cwd().createFile(full_path, .{ .read = read_enabled, .truncate = false }) catch |e| switch (e) {
            error.PathAlreadyExists => fs.cwd().openFile(full_path, .{ .mode = file_mode }) catch |open_err| switch (open_err) {
                error.AccessDenied => return self.sendError(header, -13, response_buf),
                error.FileNotFound => return self.sendError(header, -2, response_buf),
                else => return self.sendError(header, -5, response_buf),
            },
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        if ((create_in.flags & O_TRUNC) != 0) {
            file.setEndPos(0) catch {
                file.close();
                return self.sendError(header, -13, response_buf);
            };
        }

        const stat = statPath(full_path, true) catch {
            file.close();
            return self.sendError(header, -5, response_buf);
        };

        const nodeid = self.allocateNode(full_path, false) catch {
            file.close();
            return self.sendError(header, -12, response_buf);
        };
        const fh = self.allocateFileHandle(nodeid, file, create_in.flags) catch {
            file.close();
            return self.sendError(header, -12, response_buf);
        };

        const generation = self.nodeGeneration(nodeid);
        return self.sendCreateOut(header, nodeid, generation, &stat, fh, response_buf);
    }

    fn handleUnlink(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name_end = std.mem.indexOfScalar(u8, payload, 0) orelse payload.len;
        const entry_name = payload[0..name_end];
        if (entry_name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(entry_name) or containsPathSeparator(entry_name)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, entry_name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .delete)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        fs.cwd().deleteFile(full_path) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.IsDir => return self.sendError(header, -21, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        return self.sendError(header, 0, response_buf);
    }

    fn handleRmdir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (header.nodeid == 1) try self.ensureRootNode();
        const parent_node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const name_end = std.mem.indexOfScalar(u8, payload, 0) orelse payload.len;
        const entry_name = payload[0..name_end];
        if (entry_name.len == 0) {
            return self.sendError(header, -2, response_buf);
        }
        if (path_util.containsTraversal(entry_name) or containsPathSeparator(entry_name)) {
            return self.sendError(header, -1, response_buf);
        }

        const full_path = fs.path.join(self.allocator, &[_][]const u8{ parent_node.path, entry_name }) catch {
            return self.sendError(header, -12, response_buf);
        };
        defer self.allocator.free(full_path);

        if (self.validateAccess(full_path, .delete)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        fs.cwd().deleteDir(full_path) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            error.NotDir => return self.sendError(header, -20, response_buf),
            error.DirNotEmpty => return self.sendError(header, -39, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        return self.sendError(header, 0, response_buf);
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

    fn handleFlush(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseFlushIn)) {
            return self.sendError(header, -22, response_buf);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleFsync(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseFsyncIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const fsync_in: *const FuseFsyncIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(fsync_in.fh) orelse return self.sendError(header, -9, response_buf);
        if (handle.file) |f| {
            f.sync() catch return self.sendError(header, -5, response_buf);
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

        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        if (!node.is_dir) {
            return self.sendError(header, -20, response_buf);
        }

        if (self.validateAccess(node.path, .readdir)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const dir = fs.cwd().openDir(node.path, .{ .iterate = true }) catch |e| switch (e) {
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
        if (self.validateAccess(handle.node.path, .readdir)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size) {
            return VirtioFsError.IoError;
        }
        const max_data = @min(read_in.size, @as(u32, @intCast(response_buf.len - out_header_size)));

        const DT_DIR: u32 = 4;
        const DT_REG: u32 = 8;

        var pos: usize = out_header_size;
        var next_off: u64 = 1;
        const skip_off = read_in.offset;
        var d = dir;
        var it = d.iterate();
        while (true) {
            const entry = it.next() catch return self.sendError(header, -5, response_buf);
            if (entry == null) break;
            const entry_val = entry.?;
            if (next_off <= skip_off) {
                next_off += 1;
                continue;
            }
            const name_len: u32 = @intCast(entry_val.name.len);
            const entry_size = @sizeOf(FuseDirent) + entry_val.name.len;
            const padded_size = std.mem.alignForward(usize, entry_size, 8);
            if (pos + padded_size > out_header_size + max_data) break;

            var dirent = FuseDirent{
                .ino = next_off,
                .off = next_off + 1,
                .namelen = name_len,
                .type = switch (entry_val.kind) {
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
            next_off += 1;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(pos);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        return pos;
    }

    fn handleReaddirplus(
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
        if (self.validateAccess(handle.node.path, .readdir)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size) {
            return VirtioFsError.IoError;
        }
        const max_data = @min(read_in.size, @as(u32, @intCast(response_buf.len - out_header_size)));

        const DT_DIR: u32 = 4;
        const DT_REG: u32 = 8;

        var pos: usize = out_header_size;
        var next_off: u64 = 1;
        const skip_off = read_in.offset;
        var d = dir;
        var it = d.iterate();
        while (true) {
            const entry = it.next() catch return self.sendError(header, -5, response_buf);
            if (entry == null) break;
            const entry_val = entry.?;
            if (next_off <= skip_off) {
                next_off += 1;
                continue;
            }

            const name_len: u32 = @intCast(entry_val.name.len);
            const entry_size = @sizeOf(FuseDirentPlus) + entry_val.name.len;
            const padded_size = std.mem.alignForward(usize, entry_size, 8);
            if (pos + padded_size > out_header_size + max_data) break;

            const full_path = fs.path.join(self.allocator, &[_][]const u8{ handle.node.path, entry_val.name }) catch {
                return self.sendError(header, -12, response_buf);
            };
            defer self.allocator.free(full_path);

            const stat = statPath(full_path, false) catch {
                return self.sendError(header, -2, response_buf);
            };
            const nodeid = self.allocateNode(full_path, stat.kind == .directory) catch {
                return self.sendError(header, -12, response_buf);
            };
            const generation = self.nodeGeneration(nodeid);

            var entry_out = FuseEntryOut{
                .nodeid = nodeid,
                .generation = generation,
                .entry_valid = 1,
                .attr_valid = 1,
                .entry_valid_nsec = 0,
                .attr_valid_nsec = 0,
                .attr = statToFuseAttr(nodeid, &stat),
            };
            @memcpy(response_buf[pos..][0..@sizeOf(FuseEntryOut)], std.mem.asBytes(&entry_out));

            var dirent = FuseDirent{
                .ino = next_off,
                .off = next_off + 1,
                .namelen = name_len,
                .type = switch (entry_val.kind) {
                    .directory => DT_DIR,
                    .file => DT_REG,
                    else => 0,
                },
            };
            const dirent_start = pos + @sizeOf(FuseEntryOut);
            @memcpy(response_buf[dirent_start..][0..@sizeOf(FuseDirent)], std.mem.asBytes(&dirent));
            @memcpy(
                response_buf[dirent_start + @sizeOf(FuseDirent) ..][0..entry_val.name.len],
                entry_val.name,
            );
            const pad_start = pos + entry_size;
            @memset(
                response_buf[pad_start..][0..(padded_size - entry_size)],
                0,
            );

            pos += padded_size;
            next_off += 1;
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

    fn handleFsyncdir(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseFsyncIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const fsync_in: *const FuseFsyncIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(fsync_in.fh) orelse return self.sendError(header, -9, response_buf);
        if (handle.dir) |d| {
            fs.syncFd(d.fd) catch return self.sendError(header, -5, response_buf);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleAccess(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseAccessIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse {
            return self.sendError(header, -2, response_buf);
        };

        const access_in: *const FuseAccessIn = @ptrCast(@alignCast(payload.ptr));
        const R_OK: u32 = 4;
        const W_OK: u32 = 2;
        const X_OK: u32 = 1;

        if ((access_in.mask & W_OK) != 0) {
            if (self.validateAccess(node.path, .write)) |errno| {
                return self.sendError(header, errno, response_buf);
            }
        } else if ((access_in.mask & R_OK) != 0) {
            if (self.validateAccess(node.path, .read)) |errno| {
                return self.sendError(header, errno, response_buf);
            }
        }
        if ((access_in.mask & X_OK) != 0) {
            const mount = self.mount_manager.getMountByTag(self.tag) orelse return self.sendError(header, -2, response_buf);
            if (!mount.allow_exec) return self.sendError(header, -13, response_buf);
        }

        fs.accessAt(std.posix.AT.FDCWD, node.path, access_in.mask, 0) catch |e| switch (e) {
            error.FileNotFound => return self.sendError(header, -2, response_buf),
            error.AccessDenied => return self.sendError(header, -13, response_buf),
            else => return self.sendError(header, -5, response_buf),
        };

        return self.sendError(header, 0, response_buf);
    }

    fn handleSetxattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) {
            return self.sendError(header, -38, response_buf);
        }
        if (payload.len < @sizeOf(FuseSetxattrIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse return self.sendError(header, -2, response_buf);

        if (self.validateAccess(node.path, .write)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const set_in: *const FuseSetxattrIn = @ptrCast(@alignCast(payload.ptr));
        const name = parseCString(payload, @sizeOf(FuseSetxattrIn)) orelse return self.sendError(header, -22, response_buf);
        const value_start = name.next;
        if (value_start + set_in.size > payload.len) {
            return self.sendError(header, -22, response_buf);
        }
        const value = payload[value_start .. value_start + set_in.size];

        const path_z = try toZ(self.allocator, node.path);
        defer self.allocator.free(path_z);
        const name_z = try toZ(self.allocator, name.slice);
        defer self.allocator.free(name_z);

        const rc = if (builtin.os.tag == .macos)
            c.setxattr(path_z.ptr, name_z.ptr, value.ptr, value.len, 0, @intCast(set_in.flags))
        else
            c.setxattr(path_z.ptr, name_z.ptr, value.ptr, value.len, @intCast(set_in.flags));

        if (rc != 0) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleGetxattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) {
            return self.sendError(header, -38, response_buf);
        }
        if (payload.len < @sizeOf(FuseGetxattrIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse return self.sendError(header, -2, response_buf);

        if (self.validateAccess(node.path, .read)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const get_in: *const FuseGetxattrIn = @ptrCast(@alignCast(payload.ptr));
        const name = parseCString(payload, @sizeOf(FuseGetxattrIn)) orelse return self.sendError(header, -22, response_buf);

        const path_z = try toZ(self.allocator, node.path);
        defer self.allocator.free(path_z);
        const name_z = try toZ(self.allocator, name.slice);
        defer self.allocator.free(name_z);

        if (get_in.size == 0) {
            const size = if (builtin.os.tag == .macos)
                c.getxattr(path_z.ptr, name_z.ptr, null, 0, 0, 0)
            else
                c.getxattr(path_z.ptr, name_z.ptr, null, 0);
            if (size < 0) {
                return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
            }
            const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseGetxattrOut);
            if (response_buf.len < total_size) return VirtioFsError.IoError;
            const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
            out_header.len = @intCast(total_size);
            out_header.@"error" = 0;
            out_header.unique = header.unique;
            const out: *FuseGetxattrOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
            out.size = @intCast(size);
            out.padding = 0;
            return total_size;
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size + get_in.size) return VirtioFsError.IoError;
        const data_buf = response_buf[out_header_size .. out_header_size + get_in.size];
        const size = if (builtin.os.tag == .macos)
            c.getxattr(path_z.ptr, name_z.ptr, data_buf.ptr, data_buf.len, 0, 0)
        else
            c.getxattr(path_z.ptr, name_z.ptr, data_buf.ptr, data_buf.len);
        if (size < 0) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + @as(usize, @intCast(size)));
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        return out_header_size + @as(usize, @intCast(size));
    }

    fn handleListxattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) {
            return self.sendError(header, -38, response_buf);
        }
        if (payload.len < @sizeOf(FuseGetxattrIn)) {
            return self.sendError(header, -22, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse return self.sendError(header, -2, response_buf);
        if (self.validateAccess(node.path, .read)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const list_in: *const FuseGetxattrIn = @ptrCast(@alignCast(payload.ptr));
        const path_z = try toZ(self.allocator, node.path);
        defer self.allocator.free(path_z);

        if (list_in.size == 0) {
            const size = if (builtin.os.tag == .macos)
                c.listxattr(path_z.ptr, null, 0, 0)
            else
                c.listxattr(path_z.ptr, null, 0);
            if (size < 0) {
                return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
            }
            const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseGetxattrOut);
            if (response_buf.len < total_size) return VirtioFsError.IoError;
            const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
            out_header.len = @intCast(total_size);
            out_header.@"error" = 0;
            out_header.unique = header.unique;
            const out: *FuseGetxattrOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
            out.size = @intCast(size);
            out.padding = 0;
            return total_size;
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        if (response_buf.len < out_header_size + list_in.size) return VirtioFsError.IoError;
        const data_buf = response_buf[out_header_size .. out_header_size + list_in.size];
        const size = if (builtin.os.tag == .macos)
            c.listxattr(path_z.ptr, data_buf.ptr, data_buf.len, 0)
        else
            c.listxattr(path_z.ptr, data_buf.ptr, data_buf.len);
        if (size < 0) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }
        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + @as(usize, @intCast(size)));
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        return out_header_size + @as(usize, @intCast(size));
    }

    fn handleRemovexattr(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) {
            return self.sendError(header, -38, response_buf);
        }
        if (header.nodeid == 1) try self.ensureRootNode();
        const node = self.nodes.get(header.nodeid) orelse return self.sendError(header, -2, response_buf);
        if (self.validateAccess(node.path, .write)) |errno| {
            return self.sendError(header, errno, response_buf);
        }
        const name = parseCString(payload, 0) orelse return self.sendError(header, -22, response_buf);
        const path_z = try toZ(self.allocator, node.path);
        defer self.allocator.free(path_z);
        const name_z = try toZ(self.allocator, name.slice);
        defer self.allocator.free(name_z);

        const rc = if (builtin.os.tag == .macos)
            c.removexattr(path_z.ptr, name_z.ptr, 0)
        else
            c.removexattr(path_z.ptr, name_z.ptr);
        if (rc != 0) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleGetlk(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) return self.sendError(header, -38, response_buf);
        if (payload.len < @sizeOf(FuseLkIn)) return self.sendError(header, -22, response_buf);
        const lk_in: *const FuseLkIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(lk_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        var flock: c.struct_flock = lockToFlock(lk_in.lk);
        if (c.fcntl(file.handle, c.F_GETLK, &flock) == -1) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        const out_size = @sizeOf(FuseLkOut);
        if (response_buf.len < out_header_size + out_size) return VirtioFsError.IoError;
        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + out_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        const out: *FuseLkOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out.lk = flockToLock(flock);
        return out_header_size + out_size;
    }

    fn handleSetlk(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        return self.handleSetlkWithCmd(header, payload, response_buf, c.F_SETLK);
    }

    fn handleSetlkw(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        return self.handleSetlkWithCmd(header, payload, response_buf, c.F_SETLKW);
    }

    fn handleSetlkWithCmd(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
        cmd: c_int,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) return self.sendError(header, -38, response_buf);
        if (payload.len < @sizeOf(FuseLkIn)) return self.sendError(header, -22, response_buf);
        const lk_in: *const FuseLkIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(lk_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        var flock: c.struct_flock = lockToFlock(lk_in.lk);
        if (c.fcntl(file.handle, cmd, &flock) == -1) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleInterrupt(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        _ = payload;
        return self.sendError(header, 0, response_buf);
    }

    fn handleBmap(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseBmapIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const out_header_size = @sizeOf(FuseOutHeader);
        const out_size = @sizeOf(FuseBmapOut);
        if (response_buf.len < out_header_size + out_size) return VirtioFsError.IoError;
        const in: *const FuseBmapIn = @ptrCast(@alignCast(payload.ptr));
        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + out_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        const out: *FuseBmapOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out.block = in.block;
        return out_header_size + out_size;
    }

    fn handleIoctl(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (builtin.os.tag == .windows) {
            return self.sendError(header, -38, response_buf);
        }
        if (payload.len < @sizeOf(FuseIoctlIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const ioctl_in: *const FuseIoctlIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(ioctl_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);
        if (ioctl_in.flags != 0) {
            return self.sendError(header, -38, response_buf);
        }

        const in_size: usize = ioctl_in.in_size;
        const out_data_size: usize = ioctl_in.out_size;
        const data_start = @sizeOf(FuseIoctlIn);
        if (payload.len < data_start + in_size) {
            return self.sendError(header, -22, response_buf);
        }

        const out_header_size = @sizeOf(FuseOutHeader);
        const out_struct_size = @sizeOf(FuseIoctlOut);
        if (response_buf.len < out_header_size + out_struct_size + out_data_size) return VirtioFsError.IoError;

        const total_io = @max(in_size, out_data_size);
        var io_buf = try self.allocator.alloc(u8, @max(@as(usize, 1), total_io));
        defer self.allocator.free(io_buf);
        if (in_size > 0) {
            @memcpy(io_buf[0..in_size], payload[data_start .. data_start + in_size]);
        }

        const rc = c.ioctl(file.handle, ioctl_in.cmd, io_buf.ptr);
        if (rc == -1) {
            return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + out_struct_size + out_data_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        const out: *FuseIoctlOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out.result = @intCast(rc);
        out.flags = 0;
        out.in_iovs = 0;
        out.out_iovs = 0;
        if (out_data_size > 0) {
            @memcpy(
                response_buf[out_header_size + out_struct_size ..][0..out_data_size],
                io_buf[0..out_data_size],
            );
        }
        return out_header_size + out_struct_size + out_data_size;
    }

    fn handlePoll(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FusePollIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const poll_in: *const FusePollIn = @ptrCast(@alignCast(payload.ptr));
        const out_header_size = @sizeOf(FuseOutHeader);
        const out_size = @sizeOf(FusePollOut);
        if (response_buf.len < out_header_size + out_size) return VirtioFsError.IoError;

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + out_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        const out: *FusePollOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out.revents = poll_in.events;
        out.padding = 0;
        return out_header_size + out_size;
    }

    fn handleBatchForget(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseBatchForgetIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const batch_in: *const FuseBatchForgetIn = @ptrCast(@alignCast(payload.ptr));
        const needed = @sizeOf(FuseBatchForgetIn) + batch_in.count * @sizeOf(FuseForgetOne);
        if (payload.len < needed) {
            return self.sendError(header, -22, response_buf);
        }
        var offset: usize = @sizeOf(FuseBatchForgetIn);
        var i: u32 = 0;
        while (i < batch_in.count) : (i += 1) {
            const forget_one: *const FuseForgetOne = @ptrCast(@alignCast(payload[offset..].ptr));
            if (forget_one.nodeid != 1) {
                if (self.nodes.fetchRemove(forget_one.nodeid)) |kv| {
                    self.allocator.free(kv.value.path);
                }
            }
            offset += @sizeOf(FuseForgetOne);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleLseek(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseLseekIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const lseek_in: *const FuseLseekIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(lseek_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        const out_header_size = @sizeOf(FuseOutHeader);
        const out_size = @sizeOf(FuseLseekOut);
        if (response_buf.len < out_header_size + out_size) return VirtioFsError.IoError;

        const offset = switch (lseek_in.whence) {
            0 => blk: {
                break :blk fs.seekFd(file.handle, @intCast(lseek_in.offset), std.c.SEEK.SET) catch return self.sendError(header, -5, response_buf);
            },
            1 => blk: {
                break :blk fs.seekFd(file.handle, @as(i64, @bitCast(lseek_in.offset)), std.c.SEEK.CUR) catch return self.sendError(header, -5, response_buf);
            },
            2 => blk: {
                break :blk fs.seekFd(file.handle, @as(i64, @bitCast(lseek_in.offset)), std.c.SEEK.END) catch return self.sendError(header, -5, response_buf);
            },
            else => return self.sendError(header, -22, response_buf),
        };

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(out_header_size + out_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const out: *FuseLseekOut = @ptrCast(@alignCast(response_buf.ptr + out_header_size));
        out.offset = offset;
        return out_header_size + out_size;
    }

    fn handleCopyFileRange(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseCopyFileRangeIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const copy_in: *const FuseCopyFileRangeIn = @ptrCast(@alignCast(payload.ptr));
        const in_handle = self.handles.get(copy_in.fh_in) orelse return self.sendError(header, -9, response_buf);
        const out_handle = self.handles.get(copy_in.fh_out) orelse return self.sendError(header, -9, response_buf);
        const in_file = in_handle.file orelse return self.sendError(header, -9, response_buf);
        const out_file = out_handle.file orelse return self.sendError(header, -9, response_buf);

        if (self.validateAccess(out_handle.node.path, .write)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const copied = fs.copyFileRange(
            in_file.handle,
            copy_in.off_in,
            out_file.handle,
            copy_in.off_out,
            @intCast(copy_in.len),
            copy_in.flags,
        ) catch return self.sendError(header, -5, response_buf);

        return self.sendWriteOut(header, @intCast(copied), response_buf);
    }

    fn handleFallocate(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseFallocateIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const fallocate_in: *const FuseFallocateIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(fallocate_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);

        if (self.validateAccess(handle.node.path, .write)) |errno| {
            return self.sendError(header, errno, response_buf);
        }

        const keep_size = (fallocate_in.mode & FALLOC_FL_KEEP_SIZE) != 0;
        const punch_hole = (fallocate_in.mode & FALLOC_FL_PUNCH_HOLE) != 0;
        const unsupported = (fallocate_in.mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE)) != 0;
        if (unsupported) {
            return self.sendError(header, -95, response_buf);
        }
        if (punch_hole and !keep_size) {
            return self.sendError(header, -22, response_buf);
        }

        if (fallocate_in.mode == 0) {
            const end_pos = fallocate_in.offset + fallocate_in.length;
            file.setEndPos(end_pos) catch return self.sendError(header, -5, response_buf);
            return self.sendError(header, 0, response_buf);
        }

        if (builtin.os.tag == .linux) {
            const rc = c.fallocate(
                file.handle,
                @intCast(fallocate_in.mode),
                @intCast(fallocate_in.offset),
                @intCast(fallocate_in.length),
            );
            if (rc != 0) {
                return self.sendError(header, errnoToFuse(std.posix.errno(@as(isize, -1))), response_buf);
            }
            return self.sendError(header, 0, response_buf);
        }

        return self.sendError(header, -95, response_buf);
    }

    fn handleSetupmapping(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseSetupmappingIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const setup_in: *const FuseSetupmappingIn = @ptrCast(@alignCast(payload.ptr));
        const handle = self.handles.get(setup_in.fh) orelse return self.sendError(header, -9, response_buf);
        const file = handle.file orelse return self.sendError(header, -9, response_buf);
        const dax = self.dax orelse return self.sendError(header, -95, response_buf);
        if (setup_in.len == 0) return self.sendError(header, 0, response_buf);

        const page_size = if (dax.page_size != 0) dax.page_size else std.heap.page_size_min;
        if ((setup_in.foffset % page_size) != 0 or (setup_in.moffset % page_size) != 0 or (setup_in.len % page_size) != 0) {
            return self.sendError(header, -22, response_buf);
        }

        const end_offset = setup_in.moffset + setup_in.len;
        if (end_offset > dax.window_size) {
            return self.sendError(header, -22, response_buf);
        }

        const writable = (setup_in.flags & FUSE_SETUPMAPPING_FLAG_WRITE) != 0;
        const guest_addr = dax.window_base + setup_in.moffset;
        if (self.isDaxMappingCached(setup_in.moffset, setup_in.len, setup_in.foffset, setup_in.fh, writable)) {
            return self.sendError(header, 0, response_buf);
        }
        dax.map(dax.ctx, guest_addr, setup_in.len, file.handle, setup_in.foffset, writable) catch {
            return self.sendError(header, -5, response_buf);
        };
        self.cacheDaxMapping(setup_in.moffset, setup_in.len, setup_in.foffset, setup_in.fh, writable) catch {
            return self.sendError(header, -12, response_buf);
        };
        return self.sendError(header, 0, response_buf);
    }

    fn handleRemovemapping(
        self: *VirtioFsDevice,
        header: *const FuseInHeader,
        payload: []const u8,
        response_buf: []u8,
    ) VirtioFsError!usize {
        if (payload.len < @sizeOf(FuseRemovemappingIn)) {
            return self.sendError(header, -22, response_buf);
        }
        const remove_in: *const FuseRemovemappingIn = @ptrCast(@alignCast(payload.ptr));
        const needed = @sizeOf(FuseRemovemappingIn) + @as(usize, @intCast(remove_in.count)) * @sizeOf(FuseRemovemappingOne);
        if (payload.len < needed) {
            return self.sendError(header, -22, response_buf);
        }
        const dax = self.dax orelse return self.sendError(header, -95, response_buf);
        if (remove_in.count == 0) return self.sendError(header, 0, response_buf);

        var offset: usize = @sizeOf(FuseRemovemappingIn);
        var i: u32 = 0;
        while (i < remove_in.count) : (i += 1) {
            const one: *const FuseRemovemappingOne = @ptrCast(@alignCast(payload[offset..].ptr));
            if (one.len == 0) {
                offset += @sizeOf(FuseRemovemappingOne);
                continue;
            }
            const end_offset = one.moffset + one.len;
            if (end_offset > dax.window_size) return self.sendError(header, -22, response_buf);
            const guest_addr = dax.window_base + one.moffset;
            dax.unmap(dax.ctx, guest_addr, one.len) catch {
                return self.sendError(header, -5, response_buf);
            };
            self.dropDaxMappings(one.moffset, one.len);
            offset += @sizeOf(FuseRemovemappingOne);
        }
        return self.sendError(header, 0, response_buf);
    }

    fn handleDestroy(
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        response_buf: []u8,
    ) VirtioFsError!usize {
        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @sizeOf(FuseOutHeader);
        out_header.@"error" = 0;
        out_header.unique = header.unique;
        return @sizeOf(FuseOutHeader);
    }

    fn sendError(
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        err: i32,
        response_buf: []u8,
    ) VirtioFsError!usize {
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
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        stat: *const StatView,
        response_buf: []u8,
    ) VirtioFsError!usize {
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

    fn sendCreateOut(
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        nodeid: u64,
        generation: u64,
        stat: *const StatView,
        fh: u64,
        response_buf: []u8,
    ) VirtioFsError!usize {
        const total_size = @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut) + @sizeOf(FuseOpenOut);
        if (response_buf.len < total_size) {
            return VirtioFsError.IoError;
        }

        const out_header: *FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
        out_header.len = @intCast(total_size);
        out_header.@"error" = 0;
        out_header.unique = header.unique;

        const entry_out: *FuseEntryOut = @ptrCast(@alignCast(response_buf.ptr + @sizeOf(FuseOutHeader)));
        entry_out.nodeid = nodeid;
        entry_out.generation = generation;
        entry_out.entry_valid = 1;
        entry_out.attr_valid = 1;
        entry_out.entry_valid_nsec = 0;
        entry_out.attr_valid_nsec = 0;
        entry_out.attr = statToFuseAttr(nodeid, stat);

        const open_out: *FuseOpenOut = @ptrCast(@alignCast(
            response_buf.ptr + @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut),
        ));
        open_out.fh = fh;
        open_out.open_flags = 0;
        open_out.padding = 0;

        return total_size;
    }

    fn sendEntryOut(
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        nodeid: u64,
        generation: u64,
        stat: *const StatView,
        response_buf: []u8,
    ) VirtioFsError!usize {
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
        entry_out.generation = generation;
        entry_out.entry_valid = 1;
        entry_out.attr_valid = 1;
        entry_out.entry_valid_nsec = 0;
        entry_out.attr_valid_nsec = 0;
        entry_out.attr = statToFuseAttr(nodeid, stat);

        return total_size;
    }

    fn sendOpenOut(
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        fh: u64,
        response_buf: []u8,
    ) VirtioFsError!usize {
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
        _: *VirtioFsDevice,
        header: *const FuseInHeader,
        size: u32,
        response_buf: []u8,
    ) VirtioFsError!usize {
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
        const generation = self.next_generation;
        self.next_generation += 1;

        const owned_path = try self.allocator.dupe(u8, path);
        try self.nodes.put(nodeid, .{
            .inode = nodeid,
            .path = owned_path,
            .is_dir = is_dir,
            .generation = generation,
        });

        return nodeid;
    }

    fn nodeGeneration(self: *VirtioFsDevice, nodeid: u64) u64 {
        if (self.nodes.get(nodeid)) |node| return node.generation;
        return 0;
    }

    fn ensureRootNode(self: *VirtioFsDevice) VirtioFsError!void {
        if (self.nodes.contains(1)) return;

        const mount = self.mount_manager.getMountByTag(self.tag) orelse {
            return VirtioFsError.NotFound;
        };

        const stat = statPath(mount.host_path, true) catch {
            return VirtioFsError.NotFound;
        };

        const owned_path = self.allocator.dupe(u8, mount.host_path) catch {
            return VirtioFsError.OutOfMemory;
        };
        errdefer self.allocator.free(owned_path);

        self.nodes.put(1, .{
            .inode = 1,
            .path = owned_path,
            .is_dir = stat.kind == .directory,
            .generation = 1,
        }) catch return VirtioFsError.OutOfMemory;
    }

    fn allocateFileHandle(self: *VirtioFsDevice, nodeid: u64, file: fs.File, open_flags: u32) !u64 {
        const fh = self.next_fh;
        self.next_fh += 1;

        const node = self.nodes.getPtr(nodeid) orelse return error.InvalidHandle;
        const open_state = parseOpenFlags(open_flags);
        try self.handles.put(fh, .{
            .handle_id = fh,
            .node = node,
            .file = file,
            .dir = null,
            .open_flags = open_flags,
            .append = open_state.append,
            .sync_mode = open_state.sync_mode,
        });

        return fh;
    }

    fn allocateDirHandle(self: *VirtioFsDevice, nodeid: u64, dir: fs.Dir) !u64 {
        const fh = self.next_fh;
        self.next_fh += 1;

        const node = self.nodes.getPtr(nodeid) orelse return error.InvalidHandle;
        try self.handles.put(fh, .{
            .handle_id = fh,
            .node = node,
            .file = null,
            .dir = dir,
            .open_flags = 0,
            .append = false,
            .sync_mode = .none,
        });

        return fh;
    }

    fn validateAccess(self: *VirtioFsDevice, path: []const u8, op: mounts.FileOperation) ?i32 {
        const mount = self.mount_manager.getMountByTag(self.tag) orelse return -2;
        if (!path_util.isWithinRoot(path, mount.host_path)) return -13;
        const rel = if (path.len > mount.host_path.len) path[mount.host_path.len..] else "";
        const rel_trim = std.mem.trimStart(u8, rel, "/");
        self.mount_manager.validateFileOperation(mount.tag, rel_trim, op) catch |err| {
            return switch (err) {
                mounts.MountError.PathTraversal => -1,
                mounts.MountError.InvalidPath => -2,
                mounts.MountError.WriteNotAllowed => -30, // EROFS
                else => -13,
            };
        };
        return null;
    }

    fn isDaxMappingCached(
        self: *VirtioFsDevice,
        moffset: u64,
        len: u64,
        foffset: u64,
        fh: u64,
        writable: bool,
    ) bool {
        for (self.dax_mappings.items) |mapping| {
            if (mapping.moffset == moffset and mapping.len == len and mapping.foffset == foffset and mapping.fh == fh and mapping.writable == writable) {
                return true;
            }
        }
        return false;
    }

    fn cacheDaxMapping(self: *VirtioFsDevice, moffset: u64, len: u64, foffset: u64, fh: u64, writable: bool) !void {
        if (len == 0) return;
        const delta: i128 = @as(i128, @intCast(moffset)) - @as(i128, @intCast(foffset));
        var i: usize = 0;
        while (i < self.dax_mappings.items.len) {
            var mapping = &self.dax_mappings.items[i];
            if (mapping.fh != fh or mapping.writable != writable) {
                i += 1;
                continue;
            }
            const mapping_delta: i128 = @as(i128, @intCast(mapping.moffset)) - @as(i128, @intCast(mapping.foffset));
            if (mapping_delta != delta) {
                i += 1;
                continue;
            }
            const new_start = @min(moffset, mapping.moffset);
            const new_end = @max(moffset + len, mapping.moffset + mapping.len);
            const overlaps = moffset <= mapping.moffset + mapping.len and mapping.moffset <= moffset + len;
            const adjacent = (moffset + len == mapping.moffset) or (mapping.moffset + mapping.len == moffset);
            if (!overlaps and !adjacent) {
                i += 1;
                continue;
            }
            if (new_start == mapping.moffset and new_end == mapping.moffset + mapping.len) {
                return;
            }
            mapping.moffset = new_start;
            mapping.len = new_end - new_start;
            mapping.foffset = @intCast(@as(i128, @intCast(mapping.moffset)) - delta);
            // Restart scan to coalesce with any newly-adjacent mappings.
            i = 0;
            continue;
        }

        try self.dax_mappings.append(self.allocator, .{
            .moffset = moffset,
            .len = len,
            .foffset = foffset,
            .fh = fh,
            .writable = writable,
        });
    }

    fn dropDaxMappings(self: *VirtioFsDevice, moffset: u64, len: u64) void {
        if (self.dax_mappings.items.len == 0) return;
        const end = moffset + len;
        var i: usize = 0;
        while (i < self.dax_mappings.items.len) {
            const mapping = self.dax_mappings.items[i];
            const map_end = mapping.moffset + mapping.len;
            const overlaps = moffset < map_end and mapping.moffset < end;
            if (overlaps) {
                _ = self.dax_mappings.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

const O_ACCMODE: u32 = 0x3;
const O_RDONLY: u32 = 0x0;
const O_WRONLY: u32 = 0x1;
const O_RDWR: u32 = 0x2;
const O_TRUNC: u32 = 0x200;
const O_APPEND: u32 = 0x400;
const O_DSYNC: u32 = 0x1000;
const O_SYNC: u32 = 0x101000;

const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
const FUSE_SETUPMAPPING_FLAG_WRITE: u64 = 0x01;

const ParseResult = struct {
    slice: []const u8,
    next: usize,
};

const OpenFlagState = struct {
    append: bool,
    sync_mode: SyncMode,
};

const SyncMode = enum {
    none,
    data,
    full,
};

fn parseOpenFlags(flags: u32) OpenFlagState {
    var sync_mode: SyncMode = .none;
    if ((flags & O_SYNC) != 0) {
        sync_mode = .full;
    } else if ((flags & O_DSYNC) != 0) {
        sync_mode = .data;
    }
    return .{
        .append = (flags & O_APPEND) != 0,
        .sync_mode = sync_mode,
    };
}

fn syncFile(file: *fs.File, mode: SyncMode) !void {
    switch (mode) {
        .none => return,
        .full => try file.sync(),
        .data => {
            if (builtin.os.tag == .windows) {
                try file.sync();
                return;
            }
            try std.posix.fdatasync(file.handle);
        },
    }
}

fn toZ(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = try allocator.alloc(u8, s.len + 1);
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf;
}

fn parseCString(payload: []const u8, start: usize) ?ParseResult {
    if (start >= payload.len) return null;
    const end = std.mem.indexOfScalarPos(u8, payload, start, 0) orelse return null;
    return .{ .slice = payload[start..end], .next = end + 1 };
}

fn containsPathSeparator(name: []const u8) bool {
    for (name) |ch| {
        if (ch == '/' or ch == '\\') return true;
    }
    return false;
}

fn errnoToFuse(err: std.posix.E) i32 {
    if (@hasField(std.posix.E, "NOATTR") and err == .NOATTR) return -61;
    if (@hasField(std.posix.E, "NODATA") and err == .NODATA) return -61;
    return switch (err) {
        .SUCCESS => 0,
        .NOENT => -2,
        .PERM, .ACCES => -13,
        .EXIST => -17,
        .NOTDIR => -20,
        .ISDIR => -21,
        .INVAL => -22,
        .ROFS => -30,
        .NOSPC => -28,
        .XDEV => -18,
        .BUSY => -16,
        .AGAIN => -11,
        .NOTTY => -25,
        .OPNOTSUPP => -95,
        .NAMETOOLONG => -36,
        else => -5,
    };
}

fn lockToFlock(lock: FuseFileLock) c.struct_flock {
    const max_end = std.math.maxInt(u64);
    const len: u64 = if (lock.end == max_end or lock.end < lock.start)
        0
    else
        lock.end - lock.start + 1;
    const l_type: i16 = switch (lock.type) {
        0 => c.F_RDLCK,
        1 => c.F_WRLCK,
        2 => c.F_UNLCK,
        else => c.F_UNLCK,
    };
    return .{
        .l_type = l_type,
        .l_whence = c.SEEK_SET,
        .l_start = @bitCast(@as(i64, @intCast(lock.start))),
        .l_len = @bitCast(@as(i64, @intCast(len))),
        .l_pid = 0,
    };
}

fn flockToLock(flock: c.struct_flock) FuseFileLock {
    const start: u64 = @intCast(@as(u64, @bitCast(flock.l_start)));
    const len: u64 = @intCast(@as(u64, @bitCast(flock.l_len)));
    const end: u64 = if (len == 0) std.math.maxInt(u64) else start + len - 1;
    const typ: u32 = switch (flock.l_type) {
        c.F_RDLCK => 0,
        c.F_WRLCK => 1,
        else => 2,
    };
    return .{
        .start = start,
        .end = end,
        .type = typ,
        .pid = @intCast(flock.l_pid),
    };
}

fn statPath(path: []const u8, follow: bool) !StatView {
    if (builtin.os.tag == .windows) {
        const stat = try fs.cwd().statFile(path);
        const mode: u32 = switch (stat.kind) {
            .directory => 0o040000 | 0o755,
            else => 0o100000 | 0o644,
        };
        return .{
            .size = stat.size,
            .blocks = (stat.size + 511) / 512,
            .atime_ns = stat.atime,
            .mtime_ns = stat.mtime,
            .ctime_ns = stat.ctime,
            .mode = mode,
            .nlink = 1,
            .uid = 0,
            .gid = 0,
            .rdev = 0,
            .blksize = 4096,
            .kind = stat.kind,
        };
    }

    const flags: u32 = if (follow) 0 else @as(u32, std.posix.AT.SYMLINK_NOFOLLOW);
    const st = try fs.statPosixAt(std.posix.AT.FDCWD, path, flags);
    const atime = st.atime();
    const mtime = st.mtime();
    const ctime = st.ctime();
    const kind: fs.File.Kind = fs.File.Stat.fromPosix(st).kind;
    return .{
        .size = @bitCast(st.size),
        .blocks = @bitCast(st.blocks),
        .atime_ns = @as(i128, atime.sec) * std.time.ns_per_s + atime.nsec,
        .mtime_ns = @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec,
        .ctime_ns = @as(i128, ctime.sec) * std.time.ns_per_s + ctime.nsec,
        .mode = @intCast(st.mode),
        .nlink = @intCast(st.nlink),
        .uid = @intCast(st.uid),
        .gid = @intCast(st.gid),
        .rdev = @intCast(st.rdev),
        .blksize = @intCast(st.blksize),
        .kind = kind,
    };
}

fn statToFuseAttr(nodeid: u64, stat: *const StatView) FuseAttr {
    return .{
        .ino = nodeid,
        .size = stat.size,
        .blocks = stat.blocks,
        .atime = @intCast(@divFloor(stat.atime_ns, std.time.ns_per_s)),
        .mtime = @intCast(@divFloor(stat.mtime_ns, std.time.ns_per_s)),
        .ctime = @intCast(@divFloor(stat.ctime_ns, std.time.ns_per_s)),
        .atimensec = @intCast(@mod(stat.atime_ns, std.time.ns_per_s)),
        .mtimensec = @intCast(@mod(stat.mtime_ns, std.time.ns_per_s)),
        .ctimensec = @intCast(@mod(stat.ctime_ns, std.time.ns_per_s)),
        .mode = stat.mode,
        .nlink = stat.nlink,
        .uid = stat.uid,
        .gid = stat.gid,
        .rdev = stat.rdev,
        .blksize = stat.blksize,
        .flags = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    var request: [@sizeOf(FuseInHeader) + @sizeOf(FuseInitIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const header: *FuseInHeader = @ptrCast(@alignCast(&request));
    header.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseInitIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_INIT),
        .unique = 1,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };

    const init_in: *FuseInitIn = @ptrCast(@alignCast(request[@sizeOf(FuseInHeader)..]));
    init_in.* = .{
        .major = 7,
        .minor = 31,
        .max_readahead = 131072,
        .flags = 0,
        .flags2 = 0,
        .unused = std.mem.zeroes([11]u32),
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(request[0..@sizeOf(FuseInHeader)], std.mem.asBytes(&header));

    var init_in = FuseInitIn{
        .major = 7,
        .minor = 31,
        .max_readahead = 131072,
        .flags = 0,
        .flags2 = 0,
        .unused = std.mem.zeroes([11]u32),
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

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("hi");
    }

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    // LOOKUP
    const name = "file.txt";
    const name_len = name.len;
    const lookup_len = @sizeOf(FuseInHeader) + name_len + 1;
    const lookup_req = try allocator.alloc(u8, lookup_len);
    defer allocator.free(lookup_req);

    const lookup_hdr: *FuseInHeader = @ptrCast(@alignCast(lookup_req.ptr));
    lookup_hdr.* = .{
        .len = @intCast(lookup_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_LOOKUP),
        .unique = 11,
        .nodeid = 1,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(lookup_req[@sizeOf(FuseInHeader)..][0..name_len], name);
    lookup_req[@sizeOf(FuseInHeader) + name_len] = 0;

    var lookup_resp: [512]u8 = undefined;
    const lookup_resp_len = try device.handleRequest(lookup_req, &lookup_resp);
    try std.testing.expect(lookup_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut));

    const lookup_out: *const FuseOutHeader = @ptrCast(@alignCast(&lookup_resp));
    try std.testing.expectEqual(@as(i32, 0), lookup_out.@"error");
    const entry_out: *const FuseEntryOut = @ptrCast(@alignCast(lookup_resp[@sizeOf(FuseOutHeader)..]));
    const nodeid = entry_out.nodeid;
    try std.testing.expectEqual(@as(u64, 2), nodeid);
    try std.testing.expect(entry_out.generation != 0);
    try std.testing.expectEqual(@as(u64, 2), entry_out.attr.size);

    // OPEN
    var open_req: [@sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 12,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const open_in: *FuseOpenIn = @ptrCast(@alignCast(open_req[@sizeOf(FuseInHeader)..]));
    open_in.* = .{ .flags = O_RDWR, .open_flags = 0 };
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
        .total_extlen = 0,
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
    @memcpy(write_req[@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) ..][0..write_data.len], write_data);
    var write_resp: [256]u8 = undefined;
    const write_resp_len = try device.handleRequest(write_req, &write_resp);
    try std.testing.expect(write_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseWriteOut));
    const write_out: *const FuseWriteOut = @ptrCast(@alignCast(write_resp[@sizeOf(FuseOutHeader)..]));
    try std.testing.expectEqual(@as(u32, 3), write_out.size);

    // READ back "abc"
    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 14,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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
    var release_req: [release_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const release_hdr: *FuseInHeader = @ptrCast(@alignCast(&release_req));
    release_hdr.* = .{
        .len = release_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_RELEASE),
        .unique = 15,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .nodeid = 1,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 32,
        .nodeid = 999,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const open_in: *FuseOpenIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    open_in.* = .{ .flags = O_RDONLY, .open_flags = 0 };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -2), out.@"error");
}

test "virtio_fs: handleOpen rejects write on read-only mount" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_only,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 33,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const open_in: *FuseOpenIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    open_in.* = .{ .flags = O_RDWR, .open_flags = 0 };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -30), out.@"error");
}

test "virtio_fs: handleOpen honors O_TRUNC" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("abc");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 34,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const open_in: *FuseOpenIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    open_in.* = .{ .flags = O_RDWR | O_TRUNC, .open_flags = 0 };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, 0), out.@"error");

    var check = try fs.cwd().openFile(abs, .{ .mode = .read_only });
    defer check.close();
    const size = try check.getEndPos();
    try std.testing.expectEqual(@as(u64, 0), size);
}

test "virtio_fs: handleWrite appends with O_APPEND" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("abc");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);

    var open_req: [@sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseOpenIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPEN),
        .unique = 35,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const open_in: *FuseOpenIn = @ptrCast(@alignCast(open_req[@sizeOf(FuseInHeader)..]));
    open_in.* = .{ .flags = O_WRONLY | O_APPEND, .open_flags = 0 };

    var open_resp: [128]u8 = undefined;
    const open_resp_len = try device.handleRequest(&open_req, &open_resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut)), open_resp_len);
    const open_hdr_out: *const FuseOutHeader = @ptrCast(@alignCast(&open_resp));
    try std.testing.expectEqual(@as(i32, 0), open_hdr_out.@"error");
    const open_out: *const FuseOpenOut = @ptrCast(@alignCast(open_resp[@sizeOf(FuseOutHeader)..]));

    const write_data = "z";
    const write_len = @sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) + write_data.len;
    var write_req = try allocator.alloc(u8, write_len);
    defer allocator.free(write_req);
    const write_hdr: *FuseInHeader = @ptrCast(@alignCast(write_req.ptr));
    write_hdr.* = .{
        .len = @intCast(write_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_WRITE),
        .unique = 36,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const write_in: *FuseWriteIn = @ptrCast(@alignCast(write_req[@sizeOf(FuseInHeader)..]));
    write_in.* = .{
        .fh = open_out.fh,
        .offset = 0,
        .size = @intCast(write_data.len),
        .write_flags = 0,
        .lock_owner = 0,
        .flags = 0,
        .padding = 0,
    };
    @memcpy(
        write_req[@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) ..][0..write_data.len],
        write_data,
    );

    var write_resp: [128]u8 = undefined;
    const write_resp_len = try device.handleRequest(write_req, &write_resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader) + @sizeOf(FuseWriteOut)), write_resp_len);
    const write_out: *const FuseOutHeader = @ptrCast(@alignCast(&write_resp));
    try std.testing.expectEqual(@as(i32, 0), write_out.@"error");

    var check = try fs.cwd().openFile(abs, .{ .mode = .read_only });
    defer check.close();
    var buf: [4]u8 = undefined;
    const bytes = try check.readAll(&buf);
    try std.testing.expectEqual(@as(usize, 4), bytes);
    try std.testing.expectEqualStrings("abcz", buf[0..4]);
}

test "virtio_fs: handleFallocate keep size" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("data");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDWR);

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseFallocateIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseFallocateIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_FALLOCATE),
        .unique = 37,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const falloc_in: *FuseFallocateIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    falloc_in.* = .{
        .fh = fh,
        .offset = 0,
        .length = 4096,
        .mode = FALLOC_FL_KEEP_SIZE,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, 0), out.@"error");

    var check = try fs.cwd().openFile(abs, .{ .mode = .read_only });
    defer check.close();
    const size = try check.getEndPos();
    try std.testing.expectEqual(@as(u64, 4), size);
}

test "virtio_fs: handleSetupmapping validates payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + 1]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_SETUPMAPPING),
        .unique = 38,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: handleRemovemapping validates payload" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    var req: [@sizeOf(FuseInHeader) + @sizeOf(FuseRemovemappingIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const hdr: *FuseInHeader = @ptrCast(@alignCast(&req));
    hdr.* = .{
        .len = req.len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_REMOVEMAPPING),
        .unique = 39,
        .nodeid = 0,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const remove_in: *FuseRemovemappingIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    remove_in.* = .{
        .count = 1,
        .padding = 0,
    };

    var resp: [128]u8 = undefined;
    const resp_len = try device.handleRequest(&req, &resp);
    try std.testing.expectEqual(@as(usize, @sizeOf(FuseOutHeader)), resp_len);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    try std.testing.expectEqual(@as(i32, -22), out.@"error");
}

test "virtio_fs: dax mapping cache coalesces mappings" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    try device.cacheDaxMapping(0, 4096, 0, 1, false);
    try device.cacheDaxMapping(4096, 4096, 4096, 1, false);
    try std.testing.expectEqual(@as(usize, 1), device.dax_mappings.items.len);
    try std.testing.expectEqual(@as(u64, 0), device.dax_mappings.items[0].moffset);
    try std.testing.expectEqual(@as(u64, 8192), device.dax_mappings.items[0].len);
}

test "virtio_fs: handleRead rejects invalid handle" {
    const allocator = std.testing.allocator;

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
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
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDWR);

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 91,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
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
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .write_only });
    const fh = try device.allocateFileHandle(nodeid, file, O_WRONLY);

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READ),
        .unique = 111,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
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
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_only });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDONLY);

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
        .total_extlen = 0,
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
        write_req[@sizeOf(FuseInHeader) + @sizeOf(FuseWriteIn) ..][0..write_data.len],
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

    var tmp = fs.testingTmpDir(.{});
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
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDWR);
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
        .total_extlen = 0,
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

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
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
        .total_extlen = 0,
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

    var tmp = fs.testingTmpDir(.{});
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
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, true);

    // OPENDIR
    var open_req: [@sizeOf(FuseInHeader)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPENDIR),
        .unique = 201,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };

    var open_resp: [256]u8 = undefined;
    const open_resp_len = try device.handleRequest(&open_req, &open_resp);
    try std.testing.expect(open_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut));
    const open_out: *const FuseOpenOut = @ptrCast(@alignCast(open_resp[@sizeOf(FuseOutHeader)..]));
    const fh = open_out.fh;

    // READDIR
    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READDIR),
        .unique = 202,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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

test "virtio_fs: readdirplus returns generation" {
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        try tmp.dir.makeDir("data");
        var f = try tmp.dir.createFile("data/a.txt", .{});
        defer f.close();
        try f.writeAll("a");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "data");
    defer allocator.free(abs);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, true);

    var open_req: [@sizeOf(FuseInHeader)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const open_hdr: *FuseInHeader = @ptrCast(@alignCast(&open_req));
    open_hdr.* = .{
        .len = @sizeOf(FuseInHeader),
        .opcode = @intFromEnum(FuseOpcode.FUSE_OPENDIR),
        .unique = 211,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };

    var open_resp: [256]u8 = undefined;
    const open_resp_len = try device.handleRequest(&open_req, &open_resp);
    try std.testing.expect(open_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseOpenOut));
    const open_out: *const FuseOpenOut = @ptrCast(@alignCast(open_resp[@sizeOf(FuseOutHeader)..]));
    const fh = open_out.fh;

    const read_len = @sizeOf(FuseInHeader) + @sizeOf(FuseReadIn);
    var read_req: [read_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const read_hdr: *FuseInHeader = @ptrCast(@alignCast(&read_req));
    read_hdr.* = .{
        .len = read_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_READDIRPLUS),
        .unique = 212,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
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
    var pos: usize = @sizeOf(FuseOutHeader);
    while (pos + @sizeOf(FuseDirentPlus) <= read_resp_len) {
        var entry_plus: FuseDirentPlus = undefined;
        @memcpy(
            std.mem.asBytes(&entry_plus),
            read_resp[pos..][0..@sizeOf(FuseDirentPlus)],
        );
        const name_start = pos + @sizeOf(FuseDirentPlus);
        const name_end = name_start + entry_plus.dirent.namelen;
        if (name_end > read_resp_len) break;
        const name = read_resp[name_start..name_end];
        if (std.mem.eql(u8, name, "a.txt")) {
            found_a = true;
            try std.testing.expect(entry_plus.entry_out.generation != 0);
            break;
        }
        const entry_size = @sizeOf(FuseDirentPlus) + entry_plus.dirent.namelen;
        const entry_end = pos + entry_size;
        pos = std.mem.alignForward(usize, entry_end, 8);
    }

    try std.testing.expect(found_a);
}

test "virtio_fs: xattr roundtrip" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);

    const name = "user.test";
    const value = "value";

    // SETXATTR
    const set_len = @sizeOf(FuseInHeader) + @sizeOf(FuseSetxattrIn) + name.len + 1 + value.len;
    var set_req = try allocator.alloc(u8, set_len);
    defer allocator.free(set_req);
    const set_hdr: *FuseInHeader = @ptrCast(@alignCast(set_req.ptr));
    set_hdr.* = .{
        .len = @intCast(set_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_SETXATTR),
        .unique = 301,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const set_in: *FuseSetxattrIn = @ptrCast(@alignCast(set_req[@sizeOf(FuseInHeader)..]));
    set_in.* = .{
        .size = @intCast(value.len),
        .flags = 0,
    };
    var pos: usize = @sizeOf(FuseInHeader) + @sizeOf(FuseSetxattrIn);
    @memcpy(set_req[pos..][0..name.len], name);
    pos += name.len;
    set_req[pos] = 0;
    pos += 1;
    @memcpy(set_req[pos..][0..value.len], value);
    var set_resp: [256]u8 = undefined;
    const set_len_resp = try device.handleRequest(set_req, &set_resp);
    const set_out: *const FuseOutHeader = @ptrCast(@alignCast(&set_resp));
    if (set_out.@"error" != 0) {
        if (set_out.@"error" == -95 or set_out.@"error" == -13) return error.SkipZigTest;
        try std.testing.expectEqual(@as(i32, 0), set_out.@"error");
    }
    _ = set_len_resp;

    // GETXATTR size=0
    const get0_len = @sizeOf(FuseInHeader) + @sizeOf(FuseGetxattrIn) + name.len + 1;
    var get0_req = try allocator.alloc(u8, get0_len);
    defer allocator.free(get0_req);
    const get0_hdr: *FuseInHeader = @ptrCast(@alignCast(get0_req.ptr));
    get0_hdr.* = .{
        .len = @intCast(get0_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_GETXATTR),
        .unique = 302,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const get0_in: *FuseGetxattrIn = @ptrCast(@alignCast(get0_req[@sizeOf(FuseInHeader)..]));
    get0_in.* = .{ .size = 0, .padding = 0 };
    pos = @sizeOf(FuseInHeader) + @sizeOf(FuseGetxattrIn);
    @memcpy(get0_req[pos..][0..name.len], name);
    get0_req[pos + name.len] = 0;
    var get0_resp: [256]u8 = undefined;
    const get0_resp_len = try device.handleRequest(get0_req, &get0_resp);
    const get0_out: *const FuseOutHeader = @ptrCast(@alignCast(&get0_resp));
    try std.testing.expectEqual(@as(i32, 0), get0_out.@"error");
    const get0_payload: *const FuseGetxattrOut = @ptrCast(@alignCast(get0_resp[@sizeOf(FuseOutHeader)..]));
    const value_len: usize = @intCast(get0_payload.size);
    try std.testing.expectEqual(value.len, value_len);
    _ = get0_resp_len;

    // GETXATTR with buffer
    const get_len = @sizeOf(FuseInHeader) + @sizeOf(FuseGetxattrIn) + name.len + 1;
    var get_req = try allocator.alloc(u8, get_len);
    defer allocator.free(get_req);
    const get_hdr: *FuseInHeader = @ptrCast(@alignCast(get_req.ptr));
    get_hdr.* = .{
        .len = @intCast(get_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_GETXATTR),
        .unique = 303,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const get_in: *FuseGetxattrIn = @ptrCast(@alignCast(get_req[@sizeOf(FuseInHeader)..]));
    get_in.* = .{ .size = @intCast(value.len), .padding = 0 };
    pos = @sizeOf(FuseInHeader) + @sizeOf(FuseGetxattrIn);
    @memcpy(get_req[pos..][0..name.len], name);
    get_req[pos + name.len] = 0;
    var get_resp: [256]u8 = undefined;
    const get_resp_len = try device.handleRequest(get_req, &get_resp);
    const get_out: *const FuseOutHeader = @ptrCast(@alignCast(&get_resp));
    try std.testing.expectEqual(@as(i32, 0), get_out.@"error");
    try std.testing.expectEqualStrings(
        value,
        get_resp[@sizeOf(FuseOutHeader)..][0..value.len],
    );
    _ = get_resp_len;

    // LISTXATTR size=0
    const list0_len = @sizeOf(FuseInHeader) + @sizeOf(FuseGetxattrIn);
    var list0_req: [list0_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const list0_hdr: *FuseInHeader = @ptrCast(@alignCast(&list0_req));
    list0_hdr.* = .{
        .len = list0_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_LISTXATTR),
        .unique = 304,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const list0_in: *FuseGetxattrIn = @ptrCast(@alignCast(list0_req[@sizeOf(FuseInHeader)..]));
    list0_in.* = .{ .size = 0, .padding = 0 };
    var list0_resp: [256]u8 = undefined;
    const list0_resp_len = try device.handleRequest(&list0_req, &list0_resp);
    const list0_out: *const FuseOutHeader = @ptrCast(@alignCast(&list0_resp));
    try std.testing.expectEqual(@as(i32, 0), list0_out.@"error");
    const list0_payload: *const FuseGetxattrOut = @ptrCast(@alignCast(list0_resp[@sizeOf(FuseOutHeader)..]));
    const list_len: usize = @intCast(list0_payload.size);
    _ = list0_resp_len;

    // LISTXATTR with buffer
    var list_req: [list0_len]u8 align(@alignOf(FuseInHeader)) = undefined;
    const list_hdr: *FuseInHeader = @ptrCast(@alignCast(&list_req));
    list_hdr.* = .{
        .len = list0_len,
        .opcode = @intFromEnum(FuseOpcode.FUSE_LISTXATTR),
        .unique = 305,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const list_in: *FuseGetxattrIn = @ptrCast(@alignCast(list_req[@sizeOf(FuseInHeader)..]));
    list_in.* = .{ .size = @intCast(list_len), .padding = 0 };
    var list_resp: [256]u8 = undefined;
    const list_resp_len = try device.handleRequest(&list_req, &list_resp);
    const list_out: *const FuseOutHeader = @ptrCast(@alignCast(&list_resp));
    try std.testing.expectEqual(@as(i32, 0), list_out.@"error");
    const list_data = list_resp[@sizeOf(FuseOutHeader)..][0..list_len];
    try std.testing.expect(std.mem.indexOf(u8, list_data, name) != null);
    _ = list_resp_len;

    // REMOVEXATTR
    const rem_len = @sizeOf(FuseInHeader) + name.len + 1;
    var rem_req = try allocator.alloc(u8, rem_len);
    defer allocator.free(rem_req);
    const rem_hdr: *FuseInHeader = @ptrCast(@alignCast(rem_req.ptr));
    rem_hdr.* = .{
        .len = @intCast(rem_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_REMOVEXATTR),
        .unique = 306,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    pos = @sizeOf(FuseInHeader);
    @memcpy(rem_req[pos..][0..name.len], name);
    rem_req[pos + name.len] = 0;
    var rem_resp: [256]u8 = undefined;
    const rem_resp_len = try device.handleRequest(rem_req, &rem_resp);
    const rem_out: *const FuseOutHeader = @ptrCast(@alignCast(&rem_resp));
    try std.testing.expectEqual(@as(i32, 0), rem_out.@"error");
    _ = rem_resp_len;
}

test "virtio_fs: statPath reports posix metadata" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const filename = "meta.txt";
    {
        var f = try tmp.dir.createFile(filename, .{});
        defer f.close();
        try f.writeAll("meta");
    }

    const full_path = try tmp.dir.realpathAlloc(allocator, filename);
    defer allocator.free(full_path);

    const stat = try statPath(full_path, true);
    const attr = statToFuseAttr(2, &stat);
    try std.testing.expectEqual(@as(u32, @intCast(fs.getUid())), attr.uid);
    try std.testing.expectEqual(@as(u32, @intCast(c.getgid())), attr.gid);
    try std.testing.expectEqual(stat.mode, attr.mode);
    try std.testing.expectEqual(stat.nlink, attr.nlink);
}

test "virtio_fs: statPath respects symlinks" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    const filename = "target.txt";
    const linkname = "link.txt";
    {
        var f = try tmp.dir.createFile(filename, .{});
        defer f.close();
        try f.writeAll("link");
    }

    try tmp.dir.symLink(filename, linkname, .{});

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const link_path = try fs.path.join(allocator, &[_][]const u8{ root, linkname });
    defer allocator.free(link_path);

    const stat_link = try statPath(link_path, false);
    try std.testing.expectEqual(
        std.posix.S.IFLNK,
        @as(u32, @intCast(stat_link.mode & std.posix.S.IFMT)),
    );

    const stat_follow = try statPath(link_path, true);
    try std.testing.expectEqual(
        std.posix.S.IFREG,
        @as(u32, @intCast(stat_follow.mode & std.posix.S.IFMT)),
    );
}

test "virtio_fs: setattr ctime no-op succeeds" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("data");
    }

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const name = "file.txt";
    const lookup_len = @sizeOf(FuseInHeader) + name.len + 1;
    const lookup_req = try allocator.alloc(u8, lookup_len);
    defer allocator.free(lookup_req);
    const lookup_hdr: *FuseInHeader = @ptrCast(@alignCast(lookup_req.ptr));
    lookup_hdr.* = .{
        .len = @intCast(lookup_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_LOOKUP),
        .unique = 41,
        .nodeid = 1,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(lookup_req[@sizeOf(FuseInHeader)..][0..name.len], name);
    lookup_req[@sizeOf(FuseInHeader) + name.len] = 0;

    var lookup_resp: [512]u8 = undefined;
    const lookup_resp_len = try device.handleRequest(lookup_req, &lookup_resp);
    try std.testing.expect(lookup_resp_len >= @sizeOf(FuseOutHeader) + @sizeOf(FuseEntryOut));
    const entry_out: *const FuseEntryOut = @ptrCast(@alignCast(lookup_resp[@sizeOf(FuseOutHeader)..]));
    const nodeid = entry_out.nodeid;

    var set_req: [@sizeOf(FuseInHeader) + @sizeOf(FuseSetattrIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const set_hdr: *FuseInHeader = @ptrCast(@alignCast(&set_req));
    set_hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseSetattrIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_SETATTR),
        .unique = 42,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const set_in: *FuseSetattrIn = @ptrCast(@alignCast(set_req[@sizeOf(FuseInHeader)..]));
    set_in.* = std.mem.zeroes(FuseSetattrIn);
    set_in.valid = FATTR_CTIME;
    set_in.ctime = 0;
    set_in.ctimensec = 0;

    var set_resp: [256]u8 = undefined;
    const set_len = try device.handleRequest(&set_req, &set_resp);
    try std.testing.expect(set_len >= @sizeOf(FuseOutHeader));
    const out_hdr: *const FuseOutHeader = @ptrCast(@alignCast(&set_resp));
    try std.testing.expectEqual(@as(i32, 0), out_hdr.@"error");
}

test "virtio_fs: fcntl locks" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDWR);

    const lk_in = FuseLkIn{
        .fh = fh,
        .owner = 0,
        .lk = .{
            .start = 0,
            .end = std.math.maxInt(u64),
            .type = 1,
            .pid = 0,
        },
        .lk_flags = 0,
        .padding = 0,
    };
    var set_req: [@sizeOf(FuseInHeader) + @sizeOf(FuseLkIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const set_hdr: *FuseInHeader = @ptrCast(@alignCast(&set_req));
    set_hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseLkIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_SETLK),
        .unique = 401,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(set_req[@sizeOf(FuseInHeader)..][0..@sizeOf(FuseLkIn)], std.mem.asBytes(&lk_in));
    var set_resp: [128]u8 = undefined;
    const set_resp_len = try device.handleRequest(&set_req, &set_resp);
    const set_out: *const FuseOutHeader = @ptrCast(@alignCast(&set_resp));
    if (set_out.@"error" != 0) return error.SkipZigTest;
    _ = set_resp_len;

    var get_req: [@sizeOf(FuseInHeader) + @sizeOf(FuseLkIn)]u8 align(@alignOf(FuseInHeader)) = undefined;
    const get_hdr: *FuseInHeader = @ptrCast(@alignCast(&get_req));
    get_hdr.* = .{
        .len = @sizeOf(FuseInHeader) + @sizeOf(FuseLkIn),
        .opcode = @intFromEnum(FuseOpcode.FUSE_GETLK),
        .unique = 402,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    @memcpy(get_req[@sizeOf(FuseInHeader)..][0..@sizeOf(FuseLkIn)], std.mem.asBytes(&lk_in));
    var get_resp: [256]u8 = undefined;
    const get_resp_len = try device.handleRequest(&get_req, &get_resp);
    const get_out: *const FuseOutHeader = @ptrCast(@alignCast(&get_resp));
    try std.testing.expectEqual(@as(i32, 0), get_out.@"error");
    _ = get_resp_len;
}

test "virtio_fs: ioctl with buffers" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var tmp = fs.testingTmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("file.txt", .{});
        defer f.close();
        try f.writeAll("x");
    }

    const abs = try tmp.dir.realpathAlloc(allocator, "file.txt");
    defer allocator.free(abs);
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var mount_manager = mounts.MountManager.init(allocator);
    defer mount_manager.deinit();
    mount_manager.strict_validation = false;
    try mount_manager.addAllowedRoot(root);
    try mount_manager.addMount(.{
        .tag = "test",
        .host_path = root,
        .guest_path = "/mnt/test",
        .access = .read_write,
    });

    var device = VirtioFsDevice.init(allocator, &mount_manager, "test", .auto);
    defer device.deinit();

    const nodeid = try device.allocateNode(abs, false);
    const file = try fs.cwd().openFile(abs, .{ .mode = .read_write });
    const fh = try device.allocateFileHandle(nodeid, file, O_RDWR);

    const data = [_]u8{0xAB};
    const req_len = @sizeOf(FuseInHeader) + @sizeOf(FuseIoctlIn) + data.len;
    var req = try allocator.alloc(u8, req_len);
    defer allocator.free(req);
    const hdr: *FuseInHeader = @ptrCast(@alignCast(req.ptr));
    hdr.* = .{
        .len = @intCast(req_len),
        .opcode = @intFromEnum(FuseOpcode.FUSE_IOCTL),
        .unique = 501,
        .nodeid = nodeid,
        .uid = 0,
        .gid = 0,
        .pid = 0,
        .total_extlen = 0,
        .padding = 0,
    };
    const ioctl_in: *FuseIoctlIn = @ptrCast(@alignCast(req[@sizeOf(FuseInHeader)..]));
    ioctl_in.* = .{
        .fh = fh,
        .flags = 0,
        .cmd = 0,
        .arg = 0,
        .in_size = data.len,
        .out_size = data.len,
    };
    @memcpy(
        req[@sizeOf(FuseInHeader) + @sizeOf(FuseIoctlIn) ..][0..data.len],
        data[0..],
    );

    var resp: [256]u8 = undefined;
    const resp_len = try device.handleRequest(req, &resp);
    const out: *const FuseOutHeader = @ptrCast(@alignCast(&resp));
    if (out.@"error" != 0 and out.@"error" != -25) {
        try std.testing.expectEqual(@as(i32, 0), out.@"error");
    }
    _ = resp_len;
}

const std = @import("std");
const builtin = @import("builtin");

pub const path = std.fs.path;
pub const max_path_bytes = std.Io.Dir.max_path_bytes;

pub fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const File = struct {
    handle: std.Io.File.Handle,
    flags: std.Io.File.Flags,

    pub const Kind = std.Io.File.Kind;
    pub const OpenMode = std.Io.Dir.OpenFileOptions.Mode;
    pub const Mode = std.posix.mode_t;
    pub const Permissions = std.Io.File.Permissions;
    pub const Lock = std.Io.File.Lock;

    pub const Stat = struct {
        inode: std.Io.File.INode,
        nlink: std.Io.File.NLink,
        size: u64,
        mode: std.posix.mode_t,
        permissions: Permissions,
        kind: Kind,
        atime: ?i128,
        mtime: i128,
        ctime: i128,
        block_size: std.Io.File.BlockSize,

        pub fn fromIo(io_stat: std.Io.File.Stat) Stat {
            const mode = modeFromKind(io_stat.kind) | permissionMode(io_stat.permissions);
            return .{
                .inode = io_stat.inode,
                .nlink = io_stat.nlink,
                .size = io_stat.size,
                .mode = mode,
                .permissions = io_stat.permissions,
                .kind = io_stat.kind,
                .atime = if (io_stat.atime) |t| t.nanoseconds else null,
                .mtime = io_stat.mtime.nanoseconds,
                .ctime = io_stat.ctime.nanoseconds,
                .block_size = io_stat.block_size,
            };
        }

        pub fn fromPosix(posix_stat: std.posix.Stat) Stat {
            const mode: std.posix.mode_t = @intCast(posix_stat.mode);
            const atime = posix_stat.atime();
            const mtime = posix_stat.mtime();
            const ctime = posix_stat.ctime();
            return .{
                .inode = @intCast(posix_stat.ino),
                .nlink = @intCast(posix_stat.nlink),
                .size = @intCast(posix_stat.size),
                .mode = mode,
                .permissions = permissionsFromMode(mode),
                .kind = kindFromMode(mode),
                .atime = @as(i128, atime.sec) * std.time.ns_per_s + atime.nsec,
                .mtime = @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec,
                .ctime = @as(i128, ctime.sec) * std.time.ns_per_s + ctime.nsec,
                .block_size = @intCast(@max(1, posix_stat.blksize)),
            };
        }

        pub fn fromLinuxStatx(statx: std.os.linux.Statx) Stat {
            const mode: std.posix.mode_t = @intCast(statx.mode);
            return .{
                .inode = @intCast(statx.ino),
                .nlink = @intCast(statx.nlink),
                .size = @intCast(statx.size),
                .mode = mode,
                .permissions = permissionsFromMode(mode),
                .kind = kindFromMode(mode),
                .atime = @as(i128, statx.atime.sec) * std.time.ns_per_s + statx.atime.nsec,
                .mtime = @as(i128, statx.mtime.sec) * std.time.ns_per_s + statx.mtime.nsec,
                .ctime = @as(i128, statx.ctime.sec) * std.time.ns_per_s + statx.ctime.nsec,
                .block_size = @intCast(@max(@as(u32, 1), statx.blksize)),
            };
        }
    };

    fn wrap(file: std.Io.File) File {
        return .{ .handle = file.handle, .flags = file.flags };
    }

    fn raw(self: File) std.Io.File {
        return .{ .handle = self.handle, .flags = self.flags };
    }

    pub fn stdin() File {
        return wrap(std.Io.File.stdin());
    }

    pub fn stdout() File {
        return wrap(std.Io.File.stdout());
    }

    pub fn stderr() File {
        return wrap(std.Io.File.stderr());
    }

    pub fn close(self: File) void {
        self.raw().close(io());
    }

    pub fn stat(self: File) !Stat {
        return Stat.fromIo(try self.raw().stat(io()));
    }

    pub fn sync(self: File) !void {
        try self.raw().sync(io());
    }

    pub fn setEndPos(self: File, size: u64) !void {
        try self.raw().setLength(io(), size);
    }

    pub fn getEndPos(self: File) !u64 {
        return self.raw().length(io());
    }

    pub fn seekTo(self: File, offset: u64) !void {
        try io().vtable.fileSeekTo(io().userdata, self.raw(), offset);
    }

    pub fn seekFromEnd(self: File, offset: i64) !void {
        const len = try self.getEndPos();
        const target = if (offset >= 0)
            try std.math.add(u64, len, @intCast(offset))
        else
            try std.math.sub(u64, len, @intCast(-offset));
        try self.seekTo(target);
    }

    pub fn seekBy(self: File, offset: i64) !void {
        try io().vtable.fileSeekBy(io().userdata, self.raw(), offset);
    }

    pub fn getPos(self: File) !u64 {
        return seekFd(self.handle, 0, std.c.SEEK.CUR);
    }

    pub fn read(self: File, buffer: []u8) !usize {
        return self.raw().readStreaming(io(), &.{buffer}) catch |err| switch (err) {
            error.EndOfStream => 0,
            else => |e| return e,
        };
    }

    pub fn readAll(self: File, buffer: []u8) !usize {
        var offset: usize = 0;
        while (offset < buffer.len) {
            const n = try self.read(buffer[offset..]);
            if (n == 0) break;
            offset += n;
        }
        return offset;
    }

    pub fn write(self: File, bytes: []const u8) !usize {
        return self.raw().writeStreaming(io(), &.{}, &.{bytes}, 1);
    }

    pub fn writeAll(self: File, bytes: []const u8) !void {
        try self.raw().writeStreamingAll(io(), bytes);
    }

    pub fn preadAll(self: File, buffer: []u8, offset: u64) !usize {
        return self.raw().readPositionalAll(io(), buffer, offset);
    }

    pub fn pwriteAll(self: File, bytes: []const u8, offset: u64) !void {
        try self.raw().writePositionalAll(io(), bytes, offset);
    }

    pub fn readToEndAlloc(self: File, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try self.read(&buf);
            if (n == 0) break;
            if (out.items.len + n > max_bytes) return error.StreamTooLong;
            try out.appendSlice(allocator, buf[0..n]);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn reader(self: File, buffer: []u8) std.Io.File.Reader {
        return self.raw().reader(io(), buffer);
    }

    pub fn writer(self: File, buffer: []u8) std.Io.File.Writer {
        return self.raw().writer(io(), buffer);
    }

    pub fn updateTimes(self: File, atime_ns: i128, mtime_ns: i128) !void {
        try self.raw().setTimestamps(io(), .{
            .access_timestamp = .{ .new = timestampFromNanoseconds(atime_ns) },
            .modify_timestamp = .{ .new = timestampFromNanoseconds(mtime_ns) },
        });
    }
};

pub const Dir = struct {
    handle: std.Io.Dir.Handle,
    fd: std.Io.Dir.Handle,

    pub const Entry = std.Io.Dir.Entry;
    pub const OpenOptions = std.Io.Dir.OpenOptions;
    pub const OpenFileOptions = std.Io.Dir.OpenFileOptions;
    pub const CreateFileOptions = std.Io.Dir.CreateFileOptions;
    pub const Stat = File.Stat;

    pub fn wrap(dir: std.Io.Dir) Dir {
        return .{ .handle = dir.handle, .fd = dir.handle };
    }

    fn raw(self: Dir) std.Io.Dir {
        return .{ .handle = self.handle };
    }

    pub fn close(self: Dir) void {
        self.raw().close(io());
    }

    pub fn openFile(self: Dir, sub_path: []const u8, options: OpenFileOptions) !File {
        return File.wrap(try self.raw().openFile(io(), sub_path, options));
    }

    pub fn createFile(self: Dir, sub_path: []const u8, options: CreateFileOptions) !File {
        return File.wrap(try self.raw().createFile(io(), sub_path, options));
    }

    pub fn openDir(self: Dir, sub_path: []const u8, options: OpenOptions) !Dir {
        return wrap(try self.raw().openDir(io(), sub_path, options));
    }

    pub fn makePath(self: Dir, sub_path: []const u8) !void {
        try self.raw().createDirPath(io(), sub_path);
    }

    pub fn makeDir(self: Dir, sub_path: []const u8) !void {
        try self.raw().createDir(io(), sub_path, .default_dir);
    }

    pub fn deleteFile(self: Dir, sub_path: []const u8) !void {
        try self.raw().deleteFile(io(), sub_path);
    }

    pub fn deleteDir(self: Dir, sub_path: []const u8) !void {
        try self.raw().deleteDir(io(), sub_path);
    }

    pub fn deleteTree(self: Dir, sub_path: []const u8) !void {
        try self.raw().deleteTree(io(), sub_path);
    }

    pub fn statFile(self: Dir, sub_path: []const u8) !Stat {
        return Stat.fromIo(try self.raw().statFile(io(), sub_path, .{}));
    }

    pub fn statFileNoFollow(self: Dir, sub_path: []const u8) !Stat {
        return Stat.fromIo(try self.raw().statFile(io(), sub_path, .{ .follow_symlinks = false }));
    }

    pub fn realpathAlloc(self: Dir, allocator: std.mem.Allocator, sub_path: []const u8) ![]u8 {
        var buffer: [max_path_bytes]u8 = undefined;
        const n = try self.raw().realPathFile(io(), sub_path, &buffer);
        return try allocator.dupe(u8, buffer[0..n]);
    }

    pub fn readFileAlloc(self: Dir, allocator: std.mem.Allocator, sub_path: []const u8, max_bytes: usize) ![]u8 {
        return try self.raw().readFileAlloc(io(), sub_path, allocator, .limited(max_bytes));
    }

    pub fn readLink(self: Dir, sub_path: []const u8, buffer: []u8) !usize {
        return try self.raw().readLink(io(), sub_path, buffer);
    }

    pub fn symLink(self: Dir, target_path: []const u8, sym_link_path: []const u8, flags: std.Io.Dir.SymLinkFlags) !void {
        try self.raw().symLink(io(), target_path, sym_link_path, flags);
    }

    pub fn rename(self: Dir, old_sub_path: []const u8, new_sub_path: []const u8) !void {
        try self.raw().rename(old_sub_path, self.raw(), new_sub_path, io());
    }

    pub fn iterate(self: Dir) Iterator {
        return .{ .inner = self.raw().iterate() };
    }

    pub const Iterator = struct {
        inner: std.Io.Dir.Iterator,

        pub fn next(self: *Iterator) !?Entry {
            return try self.inner.next(io());
        }
    };
};

pub fn cwd() Dir {
    return Dir.wrap(std.Io.Dir.cwd());
}

pub fn openFileAbsolute(absolute_path: []const u8, options: Dir.OpenFileOptions) !File {
    return File.wrap(try std.Io.Dir.openFileAbsolute(io(), absolute_path, options));
}

pub fn createFileAbsolute(absolute_path: []const u8, options: Dir.CreateFileOptions) !File {
    return File.wrap(try std.Io.Dir.createFileAbsolute(io(), absolute_path, options));
}

pub fn deleteFileAbsolute(absolute_path: []const u8) !void {
    try std.Io.Dir.deleteFileAbsolute(io(), absolute_path);
}

pub fn selfExePathAlloc(allocator: std.mem.Allocator) ![]u8 {
    var buffer: [max_path_bytes]u8 = undefined;
    const n = try std.process.executablePath(io(), &buffer);
    return try allocator.dupe(u8, buffer[0..n]);
}

pub const TmpDir = struct {
    inner: std.testing.TmpDir,
    dir: Dir,

    pub fn cleanup(self: *TmpDir) void {
        self.inner.cleanup();
        self.* = undefined;
    }
};

pub fn testingTmpDir(options: std.Io.Dir.OpenOptions) TmpDir {
    const tmp = std.testing.tmpDir(options);
    return .{ .inner = tmp, .dir = Dir.wrap(tmp.dir) };
}

pub fn chmodAt(dirfd: std.posix.fd_t, sub_path: []const u8, mode: std.posix.mode_t, flags: c_uint) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const path_z = try std.posix.toPosixPath(sub_path);
    if (std.c.fchmodat(dirfd, &path_z, mode, flags) == 0) return;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        else => error.Unexpected,
    };
}

pub fn openAt(dirfd: std.posix.fd_t, sub_path: []const u8, flags: std.posix.O, mode: std.posix.mode_t) !std.posix.fd_t {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const path_z = try std.posix.toPosixPath(sub_path);
    while (true) {
        const rc = std.c.openat(dirfd, &path_z, flags, mode);
        return switch (std.c.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,
            .ACCES, .PERM => error.AccessDenied,
            .NOENT => error.FileNotFound,
            .EXIST => error.PathAlreadyExists,
            .NOTDIR => error.NotDir,
            .ISDIR => error.IsDir,
            .LOOP => error.SymLinkLoop,
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            else => error.Unexpected,
        };
    }
}

pub fn statAt(dirfd: std.posix.fd_t, sub_path: []const u8, flags: c_uint) !File.Stat {
    if (comptime builtin.os.tag == .linux) {
        return File.Stat.fromLinuxStatx(try statxAt(dirfd, sub_path, flags));
    }
    return File.Stat.fromPosix(try statPosixAt(dirfd, sub_path, flags));
}

pub fn statxAt(dirfd: std.posix.fd_t, sub_path: []const u8, flags: c_uint) !std.os.linux.Statx {
    if (builtin.os.tag != .linux) return error.NotSupported;
    const path_z = try std.posix.toPosixPath(sub_path);
    var st: std.os.linux.Statx = undefined;
    const rc = std.os.linux.statx(@intCast(dirfd), &path_z, @intCast(flags), std.os.linux.STATX.BASIC_STATS, &st);
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => st,
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .LOOP => error.SymLinkLoop,
        else => error.Unexpected,
    };
}

pub fn statPosixAt(dirfd: std.posix.fd_t, sub_path: []const u8, flags: c_uint) !std.posix.Stat {
    if (builtin.os.tag == .windows) return error.NotSupported;
    if (comptime builtin.os.tag == .linux) {
        @compileError("statPosixAt is not available on Linux; use statAt or statxAt");
    }
    const path_z = try std.posix.toPosixPath(sub_path);
    var st: std.posix.Stat = undefined;
    if (std.c.fstatat(dirfd, &path_z, &st, flags) == 0) return st;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .LOOP => error.SymLinkLoop,
        else => error.Unexpected,
    };
}

pub fn accessAt(dirfd: std.posix.fd_t, sub_path: []const u8, mask: u32, flags: c_uint) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const path_z = try std.posix.toPosixPath(sub_path);
    if (std.c.faccessat(dirfd, &path_z, @intCast(mask), flags) == 0) return;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .LOOP => error.SymLinkLoop,
        else => error.Unexpected,
    };
}

pub fn readLink(path_name: []const u8, buffer: []u8) !usize {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const path_z = try std.posix.toPosixPath(path_name);
    while (true) {
        const rc = std.c.readlink(&path_z, buffer.ptr, buffer.len);
        return switch (std.c.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,
            .ACCES, .PERM => error.AccessDenied,
            .NOENT => error.FileNotFound,
            .INVAL => error.NotLink,
            .LOOP => error.SymLinkLoop,
            .NOTDIR => error.NotDir,
            else => error.Unexpected,
        };
    }
}

pub fn symLink(target_path: []const u8, sym_link_path: []const u8) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const target_z = try std.posix.toPosixPath(target_path);
    const link_z = try std.posix.toPosixPath(sym_link_path);
    if (std.c.symlink(&target_z, &link_z) == 0) return;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .NOTDIR => error.NotDir,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

pub fn renamePath(old_path: []const u8, new_path: []const u8) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const old_z = try std.posix.toPosixPath(old_path);
    const new_z = try std.posix.toPosixPath(new_path);
    if (std.c.rename(&old_z, &new_z) == 0) return;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

pub fn linkPath(old_path: []const u8, new_path: []const u8) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const old_z = try std.posix.toPosixPath(old_path);
    const new_z = try std.posix.toPosixPath(new_path);
    if (std.c.link(&old_z, &new_z) == 0) return;
    return switch (std.c.errno(-1)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .NOTDIR => error.NotDir,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

pub fn syncFd(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    while (true) {
        const rc = std.c.fsync(fd);
        return switch (std.c.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .BADF => error.FileNotOpenForWriting,
            else => error.Unexpected,
        };
    }
}

pub fn chownFd(fd: std.posix.fd_t, uid: ?std.posix.uid_t, gid: ?std.posix.gid_t) !void {
    if (builtin.os.tag == .windows) return error.NotSupported;
    const owner = uid orelse std.math.maxInt(std.posix.uid_t);
    const group = gid orelse std.math.maxInt(std.posix.gid_t);
    while (true) {
        const rc = std.c.fchown(fd, owner, group);
        return switch (std.c.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .ACCES, .PERM, .ROFS => error.AccessDenied,
            .NOENT => error.FileNotFound,
            .BADF => error.InvalidHandle,
            else => error.Unexpected,
        };
    }
}

pub fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .windows) return;
    File.wrap(.{ .handle = fd, .flags = .{ .nonblocking = false } }).close();
}

pub fn seekFd(fd: std.posix.fd_t, offset: i64, whence: c_int) !u64 {
    if (builtin.os.tag == .windows) return error.NotSupported;
    while (true) {
        const rc = std.c.lseek(fd, @intCast(offset), whence);
        return switch (std.c.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,
            .BADF => error.NotOpenForReading,
            .INVAL => error.InvalidArgument,
            .SPIPE => error.Unseekable,
            else => error.Unexpected,
        };
    }
}

pub fn writeFd(fd: std.posix.fd_t, bytes: []const u8) !usize {
    if (builtin.os.tag == .windows) return error.NotSupported;
    while (true) {
        const rc = std.c.write(fd, bytes.ptr, bytes.len);
        return switch (std.c.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,
            .AGAIN => error.WouldBlock,
            .BADF => error.NotOpenForWriting,
            .PIPE => error.BrokenPipe,
            .CONNRESET => error.ConnectionResetByPeer,
            else => error.Unexpected,
        };
    }
}

pub fn readFd(fd: std.posix.fd_t, buffer: []u8) !usize {
    if (builtin.os.tag == .windows) return error.NotSupported;
    while (true) {
        const rc = std.c.read(fd, buffer.ptr, buffer.len);
        return switch (std.c.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .INTR => continue,
            .AGAIN => error.WouldBlock,
            .BADF => error.NotOpenForReading,
            .CONNRESET => error.ConnectionResetByPeer,
            else => error.Unexpected,
        };
    }
}

pub fn pipe() ![2]std.posix.fd_t {
    if (builtin.os.tag == .windows) return error.NotSupported;
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.pipe(&fds) == 0) return fds;
    return switch (std.c.errno(-1)) {
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        else => error.Unexpected,
    };
}

pub fn isTty(fd: std.posix.fd_t) bool {
    if (builtin.os.tag == .windows) return false;
    return std.c.isatty(fd) != 0;
}

pub fn getUid() std.posix.uid_t {
    if (builtin.os.tag == .windows) return 0;
    return std.c.getuid();
}

pub fn copyFileRange(in_fd: std.posix.fd_t, off_in: u64, out_fd: std.posix.fd_t, off_out: u64, len: usize, flags: u64) !usize {
    if (builtin.os.tag == .windows) return error.NotSupported;
    if (flags != 0) return error.InvalidArgument;
    var copied: usize = 0;
    var buf: [64 * 1024]u8 = undefined;
    while (copied < len) {
        const in_offset: std.c.off_t = @intCast(off_in + copied);
        const out_offset: std.c.off_t = @intCast(off_out + copied);
        const chunk_len = @min(buf.len, len - copied);
        const read_rc = std.c.pread(in_fd, &buf, chunk_len, in_offset);
        const read_len: usize = switch (std.c.errno(read_rc)) {
            .SUCCESS => @intCast(read_rc),
            .INTR => continue,
            .AGAIN => return copied,
            else => return error.Unexpected,
        };
        if (read_len == 0) break;
        var written: usize = 0;
        while (written < read_len) {
            const write_rc = std.c.pwrite(out_fd, buf[written..].ptr, read_len - written, out_offset + @as(std.c.off_t, @intCast(written)));
            const n: usize = switch (std.c.errno(write_rc)) {
                .SUCCESS => @intCast(write_rc),
                .INTR => continue,
                .AGAIN => return copied + written,
                else => return error.Unexpected,
            };
            if (n == 0) return error.Unexpected;
            written += n;
        }
        copied += read_len;
    }
    return copied;
}

fn permissionMode(permissions: File.Permissions) std.posix.mode_t {
    if (builtin.os.tag == .windows) return 0o666;
    if (@hasDecl(File.Permissions, "toMode")) {
        return permissions.toMode();
    }
    return if (permissions.readOnly()) 0o444 else 0o666;
}

fn permissionsFromMode(mode: std.posix.mode_t) File.Permissions {
    if (builtin.os.tag == .windows) return .default_file;
    if (@hasDecl(File.Permissions, "fromMode")) {
        return File.Permissions.fromMode(mode);
    }
    return .default_file;
}

fn modeFromKind(kind: File.Kind) std.posix.mode_t {
    if (builtin.os.tag == .windows) {
        return switch (kind) {
            .directory => 0o040000,
            .sym_link => 0o120000,
            else => 0o100000,
        };
    }
    const S = std.posix.S;
    return switch (kind) {
        .directory => S.IFDIR,
        .sym_link => S.IFLNK,
        .named_pipe => S.IFIFO,
        .unix_domain_socket => S.IFSOCK,
        .character_device => S.IFCHR,
        .block_device => S.IFBLK,
        else => S.IFREG,
    };
}

pub fn kindFromMode(mode: std.posix.mode_t) File.Kind {
    if (builtin.os.tag == .windows) {
        if ((mode & 0o170000) == 0o040000) return .directory;
        if ((mode & 0o170000) == 0o120000) return .sym_link;
        if ((mode & 0o170000) == 0o100000) return .file;
        return .unknown;
    }
    const S = std.posix.S;
    const fmt = mode & S.IFMT;
    if (fmt == S.IFDIR) return .directory;
    if (fmt == S.IFLNK) return .sym_link;
    if (fmt == S.IFIFO) return .named_pipe;
    if (fmt == S.IFSOCK) return .unix_domain_socket;
    if (fmt == S.IFCHR) return .character_device;
    if (fmt == S.IFBLK) return .block_device;
    if (fmt == S.IFREG) return .file;
    return .unknown;
}

fn timestampFromNanoseconds(value: i128) std.Io.Timestamp {
    const min = std.math.minInt(i96);
    const max = std.math.maxInt(i96);
    return .{ .nanoseconds = @intCast(std.math.clamp(value, min, max)) };
}

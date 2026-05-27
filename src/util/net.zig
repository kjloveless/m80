const std = @import("std");
const fs = @import("fs.zig");
const builtin = @import("builtin");

const posix = std.posix;
const windows = std.os.windows;
const is_windows = builtin.os.tag == .windows;

pub const has_unix_sockets = std.Io.net.has_unix_sockets;

pub const Address = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
    un: if (has_unix_sockets) posix.sockaddr.un else void,

    pub const ListenOptions = struct {
        kernel_backlog: u31 = std.Io.net.default_kernel_backlog,
        reuse_address: bool = false,
        force_nonblocking: bool = false,
    };

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        var raw_addr: u32 = undefined;
        @memcpy(std.mem.asBytes(&raw_addr), &addr);
        return .{ .in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = raw_addr,
        } };
    }

    pub fn initUnix(socket_path: []const u8) !Address {
        if (!has_unix_sockets) return error.AddressFamilyUnsupported;
        var sock_addr = posix.sockaddr.un{
            .family = posix.AF.UNIX,
            .path = undefined,
        };
        if (socket_path.len + 1 > sock_addr.path.len) return error.NameTooLong;
        @memset(&sock_addr.path, 0);
        @memcpy(sock_addr.path[0..socket_path.len], socket_path);
        return .{ .un = sock_addr };
    }

    pub fn initPosix(addr: *align(4) const posix.sockaddr) Address {
        return switch (addr.family) {
            posix.AF.INET => .{ .in = @as(*const posix.sockaddr.in, @ptrCast(addr)).* },
            posix.AF.INET6 => .{ .in6 = @as(*const posix.sockaddr.in6, @ptrCast(addr)).* },
            else => unreachable,
        };
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => std.mem.bigToNative(u16, self.in.port),
            posix.AF.INET6 => std.mem.bigToNative(u16, self.in6.port),
            else => unreachable,
        };
    }

    pub fn toIpAddress(self: Address) std.Io.net.IpAddress {
        return switch (self.any.family) {
            posix.AF.INET => .{ .ip4 = .{
                .bytes = std.mem.toBytes(self.in.addr),
                .port = std.mem.bigToNative(u16, self.in.port),
            } },
            posix.AF.INET6 => .{ .ip6 = .{
                .bytes = self.in6.addr,
                .port = std.mem.bigToNative(u16, self.in6.port),
                .flow = self.in6.flowinfo,
                .interface = .{ .index = self.in6.scope_id },
            } },
            else => unreachable,
        };
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            posix.AF.UNIX => if (has_unix_sockets) @sizeOf(posix.sockaddr.un) else unreachable,
            else => unreachable,
        };
    }

    pub fn listen(address: Address, options: ListenOptions) !Server {
        if (!has_unix_sockets) return error.AddressFamilyUnsupported;
        if (address.any.family != posix.AF.UNIX) return error.AddressFamilyUnsupported;

        const socket_path = std.mem.sliceTo(&address.un.path, 0);
        const unix_address = try std.Io.net.UnixAddress.init(socket_path);
        const raw_server = try unix_address.listen(fs.io(), .{ .kernel_backlog = options.kernel_backlog });
        errdefer raw_server.socket.close(fs.io());

        if (options.force_nonblocking) {
            try setNonblocking(raw_server.socket.handle, true);
        }

        return .{
            .listen_address = address,
            .stream = .{ .handle = raw_server.socket.handle },
        };
    }
};

const pipe_access_duplex: windows.DWORD = 0x00000003;
const pipe_type_byte: windows.DWORD = 0x00000000;
const pipe_readmode_byte: windows.DWORD = 0x00000000;
const pipe_wait: windows.DWORD = 0x00000000;
const pipe_reject_remote_clients: windows.DWORD = 0x00000008;
const pipe_unlimited_instances: windows.DWORD = 255;
const file_flag_first_pipe_instance: windows.DWORD = 0x00080000;
const generic_read: windows.DWORD = 0x80000000;
const generic_write: windows.DWORD = 0x40000000;
const open_existing: windows.DWORD = 3;
const file_attribute_normal: windows.DWORD = 0x00000080;
const named_pipe_wait_ms: windows.DWORD = 5000;
const sddl_revision_1: windows.DWORD = 1;
const owner_only_pipe_sddl = std.unicode.utf8ToUtf16LeStringLiteral("D:P(A;;GA;;;OW)");

extern "kernel32" fn CreateNamedPipeW(
    lpName: [*:0]const u16,
    dwOpenMode: windows.DWORD,
    dwPipeMode: windows.DWORD,
    nMaxInstances: windows.DWORD,
    nOutBufferSize: windows.DWORD,
    nInBufferSize: windows.DWORD,
    nDefaultTimeOut: windows.DWORD,
    lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
) callconv(.winapi) windows.HANDLE;

extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
    StringSecurityDescriptor: [*:0]const u16,
    StringSDRevision: windows.DWORD,
    SecurityDescriptor: *?*anyopaque,
    SecurityDescriptorSize: ?*windows.ULONG,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

extern "kernel32" fn ConnectNamedPipe(
    hNamedPipe: windows.HANDLE,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: windows.DWORD,
    dwShareMode: windows.DWORD,
    lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
    dwCreationDisposition: windows.DWORD,
    dwFlagsAndAttributes: windows.DWORD,
    hTemplateFile: ?windows.HANDLE,
) callconv(.winapi) windows.HANDLE;

extern "kernel32" fn WaitNamedPipeW(
    lpNamedPipeName: [*:0]const u16,
    nTimeOut: windows.DWORD,
) callconv(.winapi) windows.BOOL;

const LocalHandle = if (is_windows) std.Io.File.Handle else std.Io.net.Socket.Handle;

pub const Stream = struct {
    handle: LocalHandle,

    fn raw(self: Stream) std.Io.net.Stream {
        return .{ .socket = .{
            .handle = self.handle,
            .address = .{ .ip4 = .loopback(0) },
        } };
    }

    fn rawFile(self: Stream) std.Io.File {
        return .{
            .handle = self.handle,
            .flags = .{ .nonblocking = false },
        };
    }

    pub fn close(self: Stream) void {
        if (is_windows) {
            self.rawFile().close(fs.io());
        } else {
            self.raw().close(fs.io());
        }
    }

    pub fn reader(self: Stream, buffer: []u8) if (is_windows) std.Io.File.Reader else std.Io.net.Stream.Reader {
        if (is_windows) {
            return self.rawFile().reader(fs.io(), buffer);
        }
        return self.raw().reader(fs.io(), buffer);
    }

    pub fn writer(self: Stream, buffer: []u8) if (is_windows) std.Io.File.Writer else std.Io.net.Stream.Writer {
        if (is_windows) {
            return self.rawFile().writer(fs.io(), buffer);
        }
        return self.raw().writer(fs.io(), buffer);
    }

    pub fn write(self: Stream, bytes: []const u8) !usize {
        var write_buf: [4096]u8 = undefined;
        var w = self.writer(&write_buf);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
        return bytes.len;
    }

    pub fn read(self: Stream, buffer: []u8) !usize {
        var read_buf: [4096]u8 = undefined;
        var r = self.reader(&read_buf);
        return r.interface.readSliceShort(buffer);
    }

    pub fn writeAll(self: Stream, bytes: []const u8) !void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.write(bytes[index..]);
        }
    }
};

pub const Server = struct {
    listen_address: Address,
    stream: ?Stream = null,
    pipe_name: ?[:0]u16 = null,
    pipe_first_instance: bool = false,

    pub const Connection = struct {
        stream: Stream,
        address: Address,
    };

    pub fn deinit(self: *Server) void {
        if (self.stream) |stream| stream.close();
        if (self.pipe_name) |pipe_name| std.heap.page_allocator.free(pipe_name);
        self.* = undefined;
    }

    pub fn accept(self: *Server) !Connection {
        if (is_windows) {
            const pipe_name = self.pipe_name orelse return error.NotOpenForReading;
            const stream = try acceptNamedPipe(pipe_name, self.pipe_first_instance);
            self.pipe_first_instance = false;
            return .{
                .stream = stream,
                .address = self.listen_address,
            };
        }
        const listen_stream = self.stream orelse return error.NotOpenForReading;
        const handle = while (true) {
            const rc = std.c.accept(listen_stream.handle, null, null);
            break switch (std.c.errno(rc)) {
                .SUCCESS => @as(std.Io.net.Socket.Handle, @intCast(rc)),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .ACCES, .PERM => return error.AccessDenied,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                else => return error.Unexpected,
            };
        };
        return .{
            .stream = .{ .handle = handle },
            .address = self.listen_address,
        };
    }
};

pub fn listenLocalSocket(socket_path: []const u8, options: Address.ListenOptions) !Server {
    if (is_windows) {
        return .{
            .listen_address = Address.initIp4(.{ 127, 0, 0, 1 }, 0),
            .pipe_name = try namedPipeNameAlloc(socket_path),
            .pipe_first_instance = true,
        };
    }

    const address = try Address.initUnix(socket_path);
    return Address.listen(address, options);
}

pub fn connectUnixSocket(socket_path: []const u8) !Stream {
    if (is_windows) return connectNamedPipeClient(socket_path);

    if (!has_unix_sockets) return error.AddressFamilyUnsupported;
    const address = try std.Io.net.UnixAddress.init(socket_path);
    const stream = address.connect(fs.io()) catch |err| switch (err) {
        error.WouldBlock => return error.ConnectionRefused,
        else => |e| return e,
    };
    return .{ .handle = stream.socket.handle };
}

pub fn wakeLocalSocket(socket_path: []const u8) void {
    var stream = connectUnixSocket(socket_path) catch return;
    stream.close();
}

fn namedPipeNameAlloc(socket_path: []const u8) ![:0]u16 {
    const hash = std.hash.Wyhash.hash(0, socket_path);
    var pipe_name_buf: [64]u8 = undefined;
    const pipe_name = try std.fmt.bufPrint(&pipe_name_buf, "\\\\.\\pipe\\m80-{x:0>16}", .{hash});
    return std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, pipe_name);
}

const NamedPipeSecurity = struct {
    attrs: windows.SECURITY_ATTRIBUTES,
    descriptor: ?*anyopaque,

    fn init() !NamedPipeSecurity {
        var descriptor: ?*anyopaque = null;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            owner_only_pipe_sddl,
            sddl_revision_1,
            &descriptor,
            null,
        ).toBool()) {
            return switch (windows.GetLastError()) {
                .ACCESS_DENIED => error.AccessDenied,
                else => error.Unexpected,
            };
        }
        errdefer _ = LocalFree(descriptor);

        return .{
            .attrs = .{
                .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
                .lpSecurityDescriptor = descriptor,
                .bInheritHandle = windows.BOOL.FALSE,
            },
            .descriptor = descriptor,
        };
    }

    fn deinit(self: *NamedPipeSecurity) void {
        if (self.descriptor) |descriptor| {
            _ = LocalFree(descriptor);
            self.descriptor = null;
        }
    }
};

fn acceptNamedPipe(pipe_name: [:0]const u16, first_instance: bool) !Stream {
    var security = try NamedPipeSecurity.init();
    defer security.deinit();

    const handle = CreateNamedPipeW(
        pipe_name.ptr,
        pipe_access_duplex | if (first_instance) file_flag_first_pipe_instance else 0,
        pipe_type_byte | pipe_readmode_byte | pipe_wait | pipe_reject_remote_clients,
        pipe_unlimited_instances,
        64 * 1024,
        64 * 1024,
        0,
        &security.attrs,
    );
    if (handle == windows.INVALID_HANDLE_VALUE) {
        return switch (windows.GetLastError()) {
            .ACCESS_DENIED => error.AccessDenied,
            else => error.Unexpected,
        };
    }
    errdefer windows.CloseHandle(handle);

    if (ConnectNamedPipe(handle, null).toBool()) {
        return .{ .handle = handle };
    }
    return switch (windows.GetLastError()) {
        .PIPE_CONNECTED => .{ .handle = handle },
        .PIPE_LISTENING, .PIPE_NOT_CONNECTED, .NO_DATA => error.WouldBlock,
        .ACCESS_DENIED => error.AccessDenied,
        else => error.Unexpected,
    };
}

fn connectNamedPipeClient(socket_path: []const u8) !Stream {
    const pipe_name = try namedPipeNameAlloc(socket_path);
    defer std.heap.page_allocator.free(pipe_name);

    while (true) {
        const handle = CreateFileW(
            pipe_name.ptr,
            generic_read | generic_write,
            0,
            null,
            open_existing,
            file_attribute_normal,
            null,
        );
        if (handle != windows.INVALID_HANDLE_VALUE) return .{ .handle = handle };

        switch (windows.GetLastError()) {
            .PIPE_BUSY => {
                if (!WaitNamedPipeW(pipe_name.ptr, named_pipe_wait_ms).toBool()) {
                    return switch (windows.GetLastError()) {
                        .FILE_NOT_FOUND, .PATH_NOT_FOUND => error.FileNotFound,
                        .ACCESS_DENIED => error.AccessDenied,
                        else => error.ConnectionRefused,
                    };
                }
            },
            .FILE_NOT_FOUND, .PATH_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            else => return error.ConnectionRefused,
        }
    }
}

pub fn setNonblocking(handle: std.Io.net.Socket.Handle, enabled: bool) !void {
    if (is_windows) {
        return error.NotSupported;
    }

    const flags_rc = posix.system.fcntl(handle, posix.F.GETFL, @as(usize, 0));
    const flags: u32 = switch (posix.errno(flags_rc)) {
        .SUCCESS => @intCast(flags_rc),
        else => return error.Unexpected,
    };
    var oflags = @as(posix.O, @bitCast(flags));
    oflags.NONBLOCK = enabled;
    const set_rc = posix.system.fcntl(handle, posix.F.SETFL, @as(u32, @bitCast(oflags)));
    switch (posix.errno(set_rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
}

const std = @import("std");
const fs = @import("fs.zig");

const posix = std.posix;

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

pub const Stream = struct {
    handle: std.Io.net.Socket.Handle,

    fn raw(self: Stream) std.Io.net.Stream {
        return .{ .socket = .{
            .handle = self.handle,
            .address = .{ .ip4 = .loopback(0) },
        } };
    }

    pub fn close(self: Stream) void {
        self.raw().close(fs.io());
    }

    pub fn reader(self: Stream, buffer: []u8) std.Io.net.Stream.Reader {
        return self.raw().reader(fs.io(), buffer);
    }

    pub fn writer(self: Stream, buffer: []u8) std.Io.net.Stream.Writer {
        return self.raw().writer(fs.io(), buffer);
    }

    pub fn write(self: Stream, bytes: []const u8) !usize {
        return fs.writeFd(self.handle, bytes);
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
    stream: Stream,

    pub const Connection = struct {
        stream: Stream,
        address: Address,
    };

    pub fn deinit(self: *Server) void {
        self.stream.close();
        self.* = undefined;
    }

    pub fn accept(self: *Server) !Connection {
        const handle = while (true) {
            const rc = std.c.accept(self.stream.handle, null, null);
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

pub fn connectUnixSocket(socket_path: []const u8) !Stream {
    if (!has_unix_sockets) return error.AddressFamilyUnsupported;
    const address = try std.Io.net.UnixAddress.init(socket_path);
    const stream = address.connect(fs.io()) catch |err| switch (err) {
        error.WouldBlock => return error.ConnectionRefused,
        else => |e| return e,
    };
    return .{ .handle = stream.socket.handle };
}

pub fn setNonblocking(handle: std.Io.net.Socket.Handle, enabled: bool) !void {
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

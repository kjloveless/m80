const std = @import("std");
const net = @import("../../util/net.zig");
const fs = @import("../../util/fs.zig");
const builtin = @import("builtin");
const core = @import("../../core.zig");
const errors = core.errors;
const state = core.state;
const runtime = @import("../runtime.zig");

const c = if (builtin.os.tag == .windows)
    struct {}
else
    @cImport({
        @cInclude("termios.h");
    });

const RawTty = struct {
    fd: std.posix.fd_t,
    prev: std.posix.termios,
};

fn enableRawStdin() ?RawTty {
    if (builtin.os.tag == .windows) return null;
    const fd = fs.File.stdin().handle;
    if (!fs.isTty(fd)) return null;
    const prev = std.posix.tcgetattr(fd) catch return null;
    var raw = prev;
    raw.iflag.IGNBRK = false;
    raw.iflag.BRKINT = false;
    raw.iflag.PARMRK = false;
    raw.iflag.ISTRIP = false;
    raw.iflag.INLCR = false;
    raw.iflag.IGNCR = false;
    raw.iflag.ICRNL = false;
    raw.iflag.IXON = false;
    if (@hasField(@TypeOf(raw.iflag), "IXOFF")) raw.iflag.IXOFF = false;
    if (@hasField(@TypeOf(raw.iflag), "IXANY")) raw.iflag.IXANY = false;

    raw.oflag.OPOST = false;
    if (@hasField(@TypeOf(raw.oflag), "ONLCR")) raw.oflag.ONLCR = false;

    raw.lflag.ECHO = false;
    raw.lflag.ECHONL = false;
    raw.lflag.ICANON = false;
    raw.lflag.ISIG = false;
    raw.lflag.IEXTEN = false;

    raw.cflag.CREAD = true;
    raw.cflag.CSIZE = .CS8;
    raw.cc[@intCast(c.VMIN)] = 1;
    raw.cc[@intCast(c.VTIME)] = 0;
    std.posix.tcsetattr(fd, .FLUSH, raw) catch return null;
    return .{ .fd = fd, .prev = prev };
}

fn restoreRawStdin(raw: RawTty) void {
    std.posix.tcsetattr(raw.fd, .FLUSH, raw.prev) catch {};
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try fs.writeFd(fd, bytes[offset..]);
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

pub fn runConsole(allocator: std.mem.Allocator, name: []const u8) !void {
    if (builtin.os.tag == .windows) {
        return error.NotSupported;
    }

    var cwd = fs.cwd();
    const dir_path = try core.paths.vmDir(allocator, name);
    defer allocator.free(dir_path);
    var vm_dir = cwd.openDir(dir_path, .{}) catch errors.die("vm not found: {s}", .{name});
    defer vm_dir.close();

    if (runtime.readVmPid(vm_dir)) |pid| {
        if (!runtime.isPidAlive(pid)) {
            runtime.clearVmPid(vm_dir);
            state.setStatus(allocator, name, .stopped) catch {};
            errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
        }
    } else {
        errors.die("vm not running: {s}\nrun `m80 start {s}` first", .{ name, name });
    }

    const socket_path = try runtime.vmConsoleSocketPath(allocator, name);
    defer allocator.free(socket_path);

    const raw = enableRawStdin();
    defer if (raw) |tty_state| restoreRawStdin(tty_state);

    var stream = net.connectUnixSocket(socket_path) catch |e| {
        errors.die("console connect failed: {s}\ncheck that the VM is running and console.sock exists", .{@errorName(e)});
    };
    defer stream.close();

    const socket_fd = stream.handle;
    const stdin_fd = fs.File.stdin().handle;
    const stdout_fd = fs.File.stdout().handle;
    var buf: [1024]u8 = undefined;
    var detached = false;
    while (true) {
        var fds = [_]std.posix.pollfd{
            .{ .fd = stdin_fd, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = socket_fd, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const ready = std.posix.poll(fds[0..], -1) catch break;
        if (ready <= 0) continue;
        if ((fds[0].revents & std.posix.POLL.IN) != 0) {
            const n = fs.readFd(stdin_fd, &buf) catch break;
            if (n <= 0) break;
            const chunk = buf[0..@intCast(n)];
            if (std.mem.indexOfScalar(u8, chunk, 0x04)) |eof_index| {
                if (eof_index > 0) {
                    writeAllFd(socket_fd, chunk[0..eof_index]) catch break;
                }
                detached = true;
                break;
            }
            writeAllFd(socket_fd, chunk) catch break;
        }
        if ((fds[1].revents & std.posix.POLL.IN) != 0) {
            const n = fs.readFd(socket_fd, &buf) catch break;
            if (n <= 0) break;
            writeAllFd(stdout_fd, buf[0..@intCast(n)]) catch break;
        }
    }
    if (detached) {
        std.debug.print("(detached from console)\n", .{});
    }
}

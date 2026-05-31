//! Serial Console Emulation
//!
//! This module emulates a 16550 UART serial port for guest console I/O.
//! The serial port allows the guest to output text (e.g., boot messages,
//! kernel logs) and optionally receive input.
//!
//! ## 16550 UART Basics
//! The 16550 is the standard PC serial port controller. Key I/O ports:
//! - 0x3F8 (COM1 base): Data register - read/write bytes
//! - 0x3FD (COM1 + 5): Line Status Register (LSR)
//!   - Bit 0: Data Ready (DR) - 1 if data available to read
//!   - Bit 5: Transmitter Holding Register Empty (THRE) - always 1 (can write)
//!
//! ## Usage
//! Guest writes to 0x3F8 → m80 prints to stdout
//! Guest reads LSR (0x3FD) → m80 returns status (data ready, TX empty)
//! Guest reads 0x3F8 → m80 returns next byte from input buffer
//!
//! ## Input Buffer
//! Set M80_SERIAL_IN environment variable to provide input bytes to the guest.
//! This is useful for testing automated interactions.

const std = @import("std");
const sync = @import("../util/sync.zig");
const fs = @import("../util/fs.zig");
const builtin = @import("builtin");
const env = @import("../util/env.zig");

const console_backlog_limit: usize = 64 * 1024;
var console_fd: ?std.posix.fd_t = null;
var console_mutex: sync.Mutex = .{};
var console_backlog: std.ArrayListUnmanaged(u8) = .empty;

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try fs.writeFd(fd, bytes[offset..]);
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

pub fn setConsoleFd(fd: std.posix.fd_t) void {
    console_mutex.lock();
    defer console_mutex.unlock();
    console_fd = fd;
}

pub fn clearConsoleFd() void {
    console_mutex.lock();
    defer console_mutex.unlock();
    console_fd = null;
}

pub fn clearConsoleBacklog() void {
    console_mutex.lock();
    defer console_mutex.unlock();
    console_backlog.deinit(std.heap.page_allocator);
    console_backlog = .empty;
}

fn appendConsoleBacklog(bytes: []const u8) void {
    if (bytes.len == 0) return;
    console_mutex.lock();
    defer console_mutex.unlock();
    console_backlog.appendSlice(std.heap.page_allocator, bytes) catch return;
    if (console_backlog.items.len > console_backlog_limit) {
        const start = console_backlog.items.len - console_backlog_limit;
        const remaining = console_backlog.items[start..];
        std.mem.copyForwards(u8, console_backlog.items[0..remaining.len], remaining);
        console_backlog.items.len = remaining.len;
    }
}

pub fn writeConsoleBacklog(fd: std.posix.fd_t) !void {
    console_mutex.lock();
    defer console_mutex.unlock();
    if (console_backlog.items.len == 0) return;
    var out: [1024]u8 = undefined;
    var out_len: usize = 0;
    var i: usize = 0;
    while (i < console_backlog.items.len) : (i += 1) {
        const b = console_backlog.items[i];
        if (b == '\r' and (i + 1 >= console_backlog.items.len or console_backlog.items[i + 1] != '\n')) {
            if (out_len + 2 > out.len) {
                try writeAllFd(fd, out[0..out_len]);
                out_len = 0;
            }
            out[out_len] = '\r';
            out[out_len + 1] = '\n';
            out_len += 2;
            continue;
        }
        if (out_len + 1 > out.len) {
            try writeAllFd(fd, out[0..out_len]);
            out_len = 0;
        }
        out[out_len] = b;
        out_len += 1;
    }
    if (out_len > 0) {
        try writeAllFd(fd, out[0..out_len]);
    }
}

fn writeToConsole(size: usize, rax: u64) bool {
    console_mutex.lock();
    defer console_mutex.unlock();
    const fd = console_fd orelse return false;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, rax, .little);
    const chunk = bytes[0..size];
    writeAllFd(fd, chunk) catch |e| switch (e) {
        error.BrokenPipe, error.ConnectionResetByPeer => {
            console_fd = null;
            return false;
        },
        else => return false,
    };
    return true;
}

pub fn writeConsoleBytes(bytes: []const u8) void {
    if (bytes.len == 0) return;
    console_mutex.lock();
    defer console_mutex.unlock();
    console_backlog.appendSlice(std.heap.page_allocator, bytes) catch return;
    if (console_backlog.items.len > console_backlog_limit) {
        const start = console_backlog.items.len - console_backlog_limit;
        const remaining = console_backlog.items[start..];
        std.mem.copyForwards(u8, console_backlog.items[0..remaining.len], remaining);
        console_backlog.items.len = remaining.len;
    }
    const fd = console_fd orelse return;
    writeAllFd(fd, bytes) catch |e| switch (e) {
        error.BrokenPipe, error.ConnectionResetByPeer => {
            console_fd = null;
        },
        else => {},
    };
}

/// Serial port emulation state.
/// Handles reads/writes to COM1 ports (0x3F8-0x3FF).
pub const SerialIo = struct {
    /// Input buffer (bytes to feed to guest on reads from 0x3F8)
    buf: std.ArrayListUnmanaged(u8) = .empty,
    /// Current position in input buffer
    offset: usize = 0,
    mutex: sync.Mutex = .{},

    /// Loads input data from M80_SERIAL_IN environment variable.
    /// This allows providing scripted input to the guest for testing.
    pub fn setFromEnv(self: *SerialIo, allocator: std.mem.Allocator) void {
        const value = env.getVarOwned(allocator, "M80_SERIAL_IN") catch null;
        if (value) |v| {
            self.clear(allocator);
            self.append(allocator, v);
            allocator.free(v);
        }
    }

    /// Frees the input buffer and resets state.
    pub fn clear(self: *SerialIo, allocator: std.mem.Allocator) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = allocator;
        self.buf.deinit(std.heap.page_allocator);
        self.buf = .empty;
        self.offset = 0;
    }

    /// Returns true if there's data available to read from the input buffer.
    pub fn hasData(self: *SerialIo) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.offset < self.buf.items.len;
    }

    /// Reads and consumes one byte from the input buffer.
    /// Returns null if no data available.
    pub fn readByte(self: *SerialIo) ?u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.offset >= self.buf.items.len) return null;
        const b = self.buf.items[self.offset];
        self.offset += 1;
        if (self.offset >= self.buf.items.len) {
            self.buf.clearRetainingCapacity();
            self.offset = 0;
        } else if (self.offset > 4096 and self.offset * 2 > self.buf.items.len) {
            const remaining = self.buf.items[self.offset..];
            std.mem.copyForwards(u8, self.buf.items[0..remaining.len], remaining);
            self.buf.items.len = remaining.len;
            self.offset = 0;
        }
        return b;
    }

    /// Appends input bytes to the buffer (for interactive serial input).
    pub fn append(self: *SerialIo, allocator: std.mem.Allocator, bytes: []const u8) void {
        if (bytes.len == 0) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = allocator;
        self.buf.appendSlice(std.heap.page_allocator, bytes) catch {};
    }

    /// Writes the low bytes of RAX to a writer.
    /// Used to extract the data from an OUT instruction.
    /// Example: OUT 0x3F8, AL writes 1 byte from RAX.
    pub fn writeFromRax(writer: anytype, size: usize, rax: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, rax, .little);
        try writer.writeAll(bytes[0..size]);
    }

    /// Writes serial output to the host's stdout.
    /// Called when guest writes to port 0x3F8 (COM1 data register).
    pub fn writeToStdout(size: usize, rax: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, rax, .little);
        appendConsoleBacklog(bytes[0..size]);

        const wrote_console = writeToConsole(size, rax);
        var buf: [256]u8 = undefined;
        if (!wrote_console) {
            var fw = fs.File.stdout().writer(&buf);
            const w = &fw.interface;
            writeFromRax(w, size, rax) catch return;
            w.flush() catch {};
        }
        writeToCaptureFile(size, rax);
    }

    fn writeToCaptureFile(size: usize, rax: u64) void {
        const file = capture_file orelse return;
        var buf: [256]u8 = undefined;
        var writer = file.writer(&buf);
        const w = &writer.interface;
        writeFromRax(w, size, rax) catch return;
        w.flush() catch return;

        if (capture_mem) |*mem_buf| {
            const remaining = if (mem_buf.items.len >= capture_limit) 0 else capture_limit - mem_buf.items.len;
            if (remaining > 0) {
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, rax, .little);
                const to_copy = @min(remaining, size);
                mem_buf.appendSlice(std.heap.page_allocator, bytes[0..to_copy]) catch {};
            }
        }
    }

    /// Handles a guest IN instruction (read from I/O port).
    ///
    /// Supported ports:
    /// - 0x3F8 (Data): Returns next byte from input buffer, or 0
    /// - 0x3FD (LSR): Returns status bits:
    ///   - Bit 0: Data Ready (DR) - set if input buffer has data
    ///   - Bit 5: Transmitter Holding Register Empty - always set
    ///
    /// The return value is masked to the requested access size.
    pub fn readPort(self: *SerialIo, port: u16, size: usize) u64 {
        var val: u64 = 0;
        if (port == 0x3F8) {
            if (self.readByte()) |b| val = b;
        } else if (port == 0x3FD) {
            val = 0x20;
            if (self.hasData()) val |= 0x01;
        }
        // Mask to requested width to mirror hardware behavior.
        if (size < 8) {
            const mask: u64 = (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            val &= mask;
        }
        return val;
    }
};

var capture_path: ?[]u8 = null;
var capture_file: ?fs.File = null;
var capture_mem: ?std.ArrayList(u8) = null;
const capture_limit: usize = 1024 * 1024;

fn closeCaptureSink(allocator: std.mem.Allocator) void {
    if (capture_path) |path| {
        allocator.free(path);
        capture_path = null;
    }
    if (capture_file) |file| {
        file.close();
        capture_file = null;
    }
}

pub fn setCapturePath(allocator: std.mem.Allocator, path: []const u8) !void {
    closeCaptureSink(allocator);
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    const file = try fs.cwd().openFile(path, .{ .mode = .read_write });
    errdefer file.close();
    file.seekFromEnd(0) catch {};
    capture_path = owned_path;
    capture_file = file;
    if (capture_mem == null) {
        capture_mem = std.ArrayList(u8).empty;
    }
}

pub fn clearCapture(allocator: std.mem.Allocator) void {
    closeCaptureSink(allocator);
    if (capture_mem) |*buf| {
        buf.deinit(allocator);
        capture_mem = null;
    }
}

pub fn captureContains(needle: []const u8) bool {
    if (capture_mem) |buf| {
        return std.mem.indexOf(u8, buf.items, needle) != null;
    }
    return false;
}

pub fn captureLen() usize {
    if (capture_mem) |buf| return buf.items.len;
    return 0;
}

/// Represents an I/O port access that caused a VM exit.
/// This is the common format used by all hypervisor backends.
pub const IoExit = struct {
    /// I/O port number (e.g., 0x3F8 for COM1)
    port: u16,
    /// True if this is a write (OUT instruction), false for read (IN)
    is_write: bool,
    /// Access size in bytes (1, 2, or 4)
    size: usize,
    /// RAX value (contains data for writes, receives data for reads)
    rax: u64,
    /// True if this is a string I/O operation (INS/OUTS)
    is_string: bool = false,
    /// True if REP prefix was used (repeat string operation)
    has_rep: bool = false,
};

// =============================================================================
// TESTS
// =============================================================================

test "serial: writeFromRax writes low bytes" {
    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try SerialIo.writeFromRax(&writer, 4, 0x64636261);
    try std.testing.expectEqualStrings("abcd", buf[0..4]);
}

test "serial: buffer feeds read" {
    var serial = SerialIo{};
    serial.append(std.testing.allocator, "hi");
    defer serial.clear(std.testing.allocator);

    try std.testing.expect(serial.hasData());
    try std.testing.expectEqual(@as(u8, 'h'), serial.readByte().?);
    try std.testing.expectEqual(@as(u8, 'i'), serial.readByte().?);
    try std.testing.expect(!serial.hasData());
    try std.testing.expectEqual(@as(?u8, null), serial.readByte());
}

test "serial: readPort reflects data ready" {
    var serial = SerialIo{};
    serial.append(std.testing.allocator, "A");
    defer serial.clear(std.testing.allocator);

    const lsr_with_data = serial.readPort(0x3FD, 1);
    try std.testing.expect((lsr_with_data & 0x21) == 0x21);

    const byte = serial.readPort(0x3F8, 1);
    try std.testing.expectEqual(@as(u8, 'A'), @as(u8, @intCast(byte)));

    const lsr_empty = serial.readPort(0x3FD, 1);
    try std.testing.expect((lsr_empty & 0x01) == 0);
}

test "serial: writeToStdout prefers console fd" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const fds = try fs.pipe();
    defer {
        fs.closeFd(fds[0]);
        fs.closeFd(fds[1]);
        clearConsoleFd();
    }

    setConsoleFd(fds[1]);
    SerialIo.writeToStdout(3, 0x00636261); // "abc"

    var buf: [8]u8 = undefined;
    const n = try fs.readFd(fds[0], &buf);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("abc", buf[0..3]);
}

test "serial: readPort masks to width" {
    var serial = SerialIo{};
    serial.append(std.testing.allocator, "\xFF");
    defer serial.clear(std.testing.allocator);

    const byte = serial.readPort(0x3F8, 1);
    try std.testing.expectEqual(@as(u64, 0xFF), byte);

    // With size 1, high bits should be masked off.
    const status = serial.readPort(0x3FD, 1);
    try std.testing.expect((status & 0xFF) == status);
}

//! Linux/BSD KVM Backend
//!
//! This module implements the VM backend for Linux and BSD systems using the
//! Kernel-based Virtual Machine (KVM) interface. KVM provides hardware-accelerated
//! virtualization via /dev/kvm.
//!
//! ## Current Status: Stub Implementation
//! This is currently a development stub that demonstrates the architecture
//! but doesn't actually create running VMs. The full implementation will:
//! - Open /dev/kvm and create a VM file descriptor
//! - Map guest physical memory into the VM
//! - Create vCPUs and configure their initial state
//! - Run the KVM_RUN ioctl loop handling VM exits
//!
//! ## KVM Concepts
//! - **VM FD**: Created via KVM_CREATE_VM ioctl on /dev/kvm
//! - **vCPU FD**: Created via KVM_CREATE_VCPU ioctl on VM FD
//! - **Memory Regions**: Mapped via KVM_SET_USER_MEMORY_REGION
//! - **VM Exit**: When guest executes I/O, HLT, or other trapped instructions
//!
//! ## Guest Memory Layout
//! Same as HVF backend - standard Linux boot addresses:
//! - 0x020000: Kernel command line
//! - 0x100000: Kernel (bzImage)
//! - 0x4000000: Initrd
//!
//! ## Platform Support
//! Compiles on all platforms but KVM ioctls only work on Linux.
//! Non-Linux builds get stub implementations that return errors.

const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");
const config = @import("../core/config.zig");
const serial = @import("serial.zig");
const boot = @import("boot.zig");
const virtio = @import("virtio.zig");
const virtio_fs = @import("../fs/virtio_fs.zig");

// Linux-only KVM bindings; compiled out on non-Linux hosts.
// Uses @cImport to access linux/kvm.h ioctl definitions.
const linux_kvm = if (builtin.os.tag == .linux)
    @cImport({
        @cInclude("linux/kvm.h");
    })
else
    struct {}; // Empty struct on non-Linux - KVM APIs will error
const SerialIo = serial.SerialIo;
const IoExit = serial.IoExit;

// Memory constants
const mb_to_bytes: u64 = 1024 * 1024;

// Guest physical memory layout (standard Linux boot protocol)
const guest_kernel_base: u64 = 0x100000; // 1 MB - bzImage load address
const guest_initrd_base: u64 = 0x4000000; // 64 MB - initrd after kernel
const guest_cmdline_base: u64 = 0x20000; // 128 KB - command line

// Default kernel command line
const default_cmdline: []const u8 = "console=ttyS0";

// =============================================================================
// GLOBAL STATE
// =============================================================================
// Single active VM at a time (m80 limitation)

var active_memory_size: usize = 0;
var active_guest_memory: ?[]align(std.heap.page_size_min) u8 = null;
var active_memory_is_mmap = false;
var active_vcpu_thread: ?std.Thread = null;
var vcpu_running = std.atomic.Value(bool).init(false);
var simulate_io = std.atomic.Value(bool).init(false);
var serial_io = SerialIo{};
var active_kvm: ?KvmState = null;

// =============================================================================
// KVM DATA STRUCTURES
// =============================================================================
// These structures mirror the Linux KVM API for ioctl calls.

/// Direction of I/O port access
const KvmIoExitDirection = enum(u8) {
    In = 0, // Guest reading from port (IN instruction)
    Out = 1, // Guest writing to port (OUT instruction)
};

/// Why the vCPU exited back to userspace
const KvmExitReason = enum(u32) {
    Unknown = 0,
    Io = 2, // I/O port access needs emulation
};

/// x86-64 general-purpose registers (matches kvm_regs structure)
const KvmRegs = extern struct {
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rsp: u64 = 0,
    rbp: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rip: u64 = 0,
    rflags: u64 = 0,
};

// Mirrors Linux kvm_segment fields for straightforward ioctl mapping.
const KvmSegment = extern struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    type: u8 = 0,
    present: u8 = 0,
    dpl: u8 = 0,
    db: u8 = 0,
    s: u8 = 0,
    l: u8 = 0,
    g: u8 = 0,
    avl: u8 = 0,
    unusable: u8 = 0,
    padding: u8 = 0,
};

const KvmDtable = extern struct {
    base: u64 = 0,
    limit: u16 = 0,
    padding: [3]u16 = .{ 0, 0, 0 },
};

// Mirrors Linux kvm_sregs layout so we can pass it to KVM_SET_SREGS.
const KvmSregs = extern struct {
    cs: KvmSegment = .{},
    ds: KvmSegment = .{},
    es: KvmSegment = .{},
    fs: KvmSegment = .{},
    gs: KvmSegment = .{},
    ss: KvmSegment = .{},
    tr: KvmSegment = .{},
    ldt: KvmSegment = .{},
    gdt: KvmDtable = .{},
    idt: KvmDtable = .{},
    cr0: u64 = 0,
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
    cr8: u64 = 0,
    efer: u64 = 0,
    apic_base: u64 = 0,
    interrupt_bitmap: [4]u64 = .{ 0, 0, 0, 0 },
};

const KvmRegSet = extern struct {
    regs: KvmRegs,
    sregs: KvmSregs,
};

const KvmIoExit = extern struct {
    direction: KvmIoExitDirection,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
};

const KvmRun = extern struct {
    exit_reason: KvmExitReason,
    _padding: u32 = 0,
    io: KvmIoExit,
    data: [64]u8 = [_]u8{0} ** 64,
};

const KvmHandle = usize;
const KvmState = if (builtin.os.tag == .linux) struct {
    kvm_fd: std.posix.fd_t,
    vm_fd: std.posix.fd_t,
    vcpu_fd: std.posix.fd_t,
    run: *linux_kvm.kvm_run,
    run_size: usize,
} else struct {};

fn kvmSetRegs(handle: KvmHandle, regs: KvmRegs) !void {
    if (builtin.os.tag != .linux) return error.NotSupported;

    // Linux KVM uses vCPU file descriptors; we treat the handle as the fd.
    // KVM_SET_REGS takes a kvm_regs struct populated with all general-purpose
    // registers (including r8-r15), RIP, and RFLAGS. We map field-by-field to
    // avoid any layout mismatch assumptions.
    const fd: std.os.linux.fd_t = @intCast(handle);
    var native = std.mem.zeroes(linux_kvm.kvm_regs);

    native.rax = regs.rax;
    native.rbx = regs.rbx;
    native.rcx = regs.rcx;
    native.rdx = regs.rdx;
    native.rsi = regs.rsi;
    native.rdi = regs.rdi;
    native.rsp = regs.rsp;
    native.rbp = regs.rbp;
    native.r8 = regs.r8;
    native.r9 = regs.r9;
    native.r10 = regs.r10;
    native.r11 = regs.r11;
    native.r12 = regs.r12;
    native.r13 = regs.r13;
    native.r14 = regs.r14;
    native.r15 = regs.r15;
    native.rip = regs.rip;
    native.rflags = regs.rflags;

    const rc = std.os.linux.ioctl(fd, linux_kvm.KVM_SET_REGS, @intFromPtr(&native));
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SystemError;
}

fn kvmSetSregs(handle: KvmHandle, sregs: KvmSregs) !void {
    if (builtin.os.tag != .linux) return error.NotSupported;

    // Linux KVM expects kvm_sregs; populate it explicitly for clarity.
    // This includes segment descriptors, descriptor tables, and control regs.
    const fd: std.os.linux.fd_t = @intCast(handle);
    var native = std.mem.zeroes(linux_kvm.kvm_sregs);

    native.cs = sregs.cs;
    native.ds = sregs.ds;
    native.es = sregs.es;
    native.fs = sregs.fs;
    native.gs = sregs.gs;
    native.ss = sregs.ss;
    native.tr = sregs.tr;
    native.ldt = sregs.ldt;
    native.gdt = sregs.gdt;
    native.idt = sregs.idt;
    native.cr0 = sregs.cr0;
    native.cr2 = sregs.cr2;
    native.cr3 = sregs.cr3;
    native.cr4 = sregs.cr4;
    native.cr8 = sregs.cr8;
    native.efer = sregs.efer;
    native.apic_base = sregs.apic_base;
    native.interrupt_bitmap = sregs.interrupt_bitmap;

    const rc = std.os.linux.ioctl(fd, linux_kvm.KVM_SET_SREGS, @intFromPtr(&native));
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SystemError;
}

fn readLeU64(data: []const u8, size: usize) u64 {
    var out: u64 = 0;
    var i: usize = 0;
    while (i < size and i < data.len) : (i += 1) {
        out |= @as(u64, data[i]) << @as(u6, @intCast(i * 8));
    }
    return out;
}

fn envFlagPresent(allocator: std.mem.Allocator, name: []const u8) bool {
    const env = std.process.getEnvVarOwned(allocator, name) catch return false;
    allocator.free(env);
    return true;
}

fn kvmIoExitToIoExit(exit: KvmIoExit, data: []const u8) IoExit {
    const is_write = exit.direction == .Out;
    const size: usize = @intCast(exit.size);
    return .{
        .port = exit.port,
        .is_write = is_write,
        .size = size,
        .rax = if (is_write) readLeU64(data, size) else 0,
        .is_string = exit.count > 1,
        .has_rep = exit.count > 1,
    };
}

fn decodeKvmIoExit(run: *const KvmRun) !IoExit {
    if (run.exit_reason != .Io) return error.NotIoExit;
    const offset: usize = @intCast(run.io.data_offset);
    const base: [*]const u8 = @ptrCast(run);
    const size: usize = @intCast(run.io.size);
    const data = base[offset..][0..size];
    return kvmIoExitToIoExit(run.io, data);
}

fn buildKvmRegs(regs: boot.BootRegs) KvmRegs {
    return .{
        .rip = regs.rip,
        .rsp = regs.rsp,
        .rflags = regs.rflags,
        .rsi = regs.rsi,
    };
}

fn buildKvmSegCode64(selector: u16) KvmSegment {
    return .{
        .base = 0,
        .limit = 0xFFFFF,
        .selector = selector,
        .type = 0xB, // execute/read, accessed
        .present = 1,
        .dpl = 0,
        .db = 0,
        .s = 1,
        .l = 1,
        .g = 1,
        .avl = 0,
        .unusable = 0,
    };
}

fn buildKvmSegData(selector: u16) KvmSegment {
    return .{
        .base = 0,
        .limit = 0xFFFFF,
        .selector = selector,
        .type = 0x3, // read/write, accessed
        .present = 1,
        .dpl = 0,
        .db = 0,
        .s = 1,
        .l = 0,
        .g = 1,
        .avl = 0,
        .unusable = 0,
    };
}

fn buildKvmSregs() KvmSregs {
    // Placeholder flat segments; real KVM setup should use proper x86 boot state.
    return .{
        .cs = buildKvmSegCode64(0x8),
        .ds = buildKvmSegData(0x10),
        .es = buildKvmSegData(0x10),
        .fs = buildKvmSegData(0x10),
        .gs = buildKvmSegData(0x10),
        .ss = buildKvmSegData(0x10),
        .cr0 = 0x80000011,
        .cr3 = 0,
        .cr4 = 0,
    };
}

fn buildKvmRegSet(regs: boot.BootRegs) KvmRegSet {
    return .{
        .regs = buildKvmRegs(regs),
        .sregs = buildKvmSregs(),
    };
}

fn handleIoPortWrite(port: u16, size: usize, rax: u64) void {
    if (port == 0x3F8) {
        SerialIo.writeToStdout(size, rax);
        return;
    }
    log.debug("posix io port write port=0x{x} size={d}", .{ port, size });
}

fn handleIoPortRead(port: u16, size: usize) u64 {
    return serial_io.readPort(port, size);
}

fn handleIoExit(exit: IoExit) u64 {
    if (exit.is_write) {
        handleIoPortWrite(exit.port, exit.size, exit.rax);
        return 0;
    }
    return handleIoPortRead(exit.port, exit.size);
}

fn runVcpuStub(index: u32) void {
    log.info("posix vcpu {d} stub run loop entered", .{index});
    while (vcpu_running.load(.seq_cst)) {
        if (simulate_io.swap(false, .seq_cst)) {
            // Emulate a single write/read IO cycle on the serial port.
            _ = handleIoExit(.{ .port = 0x3F8, .is_write = true, .size = 1, .rax = '>', .is_string = false, .has_rep = false });
            _ = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
        }
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    log.info("posix vcpu {d} stub run loop exited", .{index});
}

fn prepareGuestImage(memory_size_bytes: u64) !void {
    if (guest_cmdline_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_kernel_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_initrd_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_cmdline_base >= guest_kernel_base) return error.InvalidGuestLayout;
    if (guest_kernel_base >= guest_initrd_base) return error.InvalidGuestLayout;

    log.info(
        "posix guest layout kernel=0x{x} initrd=0x{x} cmdline=0x{x}",
        .{ guest_kernel_base, guest_initrd_base, guest_cmdline_base },
    );
}

fn readGuestImageFile(path: []const u8, label: []const u8) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    log.info("posix {s} size {d} bytes", .{ label, stat.size });
}

fn loadGuestKernel(memory_size_bytes: u64, kernel_path: ?[]const u8) !void {
    _ = memory_size_bytes;
    if (kernel_path == null) {
        log.warn("posix kernel path not set; skipping kernel load", .{});
        return;
    }
    try readGuestImageFile(kernel_path.?, "kernel");
}

fn loadGuestInitrd(memory_size_bytes: u64, initrd_path: ?[]const u8) !void {
    _ = memory_size_bytes;
    if (initrd_path == null) {
        log.warn("posix initrd path not set; skipping initrd load", .{});
        return;
    }
    try readGuestImageFile(initrd_path.?, "initrd");
}

fn setActiveGuestMemory(buffer: []align(std.heap.page_size_min) u8) void {
    active_guest_memory = buffer;
}

fn clearActiveGuestMemory() void {
    active_guest_memory = null;
}

fn allocateGuestMemory(size_bytes: usize) ![]align(std.heap.page_size_min) u8 {
    if (builtin.os.tag == .linux) {
        const prot: u32 = @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE);
        const flags = std.posix.MAP{
            .TYPE = .PRIVATE,
            .ANONYMOUS = true,
        };
        const mapped = try std.posix.mmap(null, size_bytes, prot, flags, -1, 0);
        return mapped;
    }
    const buf = try std.heap.page_allocator.alloc(u8, size_bytes);
    @memset(buf, 0);
    return @alignCast(buf);
}

fn freeGuestMemory(buffer: []align(std.heap.page_size_min) u8) void {
    if (builtin.os.tag == .linux and active_memory_is_mmap) {
        std.posix.munmap(buffer);
        return;
    }
    std.heap.page_allocator.free(buffer);
}

fn writeGuestBytes(guest_addr: u64, data: []const u8) !void {
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const end_addr = guest_addr + data.len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    const start_offset: usize = @intCast(guest_addr);
    const end_offset: usize = @intCast(end_addr);
    std.mem.copyForwards(u8, memory[start_offset..end_offset], data);
}

fn readGuestBytes(guest_addr: u64, out: []u8) !void {
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const end_addr = guest_addr + out.len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    const start_offset: usize = @intCast(guest_addr);
    const end_offset: usize = @intCast(end_addr);
    std.mem.copyForwards(u8, out, memory[start_offset..end_offset]);
}

fn mapDaxRegion(_: ?*anyopaque, guest_addr: u64, len: u64, fd: std.posix.fd_t, file_offset: u64, writable: bool) !void {
    if (builtin.os.tag != .linux) return error.NotSupported;
    if (len == 0) return;
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const end_addr = guest_addr + len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    if (len > std.math.maxInt(usize)) return error.InvalidGuestLayout;

    const host_addr = @intFromPtr(memory.ptr) + @as(usize, @intCast(guest_addr));
    const host_ptr: ?[*]align(std.heap.page_size_min) u8 = @ptrFromInt(host_addr);
    const prot: u32 = @intCast(if (writable) (std.posix.PROT.READ | std.posix.PROT.WRITE) else std.posix.PROT.READ);
    const flags = std.posix.MAP{
        .TYPE = .SHARED,
        .FIXED = true,
    };
    _ = try std.posix.mmap(host_ptr, @intCast(len), prot, flags, fd, @intCast(file_offset));
}

fn unmapDaxRegion(_: ?*anyopaque, guest_addr: u64, len: u64) !void {
    if (builtin.os.tag != .linux) return error.NotSupported;
    if (len == 0) return;
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const end_addr = guest_addr + len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    if (len > std.math.maxInt(usize)) return error.InvalidGuestLayout;

    const host_addr = @intFromPtr(memory.ptr) + @as(usize, @intCast(guest_addr));
    const host_ptr: ?[*]align(std.heap.page_size_min) u8 = @ptrFromInt(host_addr);
    const prot: u32 = @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE);
    const flags = std.posix.MAP{
        .TYPE = .PRIVATE,
        .FIXED = true,
        .ANONYMOUS = true,
    };
    _ = try std.posix.mmap(host_ptr, @intCast(len), prot, flags, -1, 0);
}

fn buildDaxMapper(memory_size_bytes: u64) virtio_fs.DaxMapper {
    return .{
        .ctx = null,
        .window_base = 0,
        .window_size = memory_size_bytes,
        .page_size = std.heap.page_size_min,
        .map = mapDaxRegion,
        .unmap = unmapDaxRegion,
    };
}

fn loadFileToGuest(path: []const u8, guest_addr: u64, label: []const u8) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        try writeGuestBytes(guest_addr + offset, buf[0..n]);
        offset += @as(u64, n);
    }
    log.info("posix loaded {s} ({d} bytes) at 0x{x}", .{ label, offset, guest_addr });
}

fn handleMmioExit(state: *KvmState) void {
    if (builtin.os.tag != .linux) return;
    const exit = state.run;
    const addr = exit.mmio.phys_addr;
    const len: usize = @intCast(exit.mmio.len);
    const is_write = exit.mmio.is_write != 0;
    var value: u64 = 0;
    if (is_write) {
        var i: usize = 0;
        while (i < len and i < exit.mmio.data.len) : (i += 1) {
            value |= @as(u64, exit.mmio.data[i]) << @as(u6, @intCast(i * 8));
        }
    }

    if (virtio.virtioBlkIndexForAddr(addr)) |blk_index| {
        _ = virtio.handleVirtioBlkMmio(blk_index, addr - virtio.virtioBlkMmioBase(blk_index), is_write, len, value);
        return;
    }
    if (addr >= virtio.virtio_console_mmio_base and addr < virtio.virtio_console_mmio_base + virtio.virtio_console_mmio_size) {
        const result = virtio.handleVirtioConsoleMmio(addr - virtio.virtio_console_mmio_base, is_write, len, value);
        if (!is_write) {
            std.mem.writeInt(u64, exit.mmio.data[0..8], result, .little);
        }
        return;
    }
    if (addr >= virtio.virtio_rng_mmio_base and addr < virtio.virtio_rng_mmio_base + virtio.virtio_rng_mmio_size) {
        const result = virtio.handleVirtioRngMmio(addr - virtio.virtio_rng_mmio_base, is_write, len, value);
        if (!is_write) {
            std.mem.writeInt(u64, exit.mmio.data[0..8], result, .little);
        }
        return;
    }
    if (addr >= virtio.virtio_fs_mmio_base and addr < virtio.virtio_fs_mmio_base + virtio.virtio_fs_mmio_size) {
        const result = virtio.handleVirtioFsMmio(addr - virtio.virtio_fs_mmio_base, is_write, len, value);
        if (!is_write) {
            std.mem.writeInt(u64, exit.mmio.data[0..8], result, .little);
        }
        return;
    }
    if (addr >= virtio.virtio_net_mmio_base and addr < virtio.virtio_net_mmio_base + virtio.virtio_net_mmio_size) {
        const result = virtio.handleVirtioNetMmio(addr - virtio.virtio_net_mmio_base, is_write, len, value);
        if (!is_write) {
            std.mem.writeInt(u64, exit.mmio.data[0..8], result, .little);
        }
        return;
    }
}

fn runVcpuKvm(state: *KvmState) void {
    if (builtin.os.tag != .linux) return;
    log.info("posix vcpu 0 kvm run loop entered", .{});
    while (vcpu_running.load(.seq_cst)) {
        const rc = std.os.linux.ioctl(state.vcpu_fd, linux_kvm.KVM_RUN, 0);
        if (std.os.linux.E.init(rc) != .SUCCESS) {
            log.err("posix KVM_RUN failed", .{});
            break;
        }

        switch (state.run.exit_reason) {
            linux_kvm.KVM_EXIT_IO => {
                const offset: usize = @intCast(state.run.io.data_offset);
                const base: [*]u8 = @ptrCast(state.run);
                const size: usize = @intCast(state.run.io.size);
                const data = base[offset..][0..size];
                const exit = kvmIoExitToIoExit(state.run.io, data);
                if (exit.is_write) {
                    _ = handleIoExit(exit);
                } else {
                    const value = handleIoExit(exit);
                    var i: usize = 0;
                    while (i < size) : (i += 1) {
                        data[i] = @intCast((value >> @intCast(i * 8)) & 0xFF);
                    }
                }
            },
            linux_kvm.KVM_EXIT_MMIO => handleMmioExit(state),
            linux_kvm.KVM_EXIT_HLT, linux_kvm.KVM_EXIT_SHUTDOWN => {
                log.info("posix KVM exit {d}, halting vcpu", .{state.run.exit_reason});
                vcpu_running.store(false, .seq_cst);
            },
            linux_kvm.KVM_EXIT_FAIL_ENTRY, linux_kvm.KVM_EXIT_INTERNAL_ERROR => {
                log.err("posix KVM exit error {d}", .{state.run.exit_reason});
                vcpu_running.store(false, .seq_cst);
            },
            else => {
                log.warn("posix KVM exit reason={d}", .{state.run.exit_reason});
            },
        }
    }
    log.info("posix vcpu 0 kvm run loop exited", .{});
}

/// Starts a VM with the KVM backend.
///
/// This function:
/// 1. Validates no VM is already running
/// 2. Prepares guest memory layout
/// 3. Loads kernel and initrd (validates files exist)
/// 4. Computes initial boot state (register values)
/// 5. Spawns the vCPU thread
///
/// Parameters:
///   - cfg: VM configuration
///
/// Errors:
///   - error.AlreadyRunning: A VM is already active
///   - error.InvalidGuestLayout: Memory too small
///   - error.MemoryTooLarge: Memory exceeds platform limits
///   - error.FileNotFound: Kernel or initrd file missing
pub fn start(cfg: config.VmConfig) !void {
    if (vcpu_running.load(.seq_cst) or active_vcpu_thread != null) return error.AlreadyRunning;
    log.info("posix backend stub start (no-op)", .{});
    const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
    if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;
    const size_bytes: usize = @intCast(size_bytes_u64);
    try prepareGuestImage(size_bytes_u64);
    try loadGuestKernel(size_bytes_u64, cfg.kernel_path);
    try loadGuestInitrd(size_bytes_u64, cfg.initrd_path);
    const cmdline = if (cfg.kernel_cmdline) |value| value else default_cmdline;
    const boot_state = try boot.computeBootState(
        size_bytes_u64,
        guest_kernel_base,
        guest_cmdline_base,
        cmdline,
    );
    const boot_regs = boot.buildBootRegs(boot_state);
    const kvm_regset = buildKvmRegSet(boot_regs);
    log.info(
        "posix boot state entry=0x{x} stack=0x{x} cmdline=0x{x} len={d} rflags=0x{x}",
        .{
            boot_state.entry,
            boot_state.stack_top,
            boot_state.cmdline_addr,
            boot_state.cmdline_len,
            boot_regs.rflags,
        },
    );
    log.debug("posix boot regs rip=0x{x} rsp=0x{x} rflags=0x{x} rsi=0x{x}", .{
        kvm_regset.regs.rip,
        kvm_regset.regs.rsp,
        kvm_regset.regs.rflags,
        kvm_regset.regs.rsi,
    });
    const guest_memory = try allocateGuestMemory(size_bytes);
    active_memory_is_mmap = builtin.os.tag == .linux;
    setActiveGuestMemory(guest_memory);
    active_memory_size = size_bytes;

    virtio.initGuestIo(.{
        .read_bytes = readGuestBytes,
        .write_bytes = writeGuestBytes,
    });
    if (builtin.os.tag == .linux) {
        const dax_mapper = buildDaxMapper(size_bytes_u64);
        virtio.setupVirtioFs(std.heap.page_allocator, cfg, dax_mapper) catch |e| {
            log.err("posix virtio-fs setup failed: {s}", .{@errorName(e)});
            return e;
        };
    } else {
        virtio.setupVirtioFs(std.heap.page_allocator, cfg, null) catch |e| {
            log.err("posix virtio-fs setup failed: {s}", .{@errorName(e)});
            return e;
        };
    }

    if (builtin.os.tag == .linux) {
        const kvm_fd = try std.posix.open("/dev/kvm", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
        errdefer std.posix.close(kvm_fd);

        const api_version = std.os.linux.ioctl(kvm_fd, linux_kvm.KVM_GET_API_VERSION, 0);
        if (api_version != linux_kvm.KVM_API_VERSION) return error.NotSupported;

        const vm_fd = std.os.linux.ioctl(kvm_fd, linux_kvm.KVM_CREATE_VM, 0);
        if (vm_fd < 0) return error.SystemError;
        errdefer std.posix.close(@intCast(vm_fd));

        if (@hasDecl(linux_kvm, "KVM_SET_TSS_ADDR")) {
            _ = std.os.linux.ioctl(@intCast(vm_fd), linux_kvm.KVM_SET_TSS_ADDR, 0xfffbd000);
        }

        var region = linux_kvm.kvm_userspace_memory_region{
            .slot = 0,
            .flags = 0,
            .guest_phys_addr = 0,
            .memory_size = size_bytes,
            .userspace_addr = @intFromPtr(guest_memory.ptr),
        };
        const rc_mem = std.os.linux.ioctl(@intCast(vm_fd), linux_kvm.KVM_SET_USER_MEMORY_REGION, @intFromPtr(&region));
        if (std.os.linux.E.init(rc_mem) != .SUCCESS) return error.SystemError;

        const vcpu_fd = std.os.linux.ioctl(@intCast(vm_fd), linux_kvm.KVM_CREATE_VCPU, 0);
        if (vcpu_fd < 0) return error.SystemError;
        errdefer std.posix.close(@intCast(vcpu_fd));

        const run_size = std.os.linux.ioctl(kvm_fd, linux_kvm.KVM_GET_VCPU_MMAP_SIZE, 0);
        if (run_size <= 0) return error.SystemError;
        const run = try std.posix.mmap(
            null,
            @intCast(run_size),
            @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE),
            std.posix.MAP{ .TYPE = .SHARED },
            @intCast(vcpu_fd),
            0,
        );

        const cmdline_with_null = try std.fmt.allocPrint(std.heap.page_allocator, "{s}\x00", .{cmdline});
        defer std.heap.page_allocator.free(cmdline_with_null);
        try writeGuestBytes(guest_cmdline_base, cmdline_with_null);

        if (cfg.kernel_path) |kernel_path| {
            try loadFileToGuest(kernel_path, guest_kernel_base, "kernel");
        }
        if (cfg.initrd_path) |initrd_path| {
            try loadFileToGuest(initrd_path, guest_initrd_base, "initrd");
        }

        const sregs = buildKvmSregs();
        try kvmSetSregs(@intCast(vcpu_fd), sregs);
        try kvmSetRegs(@intCast(vcpu_fd), kvm_regset.regs);

        active_kvm = .{
            .kvm_fd = kvm_fd,
            .vm_fd = @intCast(vm_fd),
            .vcpu_fd = @intCast(vcpu_fd),
            .run = @ptrCast(@alignCast(run.ptr)),
            .run_size = @intCast(run_size),
        };

        vcpu_running.store(true, .seq_cst);
        serial_io.setFromEnv(std.heap.page_allocator);
        active_vcpu_thread = try std.Thread.spawn(.{}, runVcpuKvm, .{&active_kvm.?});
        log.info("vm running (kvm)", .{});
        return;
    }

    vcpu_running.store(true, .seq_cst);
    if (envFlagPresent(std.heap.page_allocator, "M80_IO_SIM")) {
        simulate_io.store(true, .seq_cst);
    }
    serial_io.setFromEnv(std.heap.page_allocator);
    active_vcpu_thread = try std.Thread.spawn(.{}, runVcpuStub, .{0});

    std.Thread.sleep(std.time.ns_per_s);
    log.info("vm running (stub)", .{});
}

/// Stops the running VM and cleans up resources.
///
/// Signals the vCPU thread to stop, waits for it to exit,
/// and resets all state.
pub fn stop() !void {
    log.info("posix backend stub stop (no-op)", .{});
    vcpu_running.store(false, .seq_cst);
    if (active_vcpu_thread) |t| {
        t.join();
        active_vcpu_thread = null;
    }
    serial_io.clear(std.heap.page_allocator);
    if (builtin.os.tag == .linux) {
        if (active_kvm) |state| {
            std.posix.munmap(state.run[0..state.run_size]);
            std.posix.close(state.vcpu_fd);
            std.posix.close(state.vm_fd);
            std.posix.close(state.kvm_fd);
            active_kvm = null;
        }
    }
    if (active_guest_memory) |memory| {
        freeGuestMemory(memory);
    }
    clearActiveGuestMemory();
    active_memory_is_mmap = false;
    active_memory_size = 0;
}

// =============================================================================
// TESTS
// =============================================================================

test "smoke: posix backend start/stop" {
    const tag = @import("builtin").os.tag;
    if (tag == .windows or tag == .macos) return error.SkipZigTest;
    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    try start(cfg_mut);
    try stop();
}

test "posix: handleIoExit reads serial data" {
    serial_io.clear(std.testing.allocator);
    serial_io.append(std.testing.allocator, "Z");
    defer serial_io.clear(std.testing.allocator);

    const b = handleIoExit(.{ .port = 0x3F8, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    try std.testing.expectEqual(@as(u8, 'Z'), @as(u8, @intCast(b)));

    const lsr = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    try std.testing.expect((lsr & 0x01) == 0);
}

test "posix: kvm io exit mapping" {
    var run = std.mem.zeroes(KvmRun);
    run.exit_reason = .Io;
    run.io = .{
        .direction = .Out,
        .size = 1,
        .port = 0x3F8,
        .count = 2,
        .data_offset = @offsetOf(KvmRun, "data"),
    };
    run.data[0] = 'B';
    const mapped = try decodeKvmIoExit(&run);
    try std.testing.expect(mapped.is_write);
    try std.testing.expectEqual(@as(u64, 'B'), mapped.rax);
    try std.testing.expect(mapped.is_string);
    try std.testing.expect(mapped.has_rep);
}

test "posix: kvm io exit rejects non-io reason" {
    var run = std.mem.zeroes(KvmRun);
    run.exit_reason = .Unknown;
    try std.testing.expectError(error.NotIoExit, decodeKvmIoExit(&run));
}

test "posix: buildKvmRegs mirrors boot regs" {
    const state = try boot.computeBootState(32 * 1024 * 1024, 0x100000, 0x20000, "root=/dev/vda");
    const regs = boot.buildBootRegs(state);
    const kvm_regs = buildKvmRegs(regs);
    try std.testing.expectEqual(regs.rip, kvm_regs.rip);
    try std.testing.expectEqual(regs.rsp, kvm_regs.rsp);
    try std.testing.expectEqual(regs.rflags, kvm_regs.rflags);
    try std.testing.expectEqual(regs.rsi, kvm_regs.rsi);
}

test "posix: kvmSetRegs not supported on non-linux" {
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    const state = try boot.computeBootState(32 * 1024 * 1024, 0x100000, 0x20000, "root=/dev/vda");
    const regs = boot.buildBootRegs(state);
    const kvm_regset = buildKvmRegSet(regs);
    try std.testing.expectError(error.NotSupported, kvmSetRegs(0, kvm_regset.regs));
    try std.testing.expectError(error.NotSupported, kvmSetSregs(0, kvm_regset.sregs));
}

test "posix: readLeU64 respects size and data length" {
    try std.testing.expectEqual(@as(u64, 0), readLeU64("", 0));
    try std.testing.expectEqual(@as(u64, 0x01), readLeU64("\x01\x02", 1));
    try std.testing.expectEqual(@as(u64, 0x0201), readLeU64("\x01\x02", 2));
    try std.testing.expectEqual(@as(u64, 0x0201), readLeU64("\x01\x02", 4));
    try std.testing.expectEqual(@as(u64, 0x04030201), readLeU64("\x01\x02\x03\x04", 4));
}

test "posix: prepareGuestImage rejects too small memory" {
    try std.testing.expectError(error.InvalidGuestLayout, prepareGuestImage(0x1000));
}

test "posix: loadGuestKernel errors on missing file" {
    try std.testing.expectError(error.FileNotFound, loadGuestKernel(64 * 1024 * 1024, "missing-kernel"));
}

test "posix: loadGuestInitrd errors on missing file" {
    try std.testing.expectError(error.FileNotFound, loadGuestInitrd(64 * 1024 * 1024, "missing-initrd"));
}

test "posix: loadGuestKernel skips when unset" {
    try loadGuestKernel(64 * 1024 * 1024, null);
}

test "posix: loadGuestInitrd skips when unset" {
    try loadGuestInitrd(64 * 1024 * 1024, null);
}

test "posix: start rejects already running state" {
    vcpu_running.store(true, .seq_cst);
    defer vcpu_running.store(false, .seq_cst);

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    try std.testing.expectError(error.AlreadyRunning, start(cfg_mut));
}

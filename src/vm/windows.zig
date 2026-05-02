//! Windows Hypervisor Platform (WHP) Backend
//!
//! This module implements the VM backend for Windows using the Windows
//! Hypervisor Platform (WHP). WHP provides access to Hyper-V's virtualization
//! capabilities from user-mode applications.
//!
//! ## Requirements
//! - Windows 10 1803 or later
//! - Hyper-V enabled in Windows Features
//! - WinHvPlatform.dll must be present
//!
//! ## Architecture
//! WHP uses a partition-based model:
//! 1. Create a partition (WHvCreatePartition)
//! 2. Configure partition properties (processor count, etc.)
//! 3. Setup the partition (WHvSetupPartition)
//! 4. Map guest physical memory (WHvMapGpaRange)
//! 5. Create vCPUs (WHvCreateVirtualProcessor)
//! 6. Run vCPU loop (WHvRunVirtualProcessor)
//!
//! ## VM Exit Handling
//! The vCPU execution loop handles these exit types:
//! - X64Cpuid: Return default CPUID values and advance RIP
//! - X64IoPortAccess: Emulate I/O port read/write (e.g., serial console)
//! - X64Halt: Guest executed HLT instruction (stop VM)
//! - Others: Log and exit
//!
//! ## Guest Memory Layout
//! Same standard Linux boot layout as other backends:
//! - 0x020000: Kernel command line
//! - 0x100000: Kernel (bzImage)
//! - 0x4000000: Initrd

const std = @import("std");
const log = @import("../util/log.zig");
const env_util = @import("../util/env.zig");
const builtin = @import("builtin");

const windows = std.os.windows;
const HRESULT = i32;

const config = @import("../core/config.zig");
const serial = @import("serial.zig");
const boot = @import("boot.zig");
const guest_mem = @import("guest_mem.zig");
const SerialIo = serial.SerialIo;
const IoExit = serial.IoExit;

// Guest Physical Address base (start of guest memory at 0)
const gpa_base: u64 = 0;
const mb_to_bytes: u64 = 1024 * 1024;
const default_vcpu_index: u32 = 0;

// Guest memory layout (standard Linux boot protocol)
const guest_kernel_base: u64 = 0x100000; // 1 MB - bzImage load address
const guest_initrd_base: u64 = 0x4000000; // 64 MB
const guest_cmdline_base: u64 = 0x20000; // 128 KB
const default_cmdline: []const u8 = "console=ttyS0";

const WHV_PARTITION_PROPERTY = extern union {
    ProcessorCount: u32,
};

const WhvX64VpExecutionState = extern union {
    AsUINT16: u16,
};

const WhvX64SegmentRegister = extern struct {
    Base: u64,
    Limit: u32,
    Selector: u16,
    Attributes: u16,
};

const WhvVpExitInstructionInfo = packed struct(u8) {
    InstructionLength: u4,
    Cr8: u4,
};

const WhvVpExitContext = extern struct {
    ExecutionState: WhvX64VpExecutionState,
    InstructionInfo: WhvVpExitInstructionInfo,
    Reserved: u8,
    Reserved2: u32,
    Cs: WhvX64SegmentRegister,
    Rip: u64,
    Rflags: u64,
};

const WhvX64IoPortAccessInfo = extern union {
    AsUINT32: u32,
    Bits: packed struct(u32) {
        IsWrite: u1,
        AccessSize: u3,
        StringOp: u1,
        RepPrefix: u1,
        Reserved: u26,
    },
};

const WhvX64IoPortAccessContext = extern struct {
    InstructionByteCount: u8,
    InstructionBytes: [16]u8,
    AccessInfo: WhvX64IoPortAccessInfo,
    PortNumber: u16,
    Rax: u64,
    Rcx: u64,
    Rsi: u64,
    Rdi: u64,
    Ds: WhvX64SegmentRegister,
    Es: WhvX64SegmentRegister,
};

const WhvX64CpuidAccessContext = extern struct {
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    DefaultResultRax: u64,
    DefaultResultRcx: u64,
    DefaultResultRdx: u64,
    DefaultResultRbx: u64,
};

const WhvRunVpExitContext = extern struct {
    ExitReason: u32,
    Reserved: u32,
    VpContext: WhvVpExitContext,
    Union: extern union {
        IoPortAccess: WhvX64IoPortAccessContext,
        CpuidAccess: WhvX64CpuidAccessContext,
    },
};

const WhvRegisterValue = extern union {
    Reg128: [16]u8,
    Reg64: u64,
    Reg32: u32,
    Reg16: u16,
    Reg8: u8,
};

const WhvRegisterName = enum(u32) {
    Rax = 0x00000000,
    Rcx = 0x00000001,
    Rdx = 0x00000002,
    Rbx = 0x00000003,
    Rsp = 0x00000004,
    Rbp = 0x00000005,
    Rsi = 0x00000006,
    Rdi = 0x00000007,
    Rip = 0x00000010,
    Rflags = 0x00000011,
};

const WhvRunVpExitReason = enum(u32) {
    None = 0x00000000,
    MemoryAccess = 0x00000001,
    X64IoPortAccess = 0x00000002,
    UnrecoverableException = 0x00000004,
    InvalidVpRegisterValue = 0x00000005,
    UnsupportedFeature = 0x00000006,
    X64InterruptWindow = 0x00000007,
    X64Halt = 0x00000008,
    X64ApicEoi = 0x00000009,
    X64MsrAccess = 0x00001000,
    X64Cpuid = 0x00001001,
    Exception = 0x00001002,
    Canceled = 0x00002001,
};

/// Windows Hypervisor Platform API wrapper.
/// Provides a Zig-friendly interface to WHP functions loaded from WinHvPlatform.dll.
pub const Whp = struct {
    /// Errors from WHP operations
    pub const Error = error{
        /// Not running on Windows
        NotSupported,
        /// WinHvPlatform.dll not found
        LibraryLoadFailed,
        /// Required function not exported by DLL
        ProcNotFound,
        /// WHP API call returned a failure HRESULT
        WhpFailure,
    };

    /// Opaque handle to a WHP partition (VM)
    pub const PartitionHandle = ?*anyopaque;

    /// Configuration for partition setup
    pub const PartitionConfig = struct {
        cpu_cores: u16,
        memory_mb: u32,
    };

    const WHV_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT: u32 = 0x00000001;

    const PFN_WHvCreatePartition = *const fn (*PartitionHandle) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvSetupPartition = *const fn (PartitionHandle) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvDeletePartition = *const fn (PartitionHandle) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvMapGpaRange = *const fn (
        PartitionHandle,
        ?*anyopaque,
        u64,
        u64,
        u32,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvCreateVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        u32,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvDeleteVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvRunVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        ?*anyopaque,
        u32,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvCancelRunVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        u32,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvGetVirtualProcessorRegisters = *const fn (
        PartitionHandle,
        u32,
        *const WhvRegisterName,
        u32,
        *WhvRegisterValue,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvSetVirtualProcessorRegisters = *const fn (
        PartitionHandle,
        u32,
        *const WhvRegisterName,
        u32,
        *const WhvRegisterValue,
    ) callconv(windows.WINAPI) HRESULT;
    const PFN_WHvSetPartitionProperty = *const fn (
        PartitionHandle,
        u32,
        *const WHV_PARTITION_PROPERTY,
        u32,
    ) callconv(windows.WINAPI) HRESULT;

    const WhpFns = struct {
        create: PFN_WHvCreatePartition,
        setup: PFN_WHvSetupPartition,
        delete: PFN_WHvDeletePartition,
        set_property: PFN_WHvSetPartitionProperty,
        map_gpa: PFN_WHvMapGpaRange,
        create_vcpu: PFN_WHvCreateVirtualProcessor,
        delete_vcpu: PFN_WHvDeleteVirtualProcessor,
        run_vcpu: PFN_WHvRunVirtualProcessor,
        cancel_vcpu: PFN_WHvCancelRunVirtualProcessor,
        get_regs: PFN_WHvGetVirtualProcessorRegisters,
        set_regs: PFN_WHvSetVirtualProcessorRegisters,
    };

    var fns: ?WhpFns = null;

    extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(windows.WINAPI) windows.HMODULE;
    extern "kernel32" fn GetProcAddress(module: windows.HMODULE, name: [*:0]const u8) callconv(windows.WINAPI) ?*anyopaque;

    fn failed(hr: HRESULT) bool {
        return hr < 0;
    }

    fn loadFn(comptime T: type, module: windows.HMODULE, name: [:0]const u8) Error!T {
        const raw = GetProcAddress(module, name) orelse return error.ProcNotFound;
        return @ptrCast(@alignCast(raw));
    }

    fn getFns() Error!WhpFns {
        if (builtin.os.tag != .windows) return error.NotSupported;
        if (fns) |cached| return cached;

        const lib_name: [:0]const u8 = "WinHvPlatform.dll";
        const module = LoadLibraryA(lib_name) orelse return error.LibraryLoadFailed;

        const loaded = WhpFns{
            .create = try loadFn(PFN_WHvCreatePartition, module, "WHvCreatePartition"),
            .setup = try loadFn(PFN_WHvSetupPartition, module, "WHvSetupPartition"),
            .delete = try loadFn(PFN_WHvDeletePartition, module, "WHvDeletePartition"),
            .set_property = try loadFn(PFN_WHvSetPartitionProperty, module, "WHvSetPartitionProperty"),
            .map_gpa = try loadFn(PFN_WHvMapGpaRange, module, "WHvMapGpaRange"),
            .create_vcpu = try loadFn(PFN_WHvCreateVirtualProcessor, module, "WHvCreateVirtualProcessor"),
            .delete_vcpu = try loadFn(PFN_WHvDeleteVirtualProcessor, module, "WHvDeleteVirtualProcessor"),
            .run_vcpu = try loadFn(PFN_WHvRunVirtualProcessor, module, "WHvRunVirtualProcessor"),
            .cancel_vcpu = try loadFn(PFN_WHvCancelRunVirtualProcessor, module, "WHvCancelRunVirtualProcessor"),
            .get_regs = try loadFn(PFN_WHvGetVirtualProcessorRegisters, module, "WHvGetVirtualProcessorRegisters"),
            .set_regs = try loadFn(PFN_WHvSetVirtualProcessorRegisters, module, "WHvSetVirtualProcessorRegisters"),
        };
        fns = loaded;
        return loaded;
    }

    pub fn createPartition() Error!PartitionHandle {
        const whp = try getFns();
        var handle: PartitionHandle = null;
        const hr = whp.create(&handle);
        if (failed(hr)) return error.WhpFailure;
        if (handle == null) return error.WhpFailure;
        return handle;
    }

    pub fn setupPartition(handle: PartitionHandle, cfg: PartitionConfig) Error!void {
        const whp = try getFns();
        var prop = WHV_PARTITION_PROPERTY{ .ProcessorCount = cfg.cpu_cores };
        const hr_prop = whp.set_property(
            handle,
            WHV_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT,
            &prop,
            @sizeOf(WHV_PARTITION_PROPERTY),
        );
        if (failed(hr_prop)) return error.WhpFailure;

        const hr = whp.setup(handle);
        if (failed(hr)) return error.WhpFailure;

        _ = cfg.memory_mb; // memory mapping will be configured in a later step
    }

    pub fn deletePartition(handle: PartitionHandle) Error!void {
        const whp = try getFns();
        const hr = whp.delete(handle);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn mapGpaRange(
        handle: PartitionHandle,
        source: ?*anyopaque,
        guest_address: u64,
        size_bytes: u64,
        flags: u32,
    ) Error!void {
        const whp = try getFns();
        const hr = whp.map_gpa(handle, source, guest_address, size_bytes, flags);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn createVirtualProcessor(handle: PartitionHandle, index: u32) Error!void {
        const whp = try getFns();
        const hr = whp.create_vcpu(handle, index, 0);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn deleteVirtualProcessor(handle: PartitionHandle, index: u32) Error!void {
        const whp = try getFns();
        const hr = whp.delete_vcpu(handle, index);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn runVirtualProcessor(
        handle: PartitionHandle,
        index: u32,
        exit_context: *anyopaque,
        exit_context_size: u32,
    ) Error!void {
        const whp = try getFns();
        const hr = whp.run_vcpu(handle, index, exit_context, exit_context_size);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn cancelRunVirtualProcessor(handle: PartitionHandle, index: u32) Error!void {
        const whp = try getFns();
        const hr = whp.cancel_vcpu(handle, index, 0);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn setVirtualProcessorRegisters(
        handle: PartitionHandle,
        index: u32,
        names: []const WhvRegisterName,
        values: []const WhvRegisterValue,
    ) Error!void {
        if (names.len != values.len) return error.WhpFailure;
        const whp = try getFns();
        const hr = whp.set_regs(
            handle,
            index,
            names.ptr,
            @intCast(names.len),
            @ptrCast(@constCast(values.ptr)),
        );
        if (failed(hr)) return error.WhpFailure;
    }
};

// Global runtime state (single active VM instance).
var active_partition: ?Whp.PartitionHandle = null;
var active_memory: ?windows.LPVOID = null;
var active_memory_size: usize = 0;
var active_vcpu: bool = false;
var active_vcpu_thread: ?std.Thread = null;
var vcpu_running = std.atomic.Value(bool).init(false);
var vcpu_alive = std.atomic.Value(bool).init(false);
var cpuid_exit_count = std.atomic.Value(u32).init(0);
var ioport_exit_count = std.atomic.Value(u32).init(0);
var serial_io = SerialIo{};

fn handleIoPortWrite(port: u16, size: usize, rax: u64) void {
    if (port == 0x3F8) {
        SerialIo.writeToStdout(size, rax);
        return;
    }
    log.debug("vcpu io port write port=0x{x} size={d}", .{ port, size });
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

fn advanceRip(handle: Whp.PartitionHandle, index: u32, ctx: *const WhvRunVpExitContext) bool {
    const len = ctx.VpContext.InstructionInfo.InstructionLength;
    const next_rip = ctx.VpContext.Rip + @as(u64, len);
    var names = [_]WhvRegisterName{.Rip};
    var values = [_]WhvRegisterValue{.{ .Reg64 = next_rip }};
    Whp.setVirtualProcessorRegisters(handle, index, &names, &values) catch |e| {
        log.err("vcpu {d} failed to advance rip: {s}", .{ index, @errorName(e) });
        return false;
    };
    return true;
}

fn handleCpuidExit(handle: Whp.PartitionHandle, index: u32, ctx: *const WhvRunVpExitContext) bool {
    const cpuid = ctx.Union.CpuidAccess;
    _ = cpuid_exit_count.fetchAdd(1, .seq_cst);
    var names = [_]WhvRegisterName{ .Rax, .Rbx, .Rcx, .Rdx, .Rip };
    var values = [_]WhvRegisterValue{
        .{ .Reg64 = cpuid.DefaultResultRax },
        .{ .Reg64 = cpuid.DefaultResultRbx },
        .{ .Reg64 = cpuid.DefaultResultRcx },
        .{ .Reg64 = cpuid.DefaultResultRdx },
        .{ .Reg64 = ctx.VpContext.Rip + @as(u64, ctx.VpContext.InstructionInfo.InstructionLength) },
    };
    Whp.setVirtualProcessorRegisters(handle, index, &names, &values) catch |e| {
        log.err("vcpu {d} cpuid set regs failed: {s}", .{ index, @errorName(e) });
        return false;
    };
    return true;
}

fn handleIoPortExit(handle: Whp.PartitionHandle, index: u32, ctx: *const WhvRunVpExitContext) bool {
    const io = ctx.Union.IoPortAccess;
    const access = io.AccessInfo.Bits;
    const size = ioAccessSizeBytes(access.AccessSize);

    _ = ioport_exit_count.fetchAdd(1, .seq_cst);
    const exit: IoExit = .{
        .port = io.PortNumber,
        .is_write = access.IsWrite == 1,
        .size = size,
        .rax = io.Rax,
        .is_string = access.StringOp == 1,
        .has_rep = access.RepPrefix == 1,
    };
    const read_val = handleIoExit(exit);

    if (!exit.is_write) {
        // Read path updates RAX with the device result.
        var names = [_]WhvRegisterName{.Rax};
        var values = [_]WhvRegisterValue{.{ .Reg64 = read_val }};
        Whp.setVirtualProcessorRegisters(handle, index, &names, &values) catch |e| {
            log.err("vcpu {d} io port set regs failed: {s}", .{ index, @errorName(e) });
            return false;
        };
    }
    return advanceRip(handle, index, ctx);
}

fn ioAccessSizeBytes(access_size: u3) usize {
    return switch (access_size) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => 1,
    };
}

fn handleExitReason(reason: u32, index: u32) bool {
    switch (reason) {
        @intFromEnum(WhvRunVpExitReason.None) => return true,
        @intFromEnum(WhvRunVpExitReason.Canceled) => {
            log.info("vcpu {d} canceled", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.X64Halt) => {
            log.info("vcpu {d} halted", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.UnrecoverableException) => {
            log.err("vcpu {d} unrecoverable exception", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.InvalidVpRegisterValue) => {
            log.err("vcpu {d} invalid register value", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.UnsupportedFeature) => {
            log.err("vcpu {d} unsupported feature", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.MemoryAccess) => {
            log.warn("vcpu {d} memory access exit", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.X64IoPortAccess) => return false,
        @intFromEnum(WhvRunVpExitReason.X64InterruptWindow) => {
            log.warn("vcpu {d} interrupt window exit", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.X64ApicEoi) => {
            log.warn("vcpu {d} apic eoi exit", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.X64MsrAccess) => {
            log.warn("vcpu {d} msr access exit", .{index});
            return false;
        },
        @intFromEnum(WhvRunVpExitReason.X64Cpuid) => return false,
        @intFromEnum(WhvRunVpExitReason.Exception) => {
            log.warn("vcpu {d} exception exit", .{index});
            return false;
        },
        else => {
            log.warn("vcpu {d} unknown exit reason=0x{x}", .{ index, reason });
            return false;
        },
    }
}

fn runVcpu(index: u32) void {
    log.info("vcpu {d} run loop entered", .{index});
    const handle = active_partition orelse {
        log.err("vcpu {d} has no active partition", .{index});
        return;
    };

    vcpu_alive.store(true, .seq_cst);
    var exit_buf: [4096]u8 align(8) = undefined;
    const exit_ctx: *const WhvRunVpExitContext = @ptrCast(@alignCast(&exit_buf));

    while (vcpu_running.load(.seq_cst)) {
        Whp.runVirtualProcessor(handle, index, &exit_buf, @intCast(exit_buf.len)) catch |e| {
            log.err("vcpu {d} run failed: {s}", .{ index, @errorName(e) });
            break;
        };
        // Fast-path the common exits we know how to handle.
        switch (exit_ctx.ExitReason) {
            @intFromEnum(WhvRunVpExitReason.X64Cpuid) => {
                if (!handleCpuidExit(handle, index, exit_ctx)) break;
                continue;
            },
            @intFromEnum(WhvRunVpExitReason.X64IoPortAccess) => {
                if (!handleIoPortExit(handle, index, exit_ctx)) break;
                continue;
            },
            else => {},
        }
        if (!handleExitReason(exit_ctx.ExitReason, index)) break;
    }
    vcpu_alive.store(false, .seq_cst);
    log.info("vcpu {d} run loop exited", .{index});
}

fn prepareGuestImage(memory_size_bytes: u64) !void {
    if (guest_cmdline_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_kernel_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_initrd_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_cmdline_base >= guest_kernel_base) return error.InvalidGuestLayout;
    if (guest_kernel_base >= guest_initrd_base) return error.InvalidGuestLayout;

    log.info(
        "guest layout kernel=0x{x} initrd=0x{x} cmdline=0x{x}",
        .{ guest_kernel_base, guest_initrd_base, guest_cmdline_base },
    );
}

fn copyFileToGuest(
    mem: ?windows.LPVOID,
    memory_size_bytes: u64,
    guest_base: u64,
    path: []const u8,
    label: []const u8,
) !u64 {
    const memory_len = std.math.cast(usize, memory_size_bytes) orelse return error.GuestImageTooLarge;

    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.size > std.math.maxInt(usize)) return error.GuestImageTooLarge;

    const range = guest_mem.checkedRange(memory_len, gpa_base, guest_base, @intCast(stat.size)) catch
        return error.GuestImageTooLarge;

    const mem_ptr = mem orelse return error.MemoryAllocFailed;
    const base_ptr: [*]u8 = @ptrCast(@alignCast(mem_ptr));
    const dst = base_ptr[range.offset..range.end];

    var buf: [4096]u8 = undefined;
    var reader = file.reader(&buf);
    const r = &reader.interface;
    var remaining: usize = @intCast(stat.size);
    var offset: usize = 0;
    while (remaining > 0) {
        const chunk = @min(remaining, 64 * 1024);
        const n = try r.readSliceShort(dst[offset .. offset + chunk]);
        if (n == 0) return error.UnexpectedEof;
        remaining -= n;
        offset += n;
    }

    log.info("loaded {s} ({d} bytes) at 0x{x}", .{ label, stat.size, guest_base });
    return stat.size;
}

fn loadGuestKernel(mem: windows.LPVOID, memory_size_bytes: u64, kernel_path: ?[]const u8) !void {
    if (kernel_path == null) {
        log.warn("kernel path not set; skipping kernel load", .{});
        return;
    }
    _ = try copyFileToGuest(mem, memory_size_bytes, guest_kernel_base, kernel_path.?, "kernel");
}

fn loadGuestInitrd(mem: windows.LPVOID, memory_size_bytes: u64, initrd_path: ?[]const u8) !void {
    if (initrd_path == null) {
        log.warn("initrd path not set; skipping initrd load", .{});
        return;
    }
    _ = try copyFileToGuest(mem, memory_size_bytes, guest_initrd_base, initrd_path.?, "initrd");
}

fn allocGuestMemory(size_bytes: usize) !windows.LPVOID {
    return windows.VirtualAlloc(
        null,
        size_bytes,
        windows.MEM_RESERVE | windows.MEM_COMMIT,
        windows.PAGE_READWRITE,
    ) catch return error.MemoryAllocFailed;
}

fn writeCmdlineToGuest(mem: ?*anyopaque, memory_size_bytes: u64, state: boot.BootState, cmdline: []const u8) !void {
    const memory_len = std.math.cast(usize, memory_size_bytes) orelse return error.GuestImageTooLarge;
    const expected_with_null = std.math.add(usize, state.cmdline_len, 1) catch return error.GuestImageTooLarge;
    const actual_with_null = std.math.add(usize, cmdline.len, 1) catch return error.GuestImageTooLarge;
    if (actual_with_null > expected_with_null) return error.GuestImageTooLarge;

    const range = guest_mem.checkedRange(memory_len, gpa_base, state.cmdline_addr, expected_with_null) catch
        return error.GuestImageTooLarge;

    const mem_ptr = mem orelse return error.MemoryAllocFailed;
    const base_ptr: [*]u8 = @ptrCast(@alignCast(mem_ptr));
    const dst = base_ptr[range.offset..range.end];

    @memset(dst, 0);
    @memcpy(dst[0..cmdline.len], cmdline);
}

fn setInitialRegisters(handle: Whp.PartitionHandle, index: u32, state: boot.BootState) !void {
    const regs = boot.buildBootRegs(state);
    var names = [_]WhvRegisterName{ .Rip, .Rsp, .Rflags, .Rsi };
    var values = [_]WhvRegisterValue{
        .{ .Reg64 = regs.rip },
        .{ .Reg64 = regs.rsp },
        .{ .Reg64 = regs.rflags },
        .{ .Reg64 = regs.rsi },
    };
    try Whp.setVirtualProcessorRegisters(handle, index, &names, &values);
}

/// Starts a VM using the Windows Hypervisor Platform.
///
/// This function:
/// 1. Creates a WHP partition
/// 2. Configures CPU count and memory size
/// 3. Allocates guest physical memory (VirtualAlloc)
/// 4. Maps the memory into the partition (WHvMapGpaRange)
/// 5. Loads kernel, initrd, and command line into guest memory
/// 6. Creates a vCPU and sets initial register state
/// 7. Spawns the vCPU execution thread
///
/// Parameters:
///   - cfg: VM configuration
///
/// Errors:
///   - error.AlreadyRunning: A partition is already active
///   - error.NotSupported: Not running on Windows
///   - error.LibraryLoadFailed: WinHvPlatform.dll not found
///   - error.WhpFailure: WHP API call failed
///   - error.MemoryTooLarge: Memory exceeds platform limits
pub fn start(cfg: config.VmConfig) !void {
    log.info("windows backend starting (whp)", .{});
    if (active_partition != null) return error.AlreadyRunning;

    const handle = try Whp.createPartition();
    errdefer Whp.deletePartition(handle) catch {};

    try Whp.setupPartition(handle, .{
        .cpu_cores = cfg.cpu_cores,
        .memory_mb = cfg.memory_mb,
    });

    const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
    if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;
    const size_bytes: usize = @intCast(size_bytes_u64);

    const mem = try allocGuestMemory(size_bytes);
    errdefer windows.VirtualFree(mem, 0, windows.MEM_RELEASE);

    const map_flags: u32 = 0x1 | 0x2 | 0x4; // READ | WRITE | EXECUTE
    try Whp.mapGpaRange(handle, mem, gpa_base, size_bytes_u64, map_flags);

    try prepareGuestImage(size_bytes_u64);
    try loadGuestKernel(mem, size_bytes_u64, cfg.kernel_path);
    try loadGuestInitrd(mem, size_bytes_u64, cfg.initrd_path);
    const cmdline = if (cfg.kernel_cmdline) |value| value else default_cmdline;
    const boot_state = try boot.computeBootState(
        size_bytes_u64,
        guest_kernel_base,
        guest_cmdline_base,
        cmdline,
    );
    try writeCmdlineToGuest(mem, size_bytes_u64, boot_state, cmdline);

    try Whp.createVirtualProcessor(handle, default_vcpu_index);
    try setInitialRegisters(handle, default_vcpu_index, boot_state);
    active_vcpu = true;
    serial_io.setFromEnv(std.heap.page_allocator);
    vcpu_running.store(true, .seq_cst);
    active_vcpu_thread = try std.Thread.spawn(.{}, runVcpu, .{default_vcpu_index});

    active_memory = mem;
    active_memory_size = size_bytes;
    active_partition = handle;
    log.info("windows backend ready (partition created)", .{});
}

/// Stops the running VM and cleans up all resources.
///
/// Performs cleanup in reverse order:
/// 1. Signals vCPU thread to stop
/// 2. Cancels vCPU execution (WHvCancelRunVirtualProcessor)
/// 3. Waits for vCPU thread to exit
/// 4. Deletes vCPU (WHvDeleteVirtualProcessor)
/// 5. Deletes partition (WHvDeletePartition)
/// 6. Frees guest memory (VirtualFree)
pub fn stop() !void {
    log.info("windows backend stopping (whp)", .{});
    if (active_partition) |handle| {
        vcpu_running.store(false, .seq_cst);
        if (active_vcpu) {
            Whp.cancelRunVirtualProcessor(handle, default_vcpu_index) catch |e| {
                log.warn("failed to cancel vcpu: {s}", .{@errorName(e)});
            };
        }
        if (active_vcpu_thread) |t| {
            t.join();
            active_vcpu_thread = null;
        }
        if (active_vcpu) {
            Whp.deleteVirtualProcessor(handle, default_vcpu_index) catch |e| {
                log.err("failed to delete vcpu: {s}", .{@errorName(e)});
                return e;
            };
            active_vcpu = false;
        }

        Whp.deletePartition(handle) catch |e| {
            log.err("failed to delete partition: {s}", .{@errorName(e)});
            return e;
        };
        active_partition = null;
    }

    if (active_memory) |mem| {
        windows.VirtualFree(mem, 0, windows.MEM_RELEASE);
        active_memory = null;
        active_memory_size = 0;
    }
    serial_io.clear(std.heap.page_allocator);
}

// =============================================================================
// TESTS
// =============================================================================

test "smoke: windows backend start/stop" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    start(cfg_mut) catch |e| switch (e) {
        error.NotSupported,
        error.LibraryLoadFailed,
        error.ProcNotFound,
        error.WhpFailure,
        => return error.SkipZigTest,
        else => return e,
    };
    defer stop() catch {};

    try stop();
}

test "windows: start rejects already running state" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    const fake_handle: Whp.PartitionHandle = @ptrFromInt(1);
    active_partition = fake_handle;
    defer active_partition = null;

    try std.testing.expectError(error.AlreadyRunning, start(cfg_mut));
}

test "integration: cpuid/io port exits keep vcpu running" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    if (!env_util.integrationEnabled(std.testing.allocator, "whp")) return error.SkipZigTest;

    const kernel = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
    defer if (initrd) |i| std.testing.allocator.free(i);

    if (kernel == null or initrd == null) return error.SkipZigTest;

    cpuid_exit_count.store(0, .seq_cst);
    ioport_exit_count.store(0, .seq_cst);

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.kernel_path = try std.testing.allocator.dupe(u8, kernel.?);
    cfg_mut.initrd_path = try std.testing.allocator.dupe(u8, initrd.?);

    start(cfg_mut) catch |e| switch (e) {
        error.NotSupported,
        error.LibraryLoadFailed,
        error.ProcNotFound,
        error.WhpFailure,
        => return error.SkipZigTest,
        else => return e,
    };
    defer stop() catch {};

    const deadline = std.time.milliTimestamp() + 5000;
    while (std.time.milliTimestamp() < deadline) {
        if (cpuid_exit_count.load(.seq_cst) > 0 or ioport_exit_count.load(.seq_cst) > 0) break;
        std.time.sleep(50 * std.time.ns_per_ms);
    }

    try std.testing.expect(vcpu_alive.load(.seq_cst));
    try std.testing.expect(cpuid_exit_count.load(.seq_cst) > 0 or ioport_exit_count.load(.seq_cst) > 0);
}

test "windows: io access size mapping" {
    try std.testing.expectEqual(@as(usize, 1), ioAccessSizeBytes(0));
    try std.testing.expectEqual(@as(usize, 2), ioAccessSizeBytes(1));
    try std.testing.expectEqual(@as(usize, 4), ioAccessSizeBytes(2));
    try std.testing.expectEqual(@as(usize, 8), ioAccessSizeBytes(3));
    try std.testing.expectEqual(@as(usize, 1), ioAccessSizeBytes(7));
}

test "windows: exit reason handling" {
    try std.testing.expect(handleExitReason(@intFromEnum(WhvRunVpExitReason.None), 0));
    try std.testing.expect(!handleExitReason(@intFromEnum(WhvRunVpExitReason.X64IoPortAccess), 0));
    try std.testing.expect(!handleExitReason(@intFromEnum(WhvRunVpExitReason.X64Halt), 0));
}

test "windows: copyFileToGuest rejects oversized image" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("big.bin", .{});
        defer f.close();
        try f.writeAll("ab");
    }

    const path = try tmp.dir.realpathAlloc(allocator, "big.bin");
    defer allocator.free(path);

    try std.testing.expectError(
        error.GuestImageTooLarge,
        copyFileToGuest(null, 1, 0, path, "kernel"),
    );
}

test "windows: copyFileToGuest rejects null memory" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var f = try tmp.dir.createFile("small.bin", .{});
        defer f.close();
        try f.writeAll("a");
    }

    const path = try tmp.dir.realpathAlloc(allocator, "small.bin");
    defer allocator.free(path);

    try std.testing.expectError(
        error.MemoryAllocFailed,
        copyFileToGuest(null, 4096, 0, path, "kernel"),
    );
}

test "windows: writeCmdlineToGuest writes null-terminated string" {
    const allocator = std.testing.allocator;
    const size: usize = 0x4000;
    const mem = try allocator.alloc(u8, size);
    defer allocator.free(mem);
    @memset(mem, 0xCC);

    const state = try boot.computeBootState(0x4000, 0x1000, 0x200, "abc");
    try writeCmdlineToGuest(@ptrCast(@alignCast(mem.ptr)), 0x4000, state, "abc");

    const cmdline_offset: usize = @intCast(state.cmdline_addr);
    try std.testing.expectEqual(@as(u8, 'a'), mem[cmdline_offset]);
    try std.testing.expectEqual(@as(u8, 'b'), mem[cmdline_offset + 1]);
    try std.testing.expectEqual(@as(u8, 'c'), mem[cmdline_offset + 2]);
    try std.testing.expectEqual(@as(u8, 0), mem[cmdline_offset + 3]);
}

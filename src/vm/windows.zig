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
const sync = @import("../util/sync.zig");
const log = @import("../util/log.zig");
const env_util = @import("../util/env.zig");
const builtin = @import("builtin");

const windows = std.os.windows;
const HRESULT = i32;
const MEM_COMMIT: windows.DWORD = 0x00001000;
const MEM_RESERVE: windows.DWORD = 0x00002000;
const MEM_RELEASE: windows.DWORD = 0x00008000;
const PAGE_READWRITE: windows.DWORD = 0x00000004;

const windows_api = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn VirtualAlloc(
        lpAddress: ?windows.LPVOID,
        dwSize: usize,
        flAllocationType: windows.DWORD,
        flProtect: windows.DWORD,
    ) callconv(.winapi) ?windows.LPVOID;

    extern "kernel32" fn VirtualFree(
        lpAddress: windows.LPVOID,
        dwSize: usize,
        dwFreeType: windows.DWORD,
    ) callconv(.winapi) windows.BOOL;
} else struct {};

const config = @import("../core/config.zig");
const mounts = @import("../fs/mounts.zig");
const serial = @import("serial.zig");
const boot = @import("boot.zig");
const guest_mem = @import("guest_mem.zig");
const hvf_boot = @import("hvf/boot.zig");
const virtio = @import("virtio.zig");
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
const cmdline_arch: std.Target.Cpu.Arch = .x86_64;
const x86_irq_vector_offset: u32 = 0x20;

const VirtioIrqLayout = struct {
    blk: [virtio.virtio_blk_device_count]u32 = .{ 5, 7, 9 },
    console: u32 = 6,
    rng: u32 = 8,
    fs: u32 = 10,
    vsock: u32 = 11,
};

const virtio_irq_layout = VirtioIrqLayout{};

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
    Reserved: [3]u8,
    InstructionBytes: [16]u8,
    AccessInfo: WhvX64IoPortAccessInfo,
    PortNumber: u16,
    Reserved2: [3]u16,
    Rax: u64,
    Rcx: u64,
    Rsi: u64,
    Rdi: u64,
    Ds: WhvX64SegmentRegister,
    Es: WhvX64SegmentRegister,
};

const WhvMemoryAccessInfo = extern union {
    AsUINT32: u32,
    Bits: packed struct(u32) {
        AccessType: u2,
        GpaUnmapped: u1,
        GvaValid: u1,
        Reserved: u28,
    },
};

const WhvMemoryAccessContext = extern struct {
    InstructionByteCount: u8,
    Reserved: [3]u8,
    InstructionBytes: [16]u8,
    AccessInfo: WhvMemoryAccessInfo,
    Gpa: u64,
    Gva: u64,
};

const WhvTranslateGvaResult = extern struct {
    ResultCode: u32,
    Reserved: u32,
};

const WhvInterruptType = enum(u8) {
    Fixed = 0,
    LowestPriority = 1,
    Nmi = 4,
    Init = 5,
    Sipi = 6,
    LocalInt1 = 9,
};

const WhvInterruptDestinationMode = enum(u8) {
    Physical = 0,
    Logical = 1,
};

const WhvInterruptTriggerMode = enum(u8) {
    Edge = 0,
    Level = 1,
};

const WhvInterruptControl = extern struct {
    AsUINT64: u64,
    Destination: u32,
    Vector: u32,
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
        MemoryAccess: WhvMemoryAccessContext,
        IoPortAccess: WhvX64IoPortAccessContext,
        CpuidAccess: WhvX64CpuidAccessContext,
        Raw: [176]u8,
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

comptime {
    if (builtin.cpu.arch == .x86_64) {
        if (@sizeOf(WhvVpExitContext) != 40) @compileError("unexpected WHV_VP_EXIT_CONTEXT size");
        if (@sizeOf(WhvX64IoPortAccessContext) != 96) @compileError("unexpected WHV_X64_IO_PORT_ACCESS_CONTEXT size");
        if (@sizeOf(WhvMemoryAccessContext) != 40) @compileError("unexpected WHV_MEMORY_ACCESS_CONTEXT size");
        if (@sizeOf(WhvInterruptControl) != 16) @compileError("unexpected WHV_INTERRUPT_CONTROL size");
        if (@sizeOf(WhvRunVpExitContext) != 224) @compileError("unexpected WHV_RUN_VP_EXIT_CONTEXT size");
    }
}

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

    const PFN_WHvCreatePartition = *const fn (*PartitionHandle) callconv(.winapi) HRESULT;
    const PFN_WHvSetupPartition = *const fn (PartitionHandle) callconv(.winapi) HRESULT;
    const PFN_WHvDeletePartition = *const fn (PartitionHandle) callconv(.winapi) HRESULT;
    const PFN_WHvMapGpaRange = *const fn (
        PartitionHandle,
        ?*anyopaque,
        u64,
        u64,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvUnmapGpaRange = *const fn (
        PartitionHandle,
        u64,
        u64,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvCreateVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvDeleteVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvRunVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        ?*anyopaque,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvCancelRunVirtualProcessor = *const fn (
        PartitionHandle,
        u32,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvGetVirtualProcessorRegisters = *const fn (
        PartitionHandle,
        u32,
        [*]const WhvRegisterName,
        u32,
        [*]WhvRegisterValue,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvSetVirtualProcessorRegisters = *const fn (
        PartitionHandle,
        u32,
        [*]const WhvRegisterName,
        u32,
        [*]const WhvRegisterValue,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvSetPartitionProperty = *const fn (
        PartitionHandle,
        u32,
        *const WHV_PARTITION_PROPERTY,
        u32,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvTranslateGva = *const fn (
        PartitionHandle,
        u32,
        u64,
        u32,
        *WhvTranslateGvaResult,
        *u64,
    ) callconv(.winapi) HRESULT;
    const PFN_WHvRequestInterrupt = *const fn (
        PartitionHandle,
        *const WhvInterruptControl,
        u32,
    ) callconv(.winapi) HRESULT;

    const WhpFns = struct {
        create: PFN_WHvCreatePartition,
        setup: PFN_WHvSetupPartition,
        delete: PFN_WHvDeletePartition,
        set_property: PFN_WHvSetPartitionProperty,
        map_gpa: PFN_WHvMapGpaRange,
        unmap_gpa: PFN_WHvUnmapGpaRange,
        create_vcpu: PFN_WHvCreateVirtualProcessor,
        delete_vcpu: PFN_WHvDeleteVirtualProcessor,
        run_vcpu: PFN_WHvRunVirtualProcessor,
        cancel_vcpu: PFN_WHvCancelRunVirtualProcessor,
        get_regs: PFN_WHvGetVirtualProcessorRegisters,
        set_regs: PFN_WHvSetVirtualProcessorRegisters,
        translate_gva: PFN_WHvTranslateGva,
        request_interrupt: PFN_WHvRequestInterrupt,
    };

    var fns: ?WhpFns = null;

    extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(.winapi) ?windows.HMODULE;
    extern "kernel32" fn GetProcAddress(module: windows.HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;

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
            .unmap_gpa = try loadFn(PFN_WHvUnmapGpaRange, module, "WHvUnmapGpaRange"),
            .create_vcpu = try loadFn(PFN_WHvCreateVirtualProcessor, module, "WHvCreateVirtualProcessor"),
            .delete_vcpu = try loadFn(PFN_WHvDeleteVirtualProcessor, module, "WHvDeleteVirtualProcessor"),
            .run_vcpu = try loadFn(PFN_WHvRunVirtualProcessor, module, "WHvRunVirtualProcessor"),
            .cancel_vcpu = try loadFn(PFN_WHvCancelRunVirtualProcessor, module, "WHvCancelRunVirtualProcessor"),
            .get_regs = try loadFn(PFN_WHvGetVirtualProcessorRegisters, module, "WHvGetVirtualProcessorRegisters"),
            .set_regs = try loadFn(PFN_WHvSetVirtualProcessorRegisters, module, "WHvSetVirtualProcessorRegisters"),
            .translate_gva = try loadFn(PFN_WHvTranslateGva, module, "WHvTranslateGva"),
            .request_interrupt = try loadFn(PFN_WHvRequestInterrupt, module, "WHvRequestInterrupt"),
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

    pub fn unmapGpaRange(
        handle: PartitionHandle,
        guest_address: u64,
        size_bytes: u64,
    ) Error!void {
        const whp = try getFns();
        const hr = whp.unmap_gpa(handle, guest_address, size_bytes);
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

    pub fn getVirtualProcessorRegisters(
        handle: PartitionHandle,
        index: u32,
        names: []const WhvRegisterName,
        values: []WhvRegisterValue,
    ) Error!void {
        if (names.len != values.len) return error.WhpFailure;
        const whp = try getFns();
        const hr = whp.get_regs(
            handle,
            index,
            names.ptr,
            @intCast(names.len),
            values.ptr,
        );
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn translateGva(
        handle: PartitionHandle,
        index: u32,
        gva: u64,
        flags: u32,
        result: *WhvTranslateGvaResult,
        gpa: *u64,
    ) Error!void {
        const whp = try getFns();
        const hr = whp.translate_gva(handle, index, gva, flags, result, gpa);
        if (failed(hr)) return error.WhpFailure;
    }

    pub fn requestInterrupt(
        handle: PartitionHandle,
        interrupt: *const WhvInterruptControl,
    ) Error!void {
        const whp = try getFns();
        const hr = whp.request_interrupt(handle, interrupt, @sizeOf(WhvInterruptControl));
        if (failed(hr)) return error.WhpFailure;
    }
};

pub const WhpEmulator = struct {
    pub const Error = error{
        NotSupported,
        LibraryLoadFailed,
        ProcNotFound,
        EmulationFailure,
    };

    pub const EmulatorHandle = ?*anyopaque;
    pub const TranslateGvaResultCode = enum(u32) {
        Success = 0,
        PageNotPresent = 1,
        PrivilegeViolation = 2,
        InvalidPageTableFlags = 3,
        GpaUnmapped = 4,
        GpaNoReadAccess = 5,
        GpaNoWriteAccess = 6,
        GpaIllegalOverlayAccess = 7,
        Intercept = 8,
    };

    pub const EmulatorStatus = extern union {
        AsUINT32: u32,
        Bits: packed struct(u32) {
            EmulationSuccessful: u1,
            InternalEmulationFailure: u1,
            IoPortCallbackFailed: u1,
            MemoryCallbackFailed: u1,
            TranslateGvaPageCallbackFailed: u1,
            TranslateGvaPageCallbackGpaIsNotAligned: u1,
            GetVirtualProcessorRegistersCallbackFailed: u1,
            SetVirtualProcessorRegistersCallbackFailed: u1,
            InterruptCausedIntercept: u1,
            GuestCannotBeFaulted: u1,
            Reserved: u22,
        },
    };

    pub const EmulatorMemoryAccessInfo = extern struct {
        GpaAddress: u64,
        Direction: u8,
        AccessSize: u8,
        Data: [8]u8,
    };

    pub const EmulatorIoAccessInfo = extern struct {
        Direction: u8,
        Port: u16,
        AccessSize: u16,
        Data: u32,
    };

    pub const EmulatorIoPortCallback = *const fn (?*anyopaque, *EmulatorIoAccessInfo) callconv(.winapi) HRESULT;
    pub const EmulatorMemoryCallback = *const fn (?*anyopaque, *EmulatorMemoryAccessInfo) callconv(.winapi) HRESULT;
    pub const EmulatorGetRegistersCallback = *const fn (?*anyopaque, [*]const WhvRegisterName, u32, [*]WhvRegisterValue) callconv(.winapi) HRESULT;
    pub const EmulatorSetRegistersCallback = *const fn (?*anyopaque, [*]const WhvRegisterName, u32, [*]const WhvRegisterValue) callconv(.winapi) HRESULT;
    pub const EmulatorTranslateGvaCallback = *const fn (?*anyopaque, u64, u32, *TranslateGvaResultCode, *u64) callconv(.winapi) HRESULT;

    pub const EmulatorCallbacks = extern struct {
        Size: u32,
        Reserved: u32,
        IoPortCallbackFn: EmulatorIoPortCallback,
        MemoryCallbackFn: EmulatorMemoryCallback,
        GetRegistersCallbackFn: EmulatorGetRegistersCallback,
        SetRegistersCallbackFn: EmulatorSetRegistersCallback,
        TranslateGvaCallbackFn: EmulatorTranslateGvaCallback,
    };

    const PFN_WHvEmulatorCreateEmulator = *const fn (*const EmulatorCallbacks, *EmulatorHandle) callconv(.winapi) HRESULT;
    const PFN_WHvEmulatorDestroyEmulator = *const fn (EmulatorHandle) callconv(.winapi) HRESULT;
    const PFN_WHvEmulatorTryMmioEmulation = *const fn (
        EmulatorHandle,
        ?*anyopaque,
        *const WhvVpExitContext,
        *const WhvMemoryAccessContext,
        *EmulatorStatus,
    ) callconv(.winapi) HRESULT;

    const Fns = struct {
        create: PFN_WHvEmulatorCreateEmulator,
        destroy: PFN_WHvEmulatorDestroyEmulator,
        try_mmio: PFN_WHvEmulatorTryMmioEmulation,
    };

    var fns: ?Fns = null;
    extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(.winapi) ?windows.HMODULE;
    extern "kernel32" fn GetProcAddress(module: windows.HMODULE, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;

    fn failed(hr: HRESULT) bool {
        return hr < 0;
    }

    fn loadFn(comptime T: type, module: windows.HMODULE, name: [:0]const u8) Error!T {
        const raw = GetProcAddress(module, name) orelse return error.ProcNotFound;
        return @ptrCast(@alignCast(raw));
    }

    fn getFns() Error!Fns {
        if (builtin.os.tag != .windows) return error.NotSupported;
        if (fns) |cached| return cached;

        const lib_name: [:0]const u8 = "WinHvEmulation.dll";
        const module = LoadLibraryA(lib_name) orelse return error.LibraryLoadFailed;
        const loaded = Fns{
            .create = try loadFn(PFN_WHvEmulatorCreateEmulator, module, "WHvEmulatorCreateEmulator"),
            .destroy = try loadFn(PFN_WHvEmulatorDestroyEmulator, module, "WHvEmulatorDestroyEmulator"),
            .try_mmio = try loadFn(PFN_WHvEmulatorTryMmioEmulation, module, "WHvEmulatorTryMmioEmulation"),
        };
        fns = loaded;
        return loaded;
    }

    pub fn create(callbacks: *const EmulatorCallbacks) Error!EmulatorHandle {
        const api = try getFns();
        var handle: EmulatorHandle = null;
        const hr = api.create(callbacks, &handle);
        if (failed(hr) or handle == null) return error.EmulationFailure;
        return handle;
    }

    pub fn destroy(handle: EmulatorHandle) Error!void {
        const api = try getFns();
        const hr = api.destroy(handle);
        if (failed(hr)) return error.EmulationFailure;
    }

    pub fn tryMmioEmulation(
        handle: EmulatorHandle,
        ctx: ?*anyopaque,
        vp_context: *const WhvVpExitContext,
        memory_context: *const WhvMemoryAccessContext,
        status: *EmulatorStatus,
    ) Error!void {
        const api = try getFns();
        const hr = api.try_mmio(handle, ctx, vp_context, memory_context, status);
        if (failed(hr)) return error.EmulationFailure;
    }
};

// Global runtime state (single active VM instance).
var active_partition: ?Whp.PartitionHandle = null;
var active_memory: ?windows.LPVOID = null;
var active_memory_size: usize = 0;
var active_vcpu: bool = false;
var active_vcpu_thread: ?std.Thread = null;
var active_emulator: WhpEmulator.EmulatorHandle = null;
var interrupt_partition: Whp.PartitionHandle = null;
var vcpu_running = std.atomic.Value(bool).init(false);
var vcpu_alive = std.atomic.Value(bool).init(false);
var cpuid_exit_count = std.atomic.Value(u32).init(0);
var ioport_exit_count = std.atomic.Value(u32).init(0);
var serial_io = SerialIo{};

const EmulationContext = struct {
    partition: Whp.PartitionHandle = null,
    vp_index: u32 = 0,
};

var emu_context = EmulationContext{};

const hresult_ok: HRESULT = 0;
const hresult_fail: HRESULT = @as(HRESULT, @bitCast(@as(u32, 0x80004005)));

fn lifecycleActive() bool {
    return active_partition != null or
        interrupt_partition != null or
        active_memory != null or
        active_memory_size != 0 or
        active_vcpu or
        active_emulator != null or
        active_vcpu_thread != null or
        vcpu_running.load(.seq_cst);
}

fn buildInterruptControl(vector: u32, destination: u32, trigger_mode: WhvInterruptTriggerMode) WhvInterruptControl {
    var bits: u64 = 0;
    bits |= @as(u64, @intFromEnum(WhvInterruptType.Fixed));
    bits |= @as(u64, @intFromEnum(WhvInterruptDestinationMode.Physical)) << 8;
    bits |= @as(u64, @intFromEnum(trigger_mode)) << 12;
    return .{
        .AsUINT64 = bits,
        .Destination = destination,
        .Vector = vector,
    };
}

fn irqToX86Vector(irq: u32) u32 {
    return x86_irq_vector_offset + irq;
}

fn injectVirtioInterrupt(irq: u32) void {
    const handle = interrupt_partition orelse active_partition orelse return;
    const vector = irqToX86Vector(irq);
    const request = buildInterruptControl(vector, 0, .Edge);
    Whp.requestInterrupt(handle, &request) catch |e| {
        log.warn("windows backend failed to inject virtio irq={d} vector=0x{x}: {s}", .{
            irq,
            vector,
            @errorName(e),
        });
    };
}

fn virtioInterruptHandler(irq: u32, level: bool) void {
    // WHP interrupt injection is edge-based for now; only rising edges are injected.
    if (!level) return;
    injectVirtioInterrupt(irq);
}

fn setVirtioDeviceIrqs() void {
    for (virtio.virtio_blk_devices, 0..) |device, index| {
        virtio.gic_virtio_blk_intid[index] = if (device.enabled) virtio_irq_layout.blk[index] else null;
    }
    virtio.gic_virtio_console_intid = if (virtio.virtio_console_state.enabled) virtio_irq_layout.console else null;
    virtio.gic_virtio_rng_intid = if (virtio.virtio_rng_state.enabled) virtio_irq_layout.rng else null;
    virtio.gic_virtio_fs_intid = if (virtio.virtio_fs_state.enabled) virtio_irq_layout.fs else null;
    virtio.gic_virtio_vsock_intid = if (virtio.virtio_vsock_state.enabled) virtio_irq_layout.vsock else null;
}

const VirtioMmioCmdlineEntry = struct {
    base: u64,
    irq: u32,
};

fn parseAutoBaseU64(text: []const u8) !u64 {
    if (text.len == 0) return error.InvalidNumber;
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        if (text.len == 2) return error.InvalidNumber;
        return try std.fmt.parseInt(u64, text[2..], 16);
    }
    return try std.fmt.parseInt(u64, text, 10);
}

fn parseVirtioMmioCmdlineEntry(token: []const u8) ?VirtioMmioCmdlineEntry {
    const prefix = "virtio_mmio.device=";
    const value = if (std.mem.startsWith(u8, token, prefix)) token[prefix.len..] else return null;

    const at = std.mem.indexOfScalar(u8, value, '@') orelse return null;
    const first_colon = std.mem.indexOfPos(u8, value, at + 1, ":") orelse return null;
    const second_colon = std.mem.indexOfPos(u8, value, first_colon + 1, ":");

    if (at == 0) return null; // missing size chunk

    const base_text = value[at + 1 .. first_colon];
    const irq_text = if (second_colon) |idx| value[first_colon + 1 .. idx] else value[first_colon + 1 ..];
    const base = parseAutoBaseU64(base_text) catch return null;
    const irq_value = parseAutoBaseU64(irq_text) catch return null;
    if (irq_value > std.math.maxInt(u32)) return null;

    return .{
        .base = base,
        .irq = @intCast(irq_value),
    };
}

fn setVirtioIrqForBase(base: u64, irq: u32) bool {
    if (virtio.virtioBlkIndexForAddr(base)) |index| {
        if (!virtio.virtio_blk_devices[index].enabled) return false;
        virtio.gic_virtio_blk_intid[index] = irq;
        return true;
    }
    if (base == virtio.virtio_console_mmio_base and virtio.virtio_console_state.enabled) {
        virtio.gic_virtio_console_intid = irq;
        return true;
    }
    if (base == virtio.virtio_rng_mmio_base and virtio.virtio_rng_state.enabled) {
        virtio.gic_virtio_rng_intid = irq;
        return true;
    }
    if (base == virtio.virtio_fs_mmio_base and virtio.virtio_fs_state.enabled) {
        virtio.gic_virtio_fs_intid = irq;
        return true;
    }
    if (base == virtio.virtio_vsock_mmio_base and virtio.virtio_vsock_state.enabled) {
        virtio.gic_virtio_vsock_intid = irq;
        return true;
    }
    return false;
}

fn applyVirtioDeviceIrqsFromCmdline(cmdline: []const u8) void {
    var it = std.mem.tokenizeAny(u8, cmdline, " \t\r\n");
    while (it.next()) |token| {
        const entry = parseVirtioMmioCmdlineEntry(token) orelse continue;
        _ = setVirtioIrqForBase(entry.base, entry.irq);
    }
}

fn cmdlineHasVirtioMmioBase(cmdline: []const u8, base: u64) bool {
    var marker_buf: [32]u8 = undefined;
    const marker = std.fmt.bufPrint(&marker_buf, "@0x{x}", .{base}) catch return false;
    return std.mem.indexOf(u8, cmdline, marker) != null;
}

fn appendKernelArg(allocator: std.mem.Allocator, dst: *std.ArrayList(u8), arg: []const u8) !void {
    if (dst.items.len != 0 and dst.items[dst.items.len - 1] != ' ') try dst.append(allocator, ' ');
    try dst.appendSlice(allocator, arg);
}

fn appendVirtioMmioCmdlineArg(
    allocator: std.mem.Allocator,
    dst: *std.ArrayList(u8),
    base_cmdline: []const u8,
    base: u64,
    size: u64,
    irq: u32,
) !void {
    if (cmdlineHasVirtioMmioBase(base_cmdline, base)) return;
    if (cmdlineHasVirtioMmioBase(dst.items, base)) return;

    var arg_buf: [96]u8 = undefined;
    const arg = try std.fmt.bufPrint(&arg_buf, "virtio_mmio.device=0x{x}@0x{x}:{d}", .{ size, base, irq });
    try appendKernelArg(allocator, dst, arg);
}

fn buildBaseCmdline(allocator: std.mem.Allocator, cfg: config.VmConfig) ![]const u8 {
    return hvf_boot.buildCmdlineWithMounts(allocator, cfg, cmdline_arch);
}

fn buildEffectiveCmdlineFromBase(allocator: std.mem.Allocator, base_cmdline: []const u8) ![]u8 {
    var cmdline: std.ArrayList(u8) = .empty;
    errdefer cmdline.deinit(allocator);
    try cmdline.appendSlice(allocator, base_cmdline);

    for (virtio.virtio_blk_devices, 0..) |device, index| {
        if (!device.enabled) continue;
        try appendVirtioMmioCmdlineArg(
            allocator,
            &cmdline,
            base_cmdline,
            virtio.virtioBlkMmioBase(index),
            virtio.virtio_blk_mmio_size,
            virtio_irq_layout.blk[index],
        );
    }
    if (virtio.virtio_console_state.enabled) {
        try appendVirtioMmioCmdlineArg(
            allocator,
            &cmdline,
            base_cmdline,
            virtio.virtio_console_mmio_base,
            virtio.virtio_console_mmio_size,
            virtio_irq_layout.console,
        );
    }
    if (virtio.virtio_rng_state.enabled) {
        try appendVirtioMmioCmdlineArg(
            allocator,
            &cmdline,
            base_cmdline,
            virtio.virtio_rng_mmio_base,
            virtio.virtio_rng_mmio_size,
            virtio_irq_layout.rng,
        );
    }
    if (virtio.virtio_fs_state.enabled) {
        try appendVirtioMmioCmdlineArg(
            allocator,
            &cmdline,
            base_cmdline,
            virtio.virtio_fs_mmio_base,
            virtio.virtio_fs_mmio_size,
            virtio_irq_layout.fs,
        );
    }
    if (virtio.virtio_vsock_state.enabled) {
        try appendVirtioMmioCmdlineArg(
            allocator,
            &cmdline,
            base_cmdline,
            virtio.virtio_vsock_mmio_base,
            virtio.virtio_vsock_mmio_size,
            virtio_irq_layout.vsock,
        );
    }

    return cmdline.toOwnedSlice(allocator);
}

fn buildEffectiveCmdline(allocator: std.mem.Allocator, cfg: config.VmConfig) ![]u8 {
    const base_cmdline = try buildBaseCmdline(allocator, cfg);
    defer allocator.free(base_cmdline);
    return buildEffectiveCmdlineFromBase(allocator, base_cmdline);
}

fn activeMemorySlice() ?[]u8 {
    const mem_ptr = active_memory orelse return null;
    const base_ptr: [*]u8 = @ptrCast(@alignCast(mem_ptr));
    return base_ptr[0..active_memory_size];
}

fn writeGuestBytes(guest_addr: u64, data: []const u8) !void {
    try guest_mem.writeBytes(activeMemorySlice(), gpa_base, guest_addr, data);
}

fn readGuestBytes(guest_addr: u64, out: []u8) !void {
    try guest_mem.readBytes(activeMemorySlice(), gpa_base, guest_addr, out);
}

fn maybeHandleVirtioMmio(addr: u64, is_write: bool, size: usize, value: u64) ?u64 {
    if (virtio.virtioBlkIndexForAddr(addr)) |index| {
        return virtio.handleVirtioBlkMmio(index, addr - virtio.virtioBlkMmioBase(index), is_write, size, value);
    }
    if (addr >= virtio.virtio_console_mmio_base and addr < virtio.virtio_console_mmio_base + virtio.virtio_console_mmio_size) {
        return virtio.handleVirtioConsoleMmio(addr - virtio.virtio_console_mmio_base, is_write, size, value);
    }
    if (addr >= virtio.virtio_rng_mmio_base and addr < virtio.virtio_rng_mmio_base + virtio.virtio_rng_mmio_size) {
        return virtio.handleVirtioRngMmio(addr - virtio.virtio_rng_mmio_base, is_write, size, value);
    }
    if (addr >= virtio.virtio_fs_mmio_base and addr < virtio.virtio_fs_mmio_base + virtio.virtio_fs_mmio_size) {
        return virtio.handleVirtioFsMmio(addr - virtio.virtio_fs_mmio_base, is_write, size, value);
    }
    if (addr >= virtio.virtio_vsock_mmio_base and addr < virtio.virtio_vsock_mmio_base + virtio.virtio_vsock_mmio_size) {
        return virtio.handleVirtioVsockMmio(addr - virtio.virtio_vsock_mmio_base, is_write, size, value);
    }
    return null;
}

fn isMmioAddress(addr: u64) bool {
    if (virtio.virtioBlkIndexForAddr(addr)) |index| return virtio.virtio_blk_devices[index].enabled;
    if (addr >= virtio.virtio_console_mmio_base and addr < virtio.virtio_console_mmio_base + virtio.virtio_console_mmio_size) {
        return virtio.virtio_console_state.enabled;
    }
    if (addr >= virtio.virtio_rng_mmio_base and addr < virtio.virtio_rng_mmio_base + virtio.virtio_rng_mmio_size) {
        return virtio.virtio_rng_state.enabled;
    }
    if (addr >= virtio.virtio_fs_mmio_base and addr < virtio.virtio_fs_mmio_base + virtio.virtio_fs_mmio_size) {
        return virtio.virtio_fs_state.enabled;
    }
    if (addr >= virtio.virtio_vsock_mmio_base and addr < virtio.virtio_vsock_mmio_base + virtio.virtio_vsock_mmio_size) {
        return virtio.virtio_vsock_state.enabled;
    }
    return false;
}

fn readLeU64(bytes: []const u8) u64 {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < bytes.len and i < 8) : (i += 1) {
        value |= @as(u64, bytes[i]) << @as(u6, @intCast(i * 8));
    }
    return value;
}

fn writeLeU64(buf: *[8]u8, size: usize, value: u64) void {
    @memset(buf, 0);
    var i: usize = 0;
    while (i < size and i < buf.len) : (i += 1) {
        buf[i] = @intCast((value >> @as(u6, @intCast(i * 8))) & 0xFF);
    }
}

fn emuIoPortCallback(_: ?*anyopaque, _: *WhpEmulator.EmulatorIoAccessInfo) callconv(.winapi) HRESULT {
    return hresult_fail;
}

fn emuMemoryCallback(_: ?*anyopaque, access: *WhpEmulator.EmulatorMemoryAccessInfo) callconv(.winapi) HRESULT {
    const size: usize = access.AccessSize;
    if (size == 0 or size > access.Data.len) return hresult_fail;

    if (isMmioAddress(access.GpaAddress)) {
        const is_write = access.Direction != 0;
        const value = if (is_write) readLeU64(access.Data[0..size]) else 0;
        const result = maybeHandleVirtioMmio(access.GpaAddress, is_write, size, value) orelse return hresult_fail;
        if (!is_write) {
            writeLeU64(&access.Data, size, result);
        }
        return hresult_ok;
    }

    if (access.Direction == 0) {
        readGuestBytes(access.GpaAddress, access.Data[0..size]) catch return hresult_fail;
        return hresult_ok;
    }
    writeGuestBytes(access.GpaAddress, access.Data[0..size]) catch return hresult_fail;
    return hresult_ok;
}

fn emuGetRegistersCallback(
    _: ?*anyopaque,
    names: [*]const WhvRegisterName,
    count: u32,
    values: [*]WhvRegisterValue,
) callconv(.winapi) HRESULT {
    const handle = emu_context.partition orelse return hresult_fail;
    const name_slice = names[0..count];
    const value_slice = values[0..count];
    Whp.getVirtualProcessorRegisters(handle, emu_context.vp_index, name_slice, value_slice) catch return hresult_fail;
    return hresult_ok;
}

fn emuSetRegistersCallback(
    _: ?*anyopaque,
    names: [*]const WhvRegisterName,
    count: u32,
    values: [*]const WhvRegisterValue,
) callconv(.winapi) HRESULT {
    const handle = emu_context.partition orelse return hresult_fail;
    const name_slice = names[0..count];
    const value_slice = values[0..count];
    Whp.setVirtualProcessorRegisters(handle, emu_context.vp_index, name_slice, value_slice) catch return hresult_fail;
    return hresult_ok;
}

fn emuTranslateGvaCallback(
    _: ?*anyopaque,
    gva: u64,
    flags: u32,
    result_code: *WhpEmulator.TranslateGvaResultCode,
    gpa: *u64,
) callconv(.winapi) HRESULT {
    const handle = emu_context.partition orelse return hresult_fail;
    var result = WhvTranslateGvaResult{
        .ResultCode = 0,
        .Reserved = 0,
    };
    Whp.translateGva(handle, emu_context.vp_index, gva, flags, &result, gpa) catch return hresult_fail;
    result_code.* = @enumFromInt(result.ResultCode);
    return hresult_ok;
}

const whp_emulator_callbacks = WhpEmulator.EmulatorCallbacks{
    .Size = @sizeOf(WhpEmulator.EmulatorCallbacks),
    .Reserved = 0,
    .IoPortCallbackFn = emuIoPortCallback,
    .MemoryCallbackFn = emuMemoryCallback,
    .GetRegistersCallbackFn = emuGetRegistersCallback,
    .SetRegistersCallbackFn = emuSetRegistersCallback,
    .TranslateGvaCallbackFn = emuTranslateGvaCallback,
};

fn setupVirtio(cfg: config.VmConfig) !void {
    virtio.initGuestIo(.{
        .read_bytes = readGuestBytes,
        .write_bytes = writeGuestBytes,
    });
    try virtio.setupVirtioBlk(cfg);
    virtio.setupVirtioConsole(true);
    virtio.setupVirtioRng(true);
    try virtio.setupVirtioFs(std.heap.page_allocator, cfg, null);
    if (cfg.network_services.len > 0 or cfg.network_mode != .locked_down) {
        const guest_cid = cfg.assigned_guest_cid orelse return error.MissingGuestCid;
        const guest_socket_path = cfg.assigned_guest_session_socket_path orelse return error.MissingGuestSessionSocket;
        try virtio.setupVirtioVsock(true, guest_cid, guest_socket_path);
    } else {
        try virtio.setupVirtioVsock(false, 0, null);
    }
}

fn resetVirtioState() void {
    virtio.resetVirtioBlkState();
    virtio.resetVirtioConsoleState();
    virtio.resetVirtioRngState();
    virtio.resetVirtioFsState();
    virtio.resetVirtioVsockState();
}

fn unmapMmioIfEnabled(handle: Whp.PartitionHandle, base: u64, size: u64, enabled: bool) !void {
    if (!enabled) return;
    try Whp.unmapGpaRange(handle, base, size);
}

fn configureMmioIntercepts(handle: Whp.PartitionHandle) !void {
    for (virtio.virtio_blk_devices, 0..) |device, index| {
        try unmapMmioIfEnabled(handle, virtio.virtioBlkMmioBase(index), virtio.virtio_blk_mmio_size, device.enabled);
    }
    try unmapMmioIfEnabled(handle, virtio.virtio_console_mmio_base, virtio.virtio_console_mmio_size, virtio.virtio_console_state.enabled);
    try unmapMmioIfEnabled(handle, virtio.virtio_rng_mmio_base, virtio.virtio_rng_mmio_size, virtio.virtio_rng_state.enabled);
    try unmapMmioIfEnabled(handle, virtio.virtio_fs_mmio_base, virtio.virtio_fs_mmio_size, virtio.virtio_fs_state.enabled);
    try unmapMmioIfEnabled(handle, virtio.virtio_vsock_mmio_base, virtio.virtio_vsock_mmio_size, virtio.virtio_vsock_state.enabled);
}

fn handleMmioExit(index: u32, ctx: *const WhvRunVpExitContext) bool {
    const emulator = active_emulator orelse {
        log.err("vcpu {d} mmio exit without active emulator", .{index});
        return false;
    };
    var status = std.mem.zeroes(WhpEmulator.EmulatorStatus);
    WhpEmulator.tryMmioEmulation(
        emulator,
        null,
        &ctx.VpContext,
        &ctx.Union.MemoryAccess,
        &status,
    ) catch |e| {
        log.err("vcpu {d} mmio emulation call failed: {s}", .{ index, @errorName(e) });
        return false;
    };
    if (status.Bits.EmulationSuccessful == 1) return true;
    if (status.Bits.GuestCannotBeFaulted == 1) {
        log.warn("vcpu {d} mmio emulation reported GuestCannotBeFaulted", .{index});
        return true;
    }
    log.err("vcpu {d} mmio emulation failed status=0x{x}", .{ index, status.AsUINT32 });
    return false;
}

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

fn runVcpu(handle: Whp.PartitionHandle, index: u32) void {
    log.info("vcpu {d} run loop entered", .{index});

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
            @intFromEnum(WhvRunVpExitReason.MemoryAccess) => {
                if (!handleMmioExit(index, exit_ctx)) break;
                continue;
            },
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

    var file = try std.Io.Dir.cwd().openFile(std.Io.Threaded.global_single_threaded.io(), path, .{});
    defer file.close(std.Io.Threaded.global_single_threaded.io());

    const stat = try file.stat(std.Io.Threaded.global_single_threaded.io());
    if (stat.size > std.math.maxInt(usize)) return error.GuestImageTooLarge;

    const range = guest_mem.checkedRange(memory_len, gpa_base, guest_base, @intCast(stat.size)) catch
        return error.GuestImageTooLarge;

    const mem_ptr = mem orelse return error.MemoryAllocFailed;
    const base_ptr: [*]u8 = @ptrCast(@alignCast(mem_ptr));
    const dst = base_ptr[range.offset..range.end];

    var buf: [4096]u8 = undefined;
    var reader = file.reader(std.Io.Threaded.global_single_threaded.io(), &buf);
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
    return windows_api.VirtualAlloc(
        null,
        size_bytes,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    ) orelse error.MemoryAllocFailed;
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
    if (lifecycleActive()) return error.AlreadyRunning;

    const handle = try Whp.createPartition();
    var release_partition = true;
    errdefer if (release_partition) {
        Whp.deletePartition(handle) catch {};
    };

    try Whp.setupPartition(handle, .{
        .cpu_cores = cfg.cpu_cores,
        .memory_mb = cfg.memory_mb,
    });

    const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
    if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;
    const size_bytes: usize = @intCast(size_bytes_u64);

    const mem = try allocGuestMemory(size_bytes);
    var release_memory = true;
    errdefer if (release_memory) {
        _ = windows_api.VirtualFree(mem, 0, MEM_RELEASE);
    };

    const map_flags: u32 = 0x1 | 0x2 | 0x4; // READ | WRITE | EXECUTE
    try Whp.mapGpaRange(handle, mem, gpa_base, size_bytes_u64, map_flags);
    active_memory = mem;
    active_memory_size = size_bytes;
    errdefer {
        active_memory = null;
        active_memory_size = 0;
    }

    try prepareGuestImage(size_bytes_u64);
    try loadGuestKernel(mem, size_bytes_u64, cfg.kernel_path);
    try loadGuestInitrd(mem, size_bytes_u64, cfg.initrd_path);

    try setupVirtio(cfg);
    errdefer resetVirtioState();
    setVirtioDeviceIrqs();

    const base_cmdline = try buildBaseCmdline(std.heap.page_allocator, cfg);
    defer std.heap.page_allocator.free(base_cmdline);
    const cmdline = try buildEffectiveCmdlineFromBase(std.heap.page_allocator, base_cmdline);
    defer std.heap.page_allocator.free(cmdline);
    if (!std.mem.eql(u8, cmdline, base_cmdline)) {
        log.info("windows backend cmdline with virtio-mmio: {s}", .{cmdline});
    }
    applyVirtioDeviceIrqsFromCmdline(cmdline);
    const boot_state = try boot.computeBootState(
        size_bytes_u64,
        guest_kernel_base,
        guest_cmdline_base,
        cmdline,
    );
    try writeCmdlineToGuest(mem, size_bytes_u64, boot_state, cmdline);

    try Whp.createVirtualProcessor(handle, default_vcpu_index);
    var delete_vcpu = true;
    errdefer if (delete_vcpu) {
        Whp.deleteVirtualProcessor(handle, default_vcpu_index) catch {};
    };

    try setInitialRegisters(handle, default_vcpu_index, boot_state);

    active_emulator = try WhpEmulator.create(&whp_emulator_callbacks);
    var release_emulator = true;
    errdefer if (release_emulator) {
        if (active_emulator) |emu| {
            WhpEmulator.destroy(emu) catch {};
            active_emulator = null;
        }
        emu_context = .{};
    };

    emu_context = .{
        .partition = handle,
        .vp_index = default_vcpu_index,
    };
    try configureMmioIntercepts(handle);

    interrupt_partition = handle;
    errdefer interrupt_partition = null;
    virtio.setInterruptHandler(virtioInterruptHandler);
    errdefer virtio.setInterruptHandler(null);

    serial_io.setFromEnv(std.heap.page_allocator);
    var clear_serial = true;
    errdefer if (clear_serial) serial_io.clear(std.heap.page_allocator);

    vcpu_running.store(true, .seq_cst);
    errdefer vcpu_running.store(false, .seq_cst);

    const vcpu_thread = try std.Thread.spawn(.{}, runVcpu, .{ handle, default_vcpu_index });

    active_partition = handle;
    active_vcpu = true;
    active_vcpu_thread = vcpu_thread;
    release_partition = false;
    release_memory = false;
    delete_vcpu = false;
    clear_serial = false;
    release_emulator = false;

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
    virtio.setInterruptHandler(null);
    interrupt_partition = null;
    vcpu_running.store(false, .seq_cst);

    if (active_partition) |handle| {
        if (active_vcpu) {
            Whp.cancelRunVirtualProcessor(handle, default_vcpu_index) catch |e| {
                log.warn("failed to cancel vcpu: {s}", .{@errorName(e)});
            };
        }
    }

    if (active_vcpu_thread) |t| {
        t.join();
        active_vcpu_thread = null;
    }

    if (active_partition) |handle| {
        if (active_vcpu) {
            Whp.deleteVirtualProcessor(handle, default_vcpu_index) catch |e| {
                log.err("failed to delete vcpu: {s}", .{@errorName(e)});
                return e;
            };
        }

        Whp.deletePartition(handle) catch |e| {
            log.err("failed to delete partition: {s}", .{@errorName(e)});
            return e;
        };
        active_partition = null;
    }

    if (active_memory) |mem| {
        _ = windows_api.VirtualFree(mem, 0, MEM_RELEASE);
        active_memory = null;
    }
    if (active_emulator) |emu| {
        WhpEmulator.destroy(emu) catch |e| {
            log.warn("failed to destroy mmio emulator: {s}", .{@errorName(e)});
        };
        active_emulator = null;
    }
    emu_context = .{};
    active_memory_size = 0;
    active_vcpu = false;
    resetVirtioState();
    serial_io.clear(std.heap.page_allocator);
}

pub fn isVcpuRunning() bool {
    return vcpu_running.load(.seq_cst);
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

    const kernel = env_util.getVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = env_util.getVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
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

    const deadline = sync.milliTimestamp() + 5000;
    while (sync.milliTimestamp() < deadline) {
        if (cpuid_exit_count.load(.seq_cst) > 0 or ioport_exit_count.load(.seq_cst) > 0) break;
        sync.sleep(50 * std.time.ns_per_ms);
    }

    try std.testing.expect(vcpu_alive.load(.seq_cst));
    try std.testing.expect(cpuid_exit_count.load(.seq_cst) > 0 or ioport_exit_count.load(.seq_cst) > 0);
}

fn expectLifecycleReset() !void {
    try std.testing.expect(active_partition == null);
    try std.testing.expect(interrupt_partition == null);
    try std.testing.expect(active_memory == null);
    try std.testing.expectEqual(@as(usize, 0), active_memory_size);
    try std.testing.expect(!active_vcpu);
    try std.testing.expect(active_emulator == null);
    try std.testing.expect(emu_context.partition == null);
    try std.testing.expectEqual(@as(u32, 0), emu_context.vp_index);
    try std.testing.expect(active_vcpu_thread == null);
    try std.testing.expect(!vcpu_running.load(.seq_cst));
}

test "windows: start rejects active lifecycle markers" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    active_vcpu = true;
    defer active_vcpu = false;

    try std.testing.expectError(error.AlreadyRunning, start(cfg_mut));
}

test "windows: stop clears partial lifecycle markers" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;

    active_partition = null;
    active_memory = null;
    active_memory_size = 128;
    active_vcpu = true;
    active_vcpu_thread = null;
    vcpu_running.store(true, .seq_cst);

    try stop();
    try expectLifecycleReset();
}

test "integration: whp repeated start-stop reliability" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    if (!env_util.integrationEnabled(std.testing.allocator, "whp-reliability")) return error.SkipZigTest;

    const kernel = env_util.getVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = env_util.getVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
    defer if (initrd) |i| std.testing.allocator.free(i);
    if (kernel == null or initrd == null) return error.SkipZigTest;

    var cycles: usize = 20;
    const cycles_text = env_util.getVarOwned(std.testing.allocator, "M80_TEST_WHP_RELIABILITY_CYCLES") catch null;
    defer if (cycles_text) |v| std.testing.allocator.free(v);
    if (cycles_text) |value| {
        cycles = std.fmt.parseInt(usize, value, 10) catch 20;
        if (cycles == 0) cycles = 20;
    }

    const cfg = try config.defaultConfig(std.testing.allocator, "whp-reliability");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.kernel_path = try std.testing.allocator.dupe(u8, kernel.?);
    cfg_mut.initrd_path = try std.testing.allocator.dupe(u8, initrd.?);

    var cycle: usize = 0;
    while (cycle < cycles) : (cycle += 1) {
        start(cfg_mut) catch |e| switch (e) {
            error.NotSupported,
            error.LibraryLoadFailed,
            error.ProcNotFound,
            error.WhpFailure,
            => return error.SkipZigTest,
            else => return e,
        };

        // Let WHP vCPU run briefly before stop to exercise lifecycle transitions.
        sync.sleep(200 * std.time.ns_per_ms);

        stop() catch |e| switch (@as(anyerror, e)) {
            error.NotSupported,
            error.LibraryLoadFailed,
            error.ProcNotFound,
            error.WhpFailure,
            => return error.SkipZigTest,
            else => return e,
        };
        try expectLifecycleReset();
    }
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
        var f = try tmp.dir.createFile(std.testing.io, "big.bin", .{});
        defer f.close(std.Io.Threaded.global_single_threaded.io());
        try f.writeStreamingAll(std.Io.Threaded.global_single_threaded.io(), "ab");
    }

    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "big.bin", allocator);
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
        var f = try tmp.dir.createFile(std.testing.io, "small.bin", .{});
        defer f.close(std.Io.Threaded.global_single_threaded.io());
        try f.writeStreamingAll(std.Io.Threaded.global_single_threaded.io(), "a");
    }

    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "small.bin", allocator);
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

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, pos, needle)) |idx| {
        count += 1;
        pos = idx + needle.len;
    }
    return count;
}

test "windows: buildEffectiveCmdline appends enabled virtio-mmio devices" {
    defer resetVirtioState();

    virtio.virtio_blk_devices[0].enabled = true;
    virtio.virtio_console_state.enabled = true;
    virtio.virtio_rng_state.enabled = true;
    virtio.virtio_fs_state.enabled = true;

    setVirtioDeviceIrqs();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    const cmdline = try buildEffectiveCmdline(std.testing.allocator, cfg_mut);
    defer std.testing.allocator.free(cmdline);

    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa000000:5") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa001000:6") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa003000:8") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa005000:10") != null);
}

test "windows: buildEffectiveCmdline uses x86 disk boot defaults" {
    defer resetVirtioState();

    virtio.virtio_blk_devices[0].enabled = true;
    setVirtioDeviceIrqs();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.disk_path = try std.testing.allocator.dupe(u8, "/tmp/root.ext4");

    const cmdline = try buildEffectiveCmdline(std.testing.allocator, cfg_mut);
    defer std.testing.allocator.free(cmdline);

    try std.testing.expect(std.mem.indexOf(u8, cmdline, "console=ttyS0 root=/dev/vda rootwait rw") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa000000:5") != null);
}

test "windows: buildEffectiveCmdline includes mount metadata and virtio-fs mmio" {
    defer resetVirtioState();

    virtio.virtio_fs_state.enabled = true;
    setVirtioDeviceIrqs();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    const roots = try std.testing.allocator.alloc([]const u8, 1);
    roots[0] = try std.testing.allocator.dupe(u8, "/tmp");
    cfg_mut.mount_roots = roots;

    const mount_list = try std.testing.allocator.alloc(mounts.MountConfig, 1);
    mount_list[0] = .{
        .tag = try std.testing.allocator.dupe(u8, "share"),
        .host_path = try std.testing.allocator.dupe(u8, "/tmp/share"),
        .guest_path = try std.testing.allocator.dupe(u8, "/mnt/share"),
        .access = .read_only,
        .mount_type = .virtio_fs,
    };
    cfg_mut.mounts = mount_list;

    const cmdline = try buildEffectiveCmdline(std.testing.allocator, cfg_mut);
    defer std.testing.allocator.free(cmdline);

    try std.testing.expect(std.mem.indexOf(u8, cmdline, "m80.mounts=share:/mnt/share") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa005000:10") != null);
}

test "windows: buildEffectiveCmdline does not duplicate existing virtio-mmio base" {
    defer resetVirtioState();

    virtio.virtio_blk_devices[0].enabled = true;
    setVirtioDeviceIrqs();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.kernel_cmdline = try std.testing.allocator.dupe(
        u8,
        "console=ttyS0 virtio_mmio.device=0x1000@0xa000000:5",
    );

    const cmdline = try buildEffectiveCmdline(std.testing.allocator, cfg_mut);
    defer std.testing.allocator.free(cmdline);

    try std.testing.expectEqual(@as(usize, 1), countOccurrences(cmdline, "virtio_mmio.device=0x1000@0xa000000"));
}

test "windows: setVirtioDeviceIrqs populates enabled devices only" {
    defer resetVirtioState();

    virtio.virtio_blk_devices[0].enabled = true;
    virtio.virtio_console_state.enabled = true;
    virtio.virtio_rng_state.enabled = false;
    virtio.virtio_fs_state.enabled = true;
    virtio.virtio_vsock_state.enabled = false;

    setVirtioDeviceIrqs();

    try std.testing.expectEqual(@as(?u32, 5), virtio.gic_virtio_blk_intid[0]);
    try std.testing.expectEqual(@as(?u32, null), virtio.gic_virtio_blk_intid[1]);
    try std.testing.expectEqual(@as(?u32, null), virtio.gic_virtio_blk_intid[2]);
    try std.testing.expectEqual(@as(?u32, 6), virtio.gic_virtio_console_intid);
    try std.testing.expectEqual(@as(?u32, null), virtio.gic_virtio_rng_intid);
    try std.testing.expectEqual(@as(?u32, 10), virtio.gic_virtio_fs_intid);
    try std.testing.expectEqual(@as(?u32, null), virtio.gic_virtio_vsock_intid);
}

test "windows: buildEffectiveCmdline appends enabled virtio-vsock mmio" {
    defer resetVirtioState();

    virtio.virtio_vsock_state.enabled = true;
    setVirtioDeviceIrqs();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    const cmdline = try buildEffectiveCmdline(std.testing.allocator, cfg_mut);
    defer std.testing.allocator.free(cmdline);

    try std.testing.expect(std.mem.indexOf(u8, cmdline, "virtio_mmio.device=0x1000@0xa006000:11") != null);
    try std.testing.expectEqual(@as(?u32, 11), virtio.gic_virtio_vsock_intid);
}

test "windows: setupVirtio enables vsock for network services" {
    defer resetVirtioState();

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    const services = try std.testing.allocator.alloc(config.Service, 1);
    services[0] = .metadata;
    cfg_mut.network_services = services;
    cfg_mut.assigned_guest_cid = 32;
    cfg_mut.assigned_guest_session_socket_path = try std.testing.allocator.dupe(u8, "/tmp/m80-windows-vsock.sock");

    try setupVirtio(cfg_mut);

    try std.testing.expect(virtio.virtio_vsock_state.enabled);
    try std.testing.expectEqual(@as(u64, 32), virtio.virtio_vsock_state.guest_cid);
    try std.testing.expect(virtio.virtio_vsock_state.bridge_socket_path != null);
}

test "windows: parseVirtioMmioCmdlineEntry parses base and irq" {
    const entry = parseVirtioMmioCmdlineEntry("virtio_mmio.device=1K@0xa000000:5:7");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u64, 0x0a000000), entry.?.base);
    try std.testing.expectEqual(@as(u32, 5), entry.?.irq);
}

test "windows: applyVirtioDeviceIrqsFromCmdline overrides default irq mapping" {
    defer resetVirtioState();

    virtio.virtio_blk_devices[0].enabled = true;
    setVirtioDeviceIrqs();
    try std.testing.expectEqual(@as(?u32, 5), virtio.gic_virtio_blk_intid[0]);

    applyVirtioDeviceIrqsFromCmdline("console=ttyS0 virtio_mmio.device=0x1000@0xa000000:19");
    try std.testing.expectEqual(@as(?u32, 19), virtio.gic_virtio_blk_intid[0]);
}

test "windows: irqToX86Vector adds legacy vector offset" {
    try std.testing.expectEqual(@as(u32, 37), irqToX86Vector(5));
    try std.testing.expectEqual(@as(u32, 43), irqToX86Vector(11));
}

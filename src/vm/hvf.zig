//! macOS Hypervisor Framework (HVF) Backend
//!
//! This module implements the VM backend for macOS using Apple's Hypervisor
//! Framework. HVF provides direct access to hardware virtualization on Intel
//! Macs (VT-x) and Apple Silicon (virtualization.framework under the hood).
//!
//! ## Current Status: Partial Implementation
//! This backend now wires real HVF VM creation, guest memory mapping, and a
//! minimal vCPU run loop. It still lacks a full device model and robust exit
//! handling (e.g., MMIO for arm64 UARTs), so guest boot is not yet complete.
//!
//! ## Guest Memory Layout
//! The guest physical address space is laid out as:
//! ```
//! 0x0000_0000 - Reserved
//! 0x0002_0000 - Kernel command line (guest_cmdline_offset)
//! 0x0010_0000 - x86 kernel load offset (guest_kernel_offset_x86)
//! 0x0008_0000 - arm64 kernel load offset (guest_kernel_offset_arm64)
//! 0x0400_0000 - Initrd load offset (guest_initrd_offset)
//! ```
//!
//! ## Register Setup
//! Uses standard x86-64 Linux boot protocol:
//! - RIP: kernel entry point (0x100000 for bzImage)
//! - RSP: stack pointer (top of memory)
//! - RSI: pointer to boot parameters
//! - CR0: protected mode enabled
//!
//! ## Serial I/O
//! Handles I/O port exits for the 16550 UART (ports 0x3F8-0x3FF)
//! to provide console output from the guest.

const std = @import("std");
const log = @import("../util/log.zig");
const config = @import("../core/config.zig");
const serial = @import("serial.zig");
const boot = @import("boot.zig");
const dtb = @import("dtb.zig");
const builtin = @import("builtin");
const dns = @import("../net/dns.zig");
const net_policy = @import("../net/policy.zig");
const vmnet = @import("../net/vmnet.zig");
const virtio_fs = @import("../fs/virtio_fs.zig");
const mounts = @import("../fs/mounts.zig");
const SerialIo = serial.SerialIo;
const IoExit = serial.IoExit;

// Memory size conversion constant
const mb_to_bytes: u64 = 1024 * 1024;

// Guest physical memory layout - standard Linux boot offsets (from RAM base)
const guest_kernel_offset_x86: u64 = 0x100000; // 1 MB - bzImage load offset
const guest_kernel_offset_arm64: u64 = 0x80000; // 512 KB - common arm64 Image offset
const guest_initrd_offset: u64 = 0x4000000; // 64 MB - initrd loaded after kernel
const guest_cmdline_offset: u64 = 0x20000; // 128 KB - command line before kernel
const arm64_image_magic: u32 = 0x644d5241; // "ARMd" magic at offset 0x38
const arm64_memory_base: u64 = 0x40000000; // QEMU virt RAM base

fn guestMemoryBase() u64 {
    return if (builtin.cpu.arch == .aarch64) arm64_memory_base else 0;
}

fn guestKernelOffset() u64 {
    return if (builtin.cpu.arch == .aarch64) guest_kernel_offset_arm64 else guest_kernel_offset_x86;
}

fn guestKernelBase() u64 {
    return guestMemoryBase() + guestKernelOffset();
}

fn guestInitrdBase() u64 {
    return guestMemoryBase() + guest_initrd_offset;
}

fn guestCmdlineBase() u64 {
    return guestMemoryBase() + guest_cmdline_offset;
}

// Default kernel command line (minimal: enable serial console; add root if disk)
fn defaultCmdlineForConfig(cfg: config.VmConfig) []const u8 {
    if (builtin.cpu.arch == .aarch64) {
        if (cfg.disk_path != null) {
            return if (cfg.disk_readonly)
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait ro"
            else
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait rw";
        }
        return "console=ttyAMA0,115200 earlycon=pl011,0x09000000";
    }
    if (cfg.disk_path != null) {
        return if (cfg.disk_readonly) "console=ttyS0 root=/dev/vda rootwait ro" else "console=ttyS0 root=/dev/vda rootwait rw";
    }
    return "console=ttyS0";
}

const arm64_page_table_alignment: u64 = 0x1000;
const arm64_page_table_bytes: u64 = 0x2000;
const arm64_mair_el1: u64 = 0x000004ff;
const arm64_tcr_el1: u64 = 0x00003510;
const arm64_sctlr_el1: u64 = 0x30d00800;

const gic_dist_base_default: u64 = 0x08000000;
const gic_redist_base_default: u64 = 0x080a0000;
const gic_dist_size_default: u64 = 0x10000;
const gic_redist_size_default: u64 = 0x200000;
const pl011_irq_offset: u32 = 1;
const virtio_blk_device_count: usize = 3;
const virtio_blk_mmio_bases = [_]u64{ 0x0a000000, 0x0a002000, 0x0a004000 };
const virtio_blk_mmio_size: u64 = 0x1000;
const virtio_blk_queue_max: u16 = 128;
const virtio_console_mmio_base: u64 = 0x0a001000;
const virtio_console_mmio_size: u64 = 0x1000;
const virtio_console_queue_max: u16 = 128;
const virtio_rng_mmio_base: u64 = 0x0a003000;
const virtio_rng_mmio_size: u64 = 0x1000;
const virtio_rng_queue_max: u16 = 128;
const virtio_net_mmio_base: u64 = 0x0a004000;
const virtio_net_mmio_size: u64 = 0x1000;
const virtio_net_queue_max: u16 = 256;
const virtio_fs_mmio_base: u64 = 0x0a005000;
const virtio_fs_mmio_size: u64 = 0x1000;
const virtio_fs_queue_max: u16 = 256;

fn virtioBlkMmioBase(index: usize) u64 {
    return virtio_blk_mmio_bases[index];
}

fn virtioBlkIndexForAddr(addr: u64) ?usize {
    for (virtio_blk_mmio_bases, 0..) |base, index| {
        if (addr >= base and addr < base + virtio_blk_mmio_size) return index;
    }
    return null;
}

const GicLayout = struct {
    dist_base: u64,
    redist_base: u64,
    dist_size: u64,
    redist_size: u64,
    dist_alignment: usize,
    redist_alignment: usize,
};

var gic_layout: ?GicLayout = null;

/// Low-level HVF API wrapper.
/// Provides a Zig-friendly interface to the Hypervisor.framework C APIs.
pub const Hvf = struct {
    /// Errors that can occur during HVF operations.
    pub const Error = error{
        /// Feature not yet implemented
        NotImplemented,
        /// Platform doesn't support this operation (not macOS x86_64)
        NotSupported,
        /// HVF API call returned an error
        HvfFailure,
    };

    /// Opaque handle to a VM instance
    pub const VmHandle = usize;

    /// Configuration passed to VM setup
    pub const VmConfig = struct {
        cpu_cores: u16,
        memory_mb: u32,
    };

    /// Creates a new VM partition.
    pub fn createVm() Error!VmHandle {
        if (builtin.os.tag != .macos) return error.NotSupported;
        if (builtin.cpu.arch == .aarch64) {
            try arm64_vm_bindings.create();
            return 0;
        }
        if (builtin.cpu.arch == .x86_64) {
            try x86_vm_bindings.create();
            return 0;
        }
        return error.NotSupported;
    }

    /// Configures the VM with CPU and memory settings.
    pub fn setupVm(handle: VmHandle, cfg: VmConfig) Error!void {
        _ = handle;
        _ = cfg;
        if (builtin.os.tag != .macos) return error.NotSupported;
        return;
    }

    /// Destroys a VM partition and releases resources.
    pub fn deleteVm(handle: VmHandle) Error!void {
        _ = handle;
        if (builtin.os.tag != .macos) return error.NotSupported;
        if (builtin.cpu.arch == .aarch64) return arm64_vm_bindings.destroy();
        if (builtin.cpu.arch == .x86_64) return x86_vm_bindings.destroy();
        return error.NotSupported;
    }

    /// Sets the general-purpose registers for a vCPU.
    /// Only supported on macOS x86_64.
    pub fn setRegs(vcpu: HvfVcpuId, regs: HvfRegs) Error!void {
        if (builtin.os.tag != .macos or builtin.cpu.arch != .x86_64) return error.NotSupported;
        try hvfSetRegs(vcpu, regs);
    }

    /// Sets the segment and control registers for a vCPU.
    /// Only supported on macOS x86_64.
    pub fn setSregs(vcpu: HvfVcpuId, sregs: HvfSregs) Error!void {
        if (builtin.os.tag != .macos or builtin.cpu.arch != .x86_64) return error.NotSupported;
        try hvfSetSregs(vcpu, sregs);
    }

    /// Sets the general-purpose registers for an arm64 vCPU.
    /// Only supported on macOS arm64.
    pub fn setArmRegs(vcpu: arm64_bindings.VcpuId, regs: HvfArmRegs) Error!void {
        if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.NotSupported;
        try arm64_bindings.setRegs(vcpu, regs);
    }

    /// Sets the system registers for an arm64 vCPU.
    /// Only supported on macOS arm64.
    pub fn setArmSregs(vcpu: arm64_bindings.VcpuId, sregs: HvfArmSregs) Error!void {
        if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.NotSupported;
        try arm64_bindings.setSregs(vcpu, sregs);
    }
};

// ---- Hypervisor.framework bindings (x86_64 only) ----
// These bindings are intentionally minimal and documented to keep the register
// mapping clear for newer contributors. We set GPRs, control registers, and
// segment selectors using hv_vcpu_write_register.
const HvfVcpuId = u32;
const HvfReturn = i32;

const HvfReg = enum(u32) {
    RIP = 0,
    RFLAGS = 1,
    RAX = 2,
    RCX = 3,
    RDX = 4,
    RBX = 5,
    RSI = 6,
    RDI = 7,
    RSP = 8,
    RBP = 9,
    R8 = 10,
    R9 = 11,
    R10 = 12,
    R11 = 13,
    R12 = 14,
    R13 = 15,
    R14 = 16,
    R15 = 17,
    CS = 18,
    SS = 19,
    DS = 20,
    ES = 21,
    FS = 22,
    GS = 23,
    IDT_BASE = 24,
    IDT_LIMIT = 25,
    GDT_BASE = 26,
    GDT_LIMIT = 27,
    CR0 = 36,
    CR3 = 39,
    CR4 = 40,
};

const HV_SUCCESS: HvfReturn = 0;

const hvf_memory_read: u64 = 1;
const hvf_memory_write: u64 = 2;
const hvf_memory_exec: u64 = 4;

const hv_err_denied: u32 = 0xFAE94007;
const hv_err_no_device: u32 = 0xFAE94006;
const hv_err_unsupported: u32 = 0xFAE9400F;

fn logHvfFailure(op: []const u8, rc: HvfReturn) void {
    const rc_bits: u32 = @bitCast(rc);
    log.err("hvf {s} failed rc={d} (0x{x})", .{ op, rc, rc_bits });
    if (rc_bits == hv_err_denied) {
        log.err(
            "hvf HV_DENIED: sign the binary with com.apple.security.hypervisor and verify kern.hv_support=1",
            .{},
        );
    } else if (rc_bits == hv_err_no_device or rc_bits == hv_err_unsupported) {
        log.err("hvf unsupported: check kern.hv_support and hardware virtualization support", .{});
    }
}

extern "c" fn hv_vcpu_write_register(vcpu: HvfVcpuId, reg: HvfReg, value: u64) HvfReturn;
extern "c" fn hv_vcpu_read_register(vcpu: HvfVcpuId, reg: HvfReg, value: *u64) HvfReturn;

fn hvfWriteReg(vcpu: HvfVcpuId, reg: HvfReg, value: u64) Hvf.Error!void {
    const rc = hv_vcpu_write_register(vcpu, reg, value);
    if (rc != HV_SUCCESS) return error.HvfFailure;
}

fn hvfReadReg(vcpu: HvfVcpuId, reg: HvfReg) Hvf.Error!u64 {
    var value: u64 = 0;
    const rc = hv_vcpu_read_register(vcpu, reg, &value);
    if (rc != HV_SUCCESS) return error.HvfFailure;
    return value;
}

fn hvfSetRegs(vcpu: HvfVcpuId, regs: HvfRegs) Hvf.Error!void {
    try hvfWriteReg(vcpu, .RAX, regs.rax);
    try hvfWriteReg(vcpu, .RBX, regs.rbx);
    try hvfWriteReg(vcpu, .RCX, regs.rcx);
    try hvfWriteReg(vcpu, .RDX, regs.rdx);
    try hvfWriteReg(vcpu, .RSI, regs.rsi);
    try hvfWriteReg(vcpu, .RDI, regs.rdi);
    try hvfWriteReg(vcpu, .RBP, regs.rbp);
    try hvfWriteReg(vcpu, .RSP, regs.rsp);
    try hvfWriteReg(vcpu, .R8, regs.r8);
    try hvfWriteReg(vcpu, .R9, regs.r9);
    try hvfWriteReg(vcpu, .R10, regs.r10);
    try hvfWriteReg(vcpu, .R11, regs.r11);
    try hvfWriteReg(vcpu, .R12, regs.r12);
    try hvfWriteReg(vcpu, .R13, regs.r13);
    try hvfWriteReg(vcpu, .R14, regs.r14);
    try hvfWriteReg(vcpu, .R15, regs.r15);
    try hvfWriteReg(vcpu, .RIP, regs.rip);
    try hvfWriteReg(vcpu, .RFLAGS, regs.rflags);
}

fn hvfSetSregs(vcpu: HvfVcpuId, sregs: HvfSregs) Hvf.Error!void {
    // HVF exposes segment selectors + GDT/IDT base/limit via register writes.
    // Segment base/limit/attributes are not directly settable through this API,
    // so we only program selectors and the descriptor tables here.
    try hvfWriteReg(vcpu, .CS, sregs.cs.selector);
    try hvfWriteReg(vcpu, .SS, sregs.ss.selector);
    try hvfWriteReg(vcpu, .DS, sregs.ds.selector);
    try hvfWriteReg(vcpu, .ES, sregs.es.selector);
    try hvfWriteReg(vcpu, .FS, sregs.fs.selector);
    try hvfWriteReg(vcpu, .GS, sregs.gs.selector);
    try hvfWriteReg(vcpu, .GDT_BASE, sregs.gdt_base);
    try hvfWriteReg(vcpu, .GDT_LIMIT, sregs.gdt_limit);
    try hvfWriteReg(vcpu, .IDT_BASE, sregs.idt_base);
    try hvfWriteReg(vcpu, .IDT_LIMIT, sregs.idt_limit);
    try hvfWriteReg(vcpu, .CR0, sregs.cr0);
    try hvfWriteReg(vcpu, .CR3, sregs.cr3);
    try hvfWriteReg(vcpu, .CR4, sregs.cr4);
}

// ---- Hypervisor.framework bindings (arm64 only) ----
// We wrap the ARM64-only symbols in a comptime-selected struct so non-arm64
// builds never reference unavailable Hypervisor.framework symbols.
const arm64_bindings = if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64)
    struct {
        const VcpuId = u64;
        const Exit = HvfArmVcpuExit;

        const Reg = enum(u32) {
            X0 = 0,
            X1 = 1,
            X2 = 2,
            X3 = 3,
            X4 = 4,
            X5 = 5,
            X6 = 6,
            X7 = 7,
            X8 = 8,
            X9 = 9,
            X10 = 10,
            X11 = 11,
            X12 = 12,
            X13 = 13,
            X14 = 14,
            X15 = 15,
            X16 = 16,
            X17 = 17,
            X18 = 18,
            X19 = 19,
            X20 = 20,
            X21 = 21,
            X22 = 22,
            X23 = 23,
            X24 = 24,
            X25 = 25,
            X26 = 26,
            X27 = 27,
            X28 = 28,
            X29 = 29,
            X30 = 30,
            PC = 31,
            FPCR = 32,
            FPSR = 33,
            CPSR = 34,
        };

        const SysReg = enum(u16) {
            SCTLR_EL1 = 0xc080,
            MPIDR_EL1 = 0xc005,
            TTBR0_EL1 = 0xc100,
            TTBR1_EL1 = 0xc101,
            TCR_EL1 = 0xc102,
            SPSR_EL1 = 0xc200,
            ELR_EL1 = 0xc201,
            MAIR_EL1 = 0xc510,
            VBAR_EL1 = 0xc600,
            SP_EL1 = 0xe208,
        };

        extern "c" fn hv_vcpu_create(vcpu: *VcpuId, exit: **Exit, config: ?*anyopaque) HvfReturn;
        extern "c" fn hv_vcpu_destroy(vcpu: VcpuId) HvfReturn;
        extern "c" fn hv_vcpu_run(vcpu: VcpuId) HvfReturn;
        extern "c" fn hv_vcpus_exit(vcpus: [*]VcpuId, vcpu_count: u32) HvfReturn;
        extern "c" fn hv_vcpu_get_reg(vcpu: VcpuId, reg: Reg, value: *u64) HvfReturn;
        extern "c" fn hv_vcpu_set_reg(vcpu: VcpuId, reg: Reg, value: u64) HvfReturn;
        extern "c" fn hv_vcpu_set_sys_reg(vcpu: VcpuId, reg: SysReg, value: u64) HvfReturn;

        fn writeReg(vcpu: VcpuId, reg: Reg, value: u64) Hvf.Error!void {
            const rc = hv_vcpu_set_reg(vcpu, reg, value);
            if (rc != HV_SUCCESS) return error.HvfFailure;
        }

        fn readReg(vcpu: VcpuId, reg: Reg) Hvf.Error!u64 {
            var value: u64 = 0;
            const rc = hv_vcpu_get_reg(vcpu, reg, &value);
            if (rc != HV_SUCCESS) return error.HvfFailure;
            return value;
        }

        fn writeSysReg(vcpu: VcpuId, reg: SysReg, value: u64) Hvf.Error!void {
            const rc = hv_vcpu_set_sys_reg(vcpu, reg, value);
            if (rc != HV_SUCCESS) return error.HvfFailure;
        }

        fn createVcpu(exit_out: **Exit) Hvf.Error!VcpuId {
            var vcpu: VcpuId = 0;
            const rc = hv_vcpu_create(&vcpu, exit_out, null);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_create", rc);
                return error.HvfFailure;
            }
            return vcpu;
        }

        fn destroyVcpu(vcpu: VcpuId) Hvf.Error!void {
            const rc = hv_vcpu_destroy(vcpu);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_destroy", rc);
                return error.HvfFailure;
            }
        }

        fn run(vcpu: VcpuId) Hvf.Error!void {
            const rc = hv_vcpu_run(vcpu);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_run", rc);
                return error.HvfFailure;
            }
        }

        fn exit(vcpu: VcpuId) Hvf.Error!void {
            var list = [_]VcpuId{vcpu};
            const rc = hv_vcpus_exit(&list, 1);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpus_exit", rc);
                return error.HvfFailure;
            }
        }

        fn setRegs(vcpu: VcpuId, regs: HvfArmRegs) Hvf.Error!void {
            // GPRs map 1:1 to HV_REG_X*. We program all of them so the vCPU is in a
            // fully-defined state even before the guest starts executing.
            try writeReg(vcpu, .X0, regs.x0);
            try writeReg(vcpu, .X1, regs.x1);
            try writeReg(vcpu, .X2, regs.x2);
            try writeReg(vcpu, .X3, regs.x3);
            try writeReg(vcpu, .X4, regs.x4);
            try writeReg(vcpu, .X5, regs.x5);
            try writeReg(vcpu, .X6, regs.x6);
            try writeReg(vcpu, .X7, regs.x7);
            try writeReg(vcpu, .X8, regs.x8);
            try writeReg(vcpu, .X9, regs.x9);
            try writeReg(vcpu, .X10, regs.x10);
            try writeReg(vcpu, .X11, regs.x11);
            try writeReg(vcpu, .X12, regs.x12);
            try writeReg(vcpu, .X13, regs.x13);
            try writeReg(vcpu, .X14, regs.x14);
            try writeReg(vcpu, .X15, regs.x15);
            try writeReg(vcpu, .X16, regs.x16);
            try writeReg(vcpu, .X17, regs.x17);
            try writeReg(vcpu, .X18, regs.x18);
            try writeReg(vcpu, .X19, regs.x19);
            try writeReg(vcpu, .X20, regs.x20);
            try writeReg(vcpu, .X21, regs.x21);
            try writeReg(vcpu, .X22, regs.x22);
            try writeReg(vcpu, .X23, regs.x23);
            try writeReg(vcpu, .X24, regs.x24);
            try writeReg(vcpu, .X25, regs.x25);
            try writeReg(vcpu, .X26, regs.x26);
            try writeReg(vcpu, .X27, regs.x27);
            try writeReg(vcpu, .X28, regs.x28);
            try writeReg(vcpu, .X29, regs.x29);
            try writeReg(vcpu, .X30, regs.x30);
            try writeReg(vcpu, .PC, regs.pc);
            try writeReg(vcpu, .FPCR, regs.fpcr);
            try writeReg(vcpu, .FPSR, regs.fpsr);
            try writeReg(vcpu, .CPSR, regs.cpsr);
        }

        fn setSregs(vcpu: VcpuId, sregs: HvfArmSregs) Hvf.Error!void {
            // System register programming defines the EL1 execution context. We keep MMU
            // disabled initially and still set the registers explicitly so the starting
            // state is fully deterministic.
            try writeSysReg(vcpu, .SP_EL1, sregs.sp_el1);
            try writeSysReg(vcpu, .SCTLR_EL1, sregs.sctlr_el1);
            try writeSysReg(vcpu, .MPIDR_EL1, sregs.mpidr_el1);
            try writeSysReg(vcpu, .TCR_EL1, sregs.tcr_el1);
            try writeSysReg(vcpu, .TTBR0_EL1, sregs.ttbr0_el1);
            try writeSysReg(vcpu, .TTBR1_EL1, sregs.ttbr1_el1);
            try writeSysReg(vcpu, .MAIR_EL1, sregs.mair_el1);
            try writeSysReg(vcpu, .VBAR_EL1, sregs.vbar_el1);
            try writeSysReg(vcpu, .ELR_EL1, sregs.elr_el1);
            try writeSysReg(vcpu, .SPSR_EL1, sregs.spsr_el1);
        }
    }
else
    struct {
        const Exit = anyopaque;
        const VcpuId = usize;
        const Reg = u32;

        fn createVcpu(_: **Exit) Hvf.Error!VcpuId {
            return error.NotSupported;
        }

        fn destroyVcpu(_: VcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn run(_: VcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn exit(_: VcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn writeReg(_: VcpuId, _: Reg, _: u64) Hvf.Error!void {
            return error.NotSupported;
        }

        fn readReg(_: VcpuId, _: Reg) Hvf.Error!u64 {
            return error.NotSupported;
        }

        fn setRegs(_: usize, _: HvfArmRegs) Hvf.Error!void {
            return error.NotSupported;
        }

        fn setSregs(_: usize, _: HvfArmSregs) Hvf.Error!void {
            return error.NotSupported;
        }
    };

const arm64_vm_bindings = if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64)
    struct {
        extern "c" fn hv_vm_create(config: ?*anyopaque) HvfReturn;
        extern "c" fn hv_vm_destroy() HvfReturn;
        extern "c" fn hv_vm_map(addr: *anyopaque, ipa: u64, size: usize, flags: u64) HvfReturn;
        extern "c" fn hv_vm_unmap(ipa: u64, size: usize) HvfReturn;

        fn create() Hvf.Error!void {
            const rc = hv_vm_create(null);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_create", rc);
                return error.HvfFailure;
            }
        }

        fn destroy() Hvf.Error!void {
            const rc = hv_vm_destroy();
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_destroy", rc);
                return error.HvfFailure;
            }
        }

        fn map(addr: []u8, ipa: u64, flags: u64) Hvf.Error!void {
            const rc = hv_vm_map(@ptrCast(addr.ptr), ipa, addr.len, flags);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_map", rc);
                return error.HvfFailure;
            }
        }

        fn unmap(ipa: u64, size: usize) Hvf.Error!void {
            const rc = hv_vm_unmap(ipa, size);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_unmap", rc);
                return error.HvfFailure;
            }
        }
    }
else
    struct {
        fn create() Hvf.Error!void {
            return error.NotSupported;
        }

        fn destroy() Hvf.Error!void {
            return error.NotSupported;
        }

        fn map(_: []u8, _: u64, _: u64) Hvf.Error!void {
            return error.NotSupported;
        }

        fn unmap(_: u64, _: usize) Hvf.Error!void {
            return error.NotSupported;
        }
    };

const gic_bindings = if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64)
    struct {
        const GicConfig = ?*anyopaque;

        extern "c" fn hv_gic_config_create() GicConfig;
        extern "c" fn hv_gic_config_set_distributor_base(config: GicConfig, base: u64) HvfReturn;
        extern "c" fn hv_gic_config_set_redistributor_base(config: GicConfig, base: u64) HvfReturn;
        extern "c" fn hv_gic_create(config: GicConfig) HvfReturn;
        extern "c" fn hv_gic_set_spi(intid: u32, level: bool) HvfReturn;
        extern "c" fn hv_gic_get_distributor_base_alignment(alignment: *usize) HvfReturn;
        extern "c" fn hv_gic_get_redistributor_base_alignment(alignment: *usize) HvfReturn;
        extern "c" fn hv_gic_get_distributor_size(size: *usize) HvfReturn;
        extern "c" fn hv_gic_get_redistributor_size(size: *usize) HvfReturn;
        extern "c" fn hv_gic_get_spi_interrupt_range(base: *u32, count: *u32) HvfReturn;
        extern "c" fn os_release(obj: *anyopaque) void;

        fn configCreate() Hvf.Error!GicConfig {
            const cfg = hv_gic_config_create();
            if (cfg == null) return error.HvfFailure;
            return cfg;
        }

        fn configRelease(cfg: GicConfig) void {
            if (cfg) |ptr| os_release(ptr);
        }

        fn setDistributorBase(cfg: GicConfig, base: u64) Hvf.Error!void {
            const rc = hv_gic_config_set_distributor_base(cfg orelse return error.HvfFailure, base);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_config_set_distributor_base", rc);
                return error.HvfFailure;
            }
        }

        fn setRedistributorBase(cfg: GicConfig, base: u64) Hvf.Error!void {
            const rc = hv_gic_config_set_redistributor_base(cfg orelse return error.HvfFailure, base);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_config_set_redistributor_base", rc);
                return error.HvfFailure;
            }
        }

        fn create(cfg: GicConfig) Hvf.Error!void {
            const rc = hv_gic_create(cfg orelse return error.HvfFailure);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_create", rc);
                return error.HvfFailure;
            }
        }

        fn setSpi(intid: u32, level: bool) Hvf.Error!void {
            const rc = hv_gic_set_spi(intid, level);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_set_spi", rc);
                return error.HvfFailure;
            }
        }

        fn getDistributorAlignment(out: *usize) Hvf.Error!void {
            const rc = hv_gic_get_distributor_base_alignment(out);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_get_distributor_base_alignment", rc);
                return error.HvfFailure;
            }
        }

        fn getRedistributorAlignment(out: *usize) Hvf.Error!void {
            const rc = hv_gic_get_redistributor_base_alignment(out);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_get_redistributor_base_alignment", rc);
                return error.HvfFailure;
            }
        }

        fn getDistributorSize(out: *usize) Hvf.Error!void {
            const rc = hv_gic_get_distributor_size(out);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_get_distributor_size", rc);
                return error.HvfFailure;
            }
        }

        fn getRedistributorSize(out: *usize) Hvf.Error!void {
            const rc = hv_gic_get_redistributor_size(out);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_get_redistributor_size", rc);
                return error.HvfFailure;
            }
        }

        fn getSpiRange(base: *u32, count: *u32) Hvf.Error!void {
            const rc = hv_gic_get_spi_interrupt_range(base, count);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_get_spi_interrupt_range", rc);
                return error.HvfFailure;
            }
        }
    }
else
    struct {
        const GicConfig = ?*anyopaque;

        fn configCreate() Hvf.Error!GicConfig {
            return error.NotSupported;
        }

        fn configRelease(_: GicConfig) void {}

        fn setDistributorBase(_: GicConfig, _: u64) Hvf.Error!void {
            return error.NotSupported;
        }

        fn setRedistributorBase(_: GicConfig, _: u64) Hvf.Error!void {
            return error.NotSupported;
        }

        fn create(_: GicConfig) Hvf.Error!void {
            return error.NotSupported;
        }

        fn setSpi(_: u32, _: bool) Hvf.Error!void {
            return error.NotSupported;
        }

        fn getDistributorAlignment(_: *usize) Hvf.Error!void {
            return error.NotSupported;
        }

        fn getRedistributorAlignment(_: *usize) Hvf.Error!void {
            return error.NotSupported;
        }

        fn getDistributorSize(_: *usize) Hvf.Error!void {
            return error.NotSupported;
        }

        fn getRedistributorSize(_: *usize) Hvf.Error!void {
            return error.NotSupported;
        }

        fn getSpiRange(_: *u32, _: *u32) Hvf.Error!void {
            return error.NotSupported;
        }
    };

const x86_vm_bindings = if (builtin.os.tag == .macos and builtin.cpu.arch == .x86_64)
    struct {
        extern "c" fn hv_vm_create(flags: u64) HvfReturn;
        extern "c" fn hv_vm_destroy() HvfReturn;
        extern "c" fn hv_vm_map(uva: *const anyopaque, gpa: u64, size: usize, flags: u64) HvfReturn;
        extern "c" fn hv_vm_unmap(gpa: u64, size: usize) HvfReturn;

        fn create() Hvf.Error!void {
            const rc = hv_vm_create(0);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_create", rc);
                return error.HvfFailure;
            }
        }

        fn destroy() Hvf.Error!void {
            const rc = hv_vm_destroy();
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_destroy", rc);
                return error.HvfFailure;
            }
        }

        fn map(addr: []u8, gpa: u64, flags: u64) Hvf.Error!void {
            const rc = hv_vm_map(@ptrCast(addr.ptr), gpa, addr.len, flags);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_map", rc);
                return error.HvfFailure;
            }
        }

        fn unmap(gpa: u64, size: usize) Hvf.Error!void {
            const rc = hv_vm_unmap(gpa, size);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vm_unmap", rc);
                return error.HvfFailure;
            }
        }
    }
else
    struct {
        fn create() Hvf.Error!void {
            return error.NotSupported;
        }

        fn destroy() Hvf.Error!void {
            return error.NotSupported;
        }

        fn map(_: []u8, _: u64, _: u64) Hvf.Error!void {
            return error.NotSupported;
        }

        fn unmap(_: u64, _: usize) Hvf.Error!void {
            return error.NotSupported;
        }
    };

const x86_vcpu_bindings = if (builtin.os.tag == .macos and builtin.cpu.arch == .x86_64)
    struct {
        extern "c" fn hv_vcpu_create(vcpu: *HvfVcpuId, flags: u64) HvfReturn;
        extern "c" fn hv_vcpu_destroy(vcpu: HvfVcpuId) HvfReturn;
        extern "c" fn hv_vcpu_run(vcpu: HvfVcpuId) HvfReturn;
        extern "c" fn hv_vcpu_interrupt(vcpus: [*]HvfVcpuId, vcpu_count: u32) HvfReturn;
        extern "c" fn hv_vmx_vcpu_read_vmcs(vcpu: HvfVcpuId, field: u32, value: *u64) HvfReturn;

        fn createVcpu() Hvf.Error!HvfVcpuId {
            var vcpu: HvfVcpuId = 0;
            const rc = hv_vcpu_create(&vcpu, 0);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_create", rc);
                return error.HvfFailure;
            }
            return vcpu;
        }

        fn destroyVcpu(vcpu: HvfVcpuId) Hvf.Error!void {
            const rc = hv_vcpu_destroy(vcpu);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_destroy", rc);
                return error.HvfFailure;
            }
        }

        fn run(vcpu: HvfVcpuId) Hvf.Error!void {
            const rc = hv_vcpu_run(vcpu);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_run", rc);
                return error.HvfFailure;
            }
        }

        fn interrupt(vcpu: HvfVcpuId) Hvf.Error!void {
            var list = [_]HvfVcpuId{vcpu};
            const rc = hv_vcpu_interrupt(&list, 1);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_interrupt", rc);
                return error.HvfFailure;
            }
        }

        fn readVmcs(vcpu: HvfVcpuId, field: u32) Hvf.Error!u64 {
            var value: u64 = 0;
            const rc = hv_vmx_vcpu_read_vmcs(vcpu, field, &value);
            if (rc != HV_SUCCESS) return error.HvfFailure;
            return value;
        }
    }
else
    struct {
        fn createVcpu() Hvf.Error!HvfVcpuId {
            return error.NotSupported;
        }

        fn destroyVcpu(_: HvfVcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn run(_: HvfVcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn interrupt(_: HvfVcpuId) Hvf.Error!void {
            return error.NotSupported;
        }

        fn readVmcs(_: HvfVcpuId, _: u32) Hvf.Error!u64 {
            return error.NotSupported;
        }
    };

// =============================================================================
// GLOBAL STATE
// =============================================================================
// m80 currently supports a single active VM at a time.
// These globals track the active VM's state.

/// Handle to the currently active VM (null if none)
var active_vm: ?Hvf.VmHandle = null;

/// Size of guest memory in bytes
var active_memory_size: usize = 0;
var active_guest_memory: ?[]u8 = null;

/// vCPU thread handle (for joining on stop)
var active_vcpu_thread: ?std.Thread = null;

/// Active vCPU IDs by architecture (set by vCPU thread)
var active_vcpu_id_x86: ?HvfVcpuId = null;
var active_vcpu_id_arm: ?arm64_bindings.VcpuId = null;

/// Atomic flag: true while vCPU should keep running
var vcpu_running = std.atomic.Value(bool).init(false);

/// Atomic flag: trigger simulated I/O for testing
var simulate_io = std.atomic.Value(bool).init(false);

/// Serial port emulation state
var serial_io = SerialIo{};
var serial_input_thread: ?std.Thread = null;
var serial_input_running = std.atomic.Value(bool).init(false);
var console_socket_thread: ?std.Thread = null;
var console_socket_running = std.atomic.Value(bool).init(false);
var console_socket_path: ?[]u8 = null;

const VirtioConsoleInput = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    mutex: std.Thread.Mutex = .{},
};

var virtio_console_input = VirtioConsoleInput{};

/// GIC wiring for arm64 interrupt injection
var gic_enabled = false;
var gic_uart_intid: ?u32 = null;
var gic_virtio_blk_intid: [virtio_blk_device_count]?u32 = .{ null, null, null };
var gic_virtio_console_intid: ?u32 = null;
var gic_virtio_rng_intid: ?u32 = null;
var virtio_blk_irq_level: [virtio_blk_device_count]bool = .{ false, false, false };
var virtio_console_irq_level = false;
var virtio_rng_irq_level = false;

const VirtioBlkQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

const VirtioBlkDevice = struct {
    enabled: bool = false,
    readonly: bool = false,
    capacity_sectors: u64 = 0,
    file: ?std.fs.File = null,
    status: u32 = 0,
    status_last: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    queue: VirtioBlkQueue = .{},
    log_remaining: u32 = 8,
};

var virtio_blk_devices: [virtio_blk_device_count]VirtioBlkDevice = .{ .{}, .{}, .{} };

const VirtioConsoleQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

const VirtioConsoleState = struct {
    enabled: bool = false,
    status: u32 = 0,
    status_last: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    queues: [2]VirtioConsoleQueue = .{ .{}, .{} },
};

var virtio_console_state = VirtioConsoleState{};

const VirtioRngQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

const VirtioRngState = struct {
    enabled: bool = false,
    status: u32 = 0,
    status_last: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    queue: VirtioRngQueue = .{},
};

var virtio_rng_state = VirtioRngState{};
const VirtioNetQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

const VirtioNetState = struct {
    enabled: bool = false,
    status: u32 = 0,
    status_last: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    queues: [2]VirtioNetQueue = .{ .{}, .{} },
    mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

var virtio_net_state = VirtioNetState{};
var virtio_net_seen = std.atomic.Value(bool).init(false);
var gic_virtio_net_intid: ?u32 = null;
var virtio_net_irq_level = false;

var vmnet_iface: ?vmnet.VmnetInterface = null;
var vmnet_rx_thread: ?std.Thread = null;
var vmnet_rx_running = std.atomic.Value(bool).init(false);
var vmnet_rx_mutex = std.Thread.Mutex{};
var vmnet_rx_cond = std.Thread.Condition{};
var vmnet_rx_pending = false;
var vmnet_dispatch_queue: ?vmnet.c_types.dispatch_queue_t = null;

var net_policy_state: ?net_policy.NetworkPolicy = null;
var net_policy_mutex = std.Thread.Mutex{};

const virtio_fs_tag_len: usize = 36;

const VirtioFsQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

const VirtioFsState = struct {
    enabled: bool = false,
    status: u32 = 0,
    status_last: u32 = 0,
    device_features_sel: u32 = 0,
    driver_features_sel: u32 = 0,
    driver_features: [2]u32 = .{ 0, 0 },
    interrupt_status: u32 = 0,
    queue_sel: u16 = 0,
    queues: [2]VirtioFsQueue = .{ .{}, .{} },
    tag: [virtio_fs_tag_len]u8 = [_]u8{0} ** virtio_fs_tag_len,
    num_queues: u32 = 1,
};

var virtio_fs_state = VirtioFsState{};
var virtio_fs_seen = std.atomic.Value(bool).init(false);
var virtio_fs_config_logged = std.atomic.Value(bool).init(false);
var gic_virtio_fs_intid: ?u32 = null;
var virtio_fs_irq_level = false;
var virtio_fs_device: ?virtio_fs.VirtioFsDevice = null;
var virtio_fs_mount_manager: ?mounts.MountManager = null;

fn resetPl011State() void {
    pl011_state = .{};
    if (serial_io.hasData()) {
        pl011_state.pending |= pl011_int_rx;
    }
    updateUartInterrupt();
}

fn updateVirtioBlkInterrupt(index: usize) void {
    if (!gic_enabled) return;
    if (index >= virtio_blk_devices.len) return;
    const intid = gic_virtio_blk_intid[index] orelse return;
    const device = &virtio_blk_devices[index];
    const level = device.interrupt_status != 0;
    if (level != virtio_blk_irq_level[index]) {
        virtio_blk_irq_level[index] = level;
        log.debug("hvf virtio-blk irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio-blk spi failed: {s}", .{@errorName(e)});
    };
}

fn updateVirtioConsoleInterrupt() void {
    if (!gic_enabled) return;
    const intid = gic_virtio_console_intid orelse return;
    const level = virtio_console_state.interrupt_status != 0;
    if (level != virtio_console_irq_level) {
        virtio_console_irq_level = level;
        log.debug("hvf virtio-console irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio-console spi failed: {s}", .{@errorName(e)});
    };
}

fn updateVirtioRngInterrupt() void {
    if (!gic_enabled) return;
    const intid = gic_virtio_rng_intid orelse return;
    const level = virtio_rng_state.interrupt_status != 0;
    if (level != virtio_rng_irq_level) {
        virtio_rng_irq_level = level;
        log.debug("hvf virtio-rng irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio-rng spi failed: {s}", .{@errorName(e)});
    };
}

fn updateVirtioNetInterrupt() void {
    if (!gic_enabled) return;
    const intid = gic_virtio_net_intid orelse return;
    const level = virtio_net_state.interrupt_status != 0;
    if (level != virtio_net_irq_level) {
        virtio_net_irq_level = level;
        log.debug("hvf virtio-net irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio-net spi failed: {s}", .{@errorName(e)});
    };
}

fn updateVirtioFsInterrupt() void {
    if (!gic_enabled) return;
    const intid = gic_virtio_fs_intid orelse return;
    const level = virtio_fs_state.interrupt_status != 0;
    if (level != virtio_fs_irq_level) {
        virtio_fs_irq_level = level;
        log.debug("hvf virtio-fs irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio-fs spi failed: {s}", .{@errorName(e)});
    };
}

// =============================================================================
// VM EXIT HANDLING
// =============================================================================

/// Reasons why the vCPU exited back to the hypervisor.
const HvfExitReason = enum(u32) {
    /// Unknown/unhandled exit reason
    Unknown = 0,
    /// I/O port access (needs emulation)
    Io = 2,
};

const vmcs_exit_reason_field: u32 = 0x00004402;
const vmcs_exit_qualification_field: u32 = 0x00006400;
const vmcs_exit_instr_len_field: u32 = 0x0000440c;

const vmx_exit_reason_io: u32 = 30;

// =============================================================================
// CPU REGISTER STRUCTURES
// =============================================================================

/// x86-64 general-purpose registers.
/// Used to set initial vCPU state before starting execution.
const HvfRegs = extern struct {
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rbp: u64 = 0,
    rsp: u64 = 0,
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

const HvfSegment = extern struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    attributes: u16 = 0,
};

const HvfSregs = extern struct {
    cs: HvfSegment = .{},
    ds: HvfSegment = .{},
    es: HvfSegment = .{},
    fs: HvfSegment = .{},
    gs: HvfSegment = .{},
    ss: HvfSegment = .{},
    gdt_base: u64 = 0,
    gdt_limit: u16 = 0,
    idt_base: u64 = 0,
    idt_limit: u16 = 0,
    cr0: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
};

const HvfRegSet = extern struct {
    regs: HvfRegs,
    sregs: HvfSregs,
};

const HvfArmRegs = extern struct {
    x0: u64 = 0,
    x1: u64 = 0,
    x2: u64 = 0,
    x3: u64 = 0,
    x4: u64 = 0,
    x5: u64 = 0,
    x6: u64 = 0,
    x7: u64 = 0,
    x8: u64 = 0,
    x9: u64 = 0,
    x10: u64 = 0,
    x11: u64 = 0,
    x12: u64 = 0,
    x13: u64 = 0,
    x14: u64 = 0,
    x15: u64 = 0,
    x16: u64 = 0,
    x17: u64 = 0,
    x18: u64 = 0,
    x19: u64 = 0,
    x20: u64 = 0,
    x21: u64 = 0,
    x22: u64 = 0,
    x23: u64 = 0,
    x24: u64 = 0,
    x25: u64 = 0,
    x26: u64 = 0,
    x27: u64 = 0,
    x28: u64 = 0,
    x29: u64 = 0,
    x30: u64 = 0,
    pc: u64 = 0,
    fpcr: u64 = 0,
    fpsr: u64 = 0,
    cpsr: u64 = 0,
};

const HvfArmSregs = extern struct {
    sp_el1: u64 = 0,
    sctlr_el1: u64 = 0,
    mpidr_el1: u64 = 0,
    tcr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    mair_el1: u64 = 0,
    vbar_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
};

const HvfArmRegSet = extern struct {
    regs: HvfArmRegs,
    sregs: HvfArmSregs,
};

const HvfArmExitReason = enum(u32) {
    Canceled = 0,
    Exception = 1,
    VtimerActivated = 2,
    Unknown = 3,
};

const HvfArmExitException = extern struct {
    syndrome: u64,
    virtual_address: u64,
    physical_address: u64,
};

const HvfArmVcpuExit = extern struct {
    reason: HvfArmExitReason,
    exception: HvfArmExitException,
};

const HvfIoExit = extern struct {
    port: u16,
    access_size: u8,
    access_type: u8, // 0 = read, 1 = write
    is_string: bool,
    has_rep: bool,
    rax: u64,
};

const HvfVcpuExit = extern struct {
    reason: HvfExitReason,
    _padding: u32 = 0,
    data: extern union {
        io: HvfIoExit,
    },
};

fn hvfIoExitToIoExit(exit: HvfIoExit) IoExit {
    const size: usize = switch (exit.access_size) {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        else => 1,
    };
    return .{
        .port = exit.port,
        .is_write = exit.access_type == 1,
        .size = size,
        .rax = exit.rax,
        .is_string = exit.is_string,
        .has_rep = exit.has_rep,
    };
}

fn decodeHvfIoExit(exit: *const HvfVcpuExit) !IoExit {
    if (exit.reason != .Io) return error.NotIoExit;
    return hvfIoExitToIoExit(exit.data.io);
}

fn buildHvfRegs(regs: boot.BootRegs) HvfRegs {
    return .{
        .rip = regs.rip,
        .rsp = regs.rsp,
        .rflags = regs.rflags,
        .rsi = regs.rsi,
    };
}

fn buildHvfSregs() HvfSregs {
    // Placeholder flat segments; real HVF setup should use proper x86 boot state.
    return .{
        .cs = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x8, .attributes = 0xA09B },
        .ds = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x10, .attributes = 0xC093 },
        .es = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x10, .attributes = 0xC093 },
        .fs = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x10, .attributes = 0xC093 },
        .gs = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x10, .attributes = 0xC093 },
        .ss = .{ .base = 0, .limit = 0xFFFFF, .selector = 0x10, .attributes = 0xC093 },
        .gdt_base = 0,
        .gdt_limit = 0,
        .idt_base = 0,
        .idt_limit = 0,
        .cr0 = 0x80000011,
        .cr3 = 0,
        .cr4 = 0,
    };
}

fn buildHvfRegSet(regs: boot.BootRegs) HvfRegSet {
    return .{
        .regs = buildHvfRegs(regs),
        .sregs = buildHvfSregs(),
    };
}

const arm64_default_pstate_el1h: u64 = 0x3c5;

const ArmBootLayout = struct {
    dtb_addr: u64,
    page_table_addr: u64,
};

fn computeArmBootLayout(memory_base: u64, memory_size_bytes: u64, state: boot.BootState, dtb_len: usize) !ArmBootLayout {
    const cmdline_end = state.cmdline_addr + @as(u64, state.cmdline_len) + 1;
    const dtb_addr = std.mem.alignForward(u64, cmdline_end, arm64_page_table_alignment);
    const dtb_end = dtb_addr + @as(u64, dtb_len);
    const page_table_addr = std.mem.alignForward(u64, dtb_end, arm64_page_table_alignment);
    const page_table_end = page_table_addr + arm64_page_table_bytes;
    const memory_end = memory_base + memory_size_bytes;

    if (page_table_end > memory_end) return error.InvalidGuestLayout;
    if (page_table_end > state.stack_top) return error.InvalidGuestLayout;

    return .{
        .dtb_addr = dtb_addr,
        .page_table_addr = page_table_addr,
    };
}

fn buildArmIdentityMap(allocator: std.mem.Allocator, page_table_addr: u64, memory_base: u64) ![]u8 {
    // Build a minimal two-page (L0 + L1) identity map using 1GB blocks.
    // This keeps the initial MMU config simple and deterministic.
    var table = try allocator.alloc(u8, @intCast(arm64_page_table_bytes));
    errdefer allocator.free(table);
    @memset(table, 0);

    const l0_addr = page_table_addr;
    const l1_addr = page_table_addr + arm64_page_table_alignment;

    const l0_entry = l1_addr | 0x3;
    const l1_entry_flags_normal = @as(u64, 0x701);
    const l1_entry_flags_device = @as(u64, 0x705);

    std.mem.writeInt(u64, table[0..8], l0_entry, .little);
    const l1_offset: usize = @intCast(arm64_page_table_alignment);
    const l1_entries = table[l1_offset .. l1_offset + 0x1000];
    const block_size: u64 = 0x40000000;

    // Map low 1GB (devices) and RAM base block if different.
    const low_block: u64 = 0;
    const low_entry = low_block | l1_entry_flags_device;
    {
        const ptr: *[8]u8 = @ptrCast(l1_entries[0..8].ptr);
        std.mem.writeInt(u64, ptr, low_entry, .little);
    }

    if (memory_base % block_size != 0) return error.InvalidGuestLayout;
    const base_index: usize = @intCast(memory_base / block_size);
    if (base_index != 0) {
        const entry_offset = base_index * 8;
        const base_entry = memory_base | l1_entry_flags_normal;
        const ptr: *[8]u8 = @ptrCast(l1_entries[entry_offset .. entry_offset + 8].ptr);
        std.mem.writeInt(u64, ptr, base_entry, .little);
    }

    _ = l0_addr;
    return table;
}

fn buildHvfArmRegs(state: boot.BootState, layout: ArmBootLayout) HvfArmRegs {
    // Arm64 Linux expects X0 to hold the device tree physical address.
    return .{
        .x0 = layout.dtb_addr,
        .pc = state.entry,
        .cpsr = arm64_default_pstate_el1h,
    };
}

fn buildHvfArmSregs(state: boot.BootState, layout: ArmBootLayout) HvfArmSregs {
    // Keep MMU disabled on entry; Linux enables it after its own setup.
    // Page tables are an identity map covering the low 1GB for early boot.
    return .{
        .sp_el1 = state.stack_top,
        .sctlr_el1 = arm64_sctlr_el1,
        .mpidr_el1 = 0,
        .tcr_el1 = arm64_tcr_el1,
        .ttbr0_el1 = layout.page_table_addr,
        .ttbr1_el1 = 0,
        .mair_el1 = arm64_mair_el1,
        .vbar_el1 = 0,
        .elr_el1 = state.entry,
        .spsr_el1 = arm64_default_pstate_el1h,
    };
}

fn buildHvfArmRegSet(state: boot.BootState, layout: ArmBootLayout) HvfArmRegSet {
    return .{
        .regs = buildHvfArmRegs(state, layout),
        .sregs = buildHvfArmSregs(state, layout),
    };
}

fn envFlagPresent(allocator: std.mem.Allocator, name: []const u8) bool {
    const env = std.process.getEnvVarOwned(allocator, name) catch return false;
    allocator.free(env);
    return true;
}

fn handleIoPortWrite(port: u16, size: usize, rax: u64) void {
    if (port == 0x3F8) {
        SerialIo.writeToStdout(size, rax);
        return;
    }
    log.debug("hvf io port write port=0x{x} size={d}", .{ port, size });
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

fn setUartInterruptLevel(level: bool) void {
    if (!gic_enabled) return;
    const intid = gic_uart_intid orelse return;
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set spi failed: {s}", .{@errorName(e)});
    };
}

fn updateUartInterrupt() void {
    const level = (pl011_state.pending & pl011_state.imsc) != 0;
    setUartInterruptLevel(level);
}

fn alignUp(value: u64, alignment: usize) u64 {
    if (alignment <= 1) return value;
    const mask = @as(u64, alignment) - 1;
    return (value + mask) & ~mask;
}

fn computeGicLayout() GicLayout {
    var dist_alignment: usize = 0;
    var redist_alignment: usize = 0;
    var dist_size: usize = @intCast(gic_dist_size_default);
    var redist_size: usize = @intCast(gic_redist_size_default);
    if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64) {
        gic_bindings.getDistributorAlignment(&dist_alignment) catch {};
        gic_bindings.getRedistributorAlignment(&redist_alignment) catch {};
        gic_bindings.getDistributorSize(&dist_size) catch {};
        gic_bindings.getRedistributorSize(&redist_size) catch {};
    }

    var dist_base = gic_dist_base_default;
    if (dist_alignment > 1) {
        dist_base = alignUp(dist_base, dist_alignment);
    }

    var redist_base = gic_redist_base_default;
    const min_redist = dist_base + @as(u64, dist_size);
    if (redist_base < min_redist) {
        redist_base = min_redist;
    }
    if (redist_alignment > 1) {
        redist_base = alignUp(redist_base, redist_alignment);
    }
    if (redist_base == dist_base) {
        redist_base = alignUp(dist_base + @as(u64, dist_size), redist_alignment);
    }

    log.info(
        "hvf gic layout dist=0x{x} size=0x{x} align={d} redist=0x{x} size=0x{x} align={d}",
        .{ dist_base, dist_size, dist_alignment, redist_base, redist_size, redist_alignment },
    );

    return .{
        .dist_base = dist_base,
        .redist_base = redist_base,
        .dist_size = @intCast(dist_size),
        .redist_size = @intCast(redist_size),
        .dist_alignment = dist_alignment,
        .redist_alignment = redist_alignment,
    };
}

fn setupGic() void {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return;

    const layout = gic_layout orelse computeGicLayout();
    log.info(
        "hvf gic config dist=0x{x} size=0x{x} redist=0x{x} size=0x{x} ram_base=0x{x}",
        .{ layout.dist_base, layout.dist_size, layout.redist_base, layout.redist_size, guestMemoryBase() },
    );

    const cfg = gic_bindings.configCreate() catch |e| {
        log.warn("hvf gic config create failed: {s}", .{@errorName(e)});
        return;
    };
    defer gic_bindings.configRelease(cfg);

    gic_bindings.setDistributorBase(cfg, layout.dist_base) catch |e| {
        log.warn("hvf gic set distributor base failed: {s}", .{@errorName(e)});
        return;
    };
    gic_bindings.setRedistributorBase(cfg, layout.redist_base) catch |e| {
        log.warn("hvf gic set redistributor base failed: {s}", .{@errorName(e)});
        return;
    };
    gic_bindings.create(cfg) catch |e| {
        log.warn("hvf gic create failed: {s}", .{@errorName(e)});
        return;
    };

    var spi_base: u32 = 0;
    var spi_count: u32 = 0;
    gic_bindings.getSpiRange(&spi_base, &spi_count) catch |e| {
        log.warn("hvf gic spi range query failed: {s}", .{@errorName(e)});
        return;
    };
    const uart_intid = spi_base + pl011_irq_offset;
    if (uart_intid >= spi_base + spi_count) {
        log.warn("hvf gic uart intid out of range base={d} count={d}", .{ spi_base, spi_count });
        return;
    }
    gic_uart_intid = uart_intid;
    gic_enabled = true;
    log.info("hvf gic enabled spi_base={d} uart_intid={d}", .{ spi_base, uart_intid });
}

const arm64_ec_data_abort_lower: u64 = 0x24;
const arm64_ec_data_abort_same: u64 = 0x25;
const arm64_ec_sysreg: u64 = 0x18;

const arm64_sysreg_op0_shift: u6 = 20;
const arm64_sysreg_op2_shift: u6 = 17;
const arm64_sysreg_op1_shift: u6 = 14;
const arm64_sysreg_crn_shift: u6 = 10;
const arm64_sysreg_rt_shift: u6 = 5;
const arm64_sysreg_crm_shift: u6 = 1;
const arm64_sysreg_dir_mask: u64 = 0x1;

const pl011_base: u64 = 0x09000000;
const pl011_size: u64 = 0x1000;
const pl011_reg_dr: u64 = 0x00;
const pl011_reg_ris: u64 = 0x3c;
const pl011_reg_mis: u64 = 0x40;
const pl011_reg_icr: u64 = 0x44;
const pl011_reg_fr: u64 = 0x18;
const pl011_reg_ibrd: u64 = 0x24;
const pl011_reg_fbrd: u64 = 0x28;
const pl011_reg_lcrh: u64 = 0x2c;
const pl011_reg_cr: u64 = 0x30;
const pl011_reg_imsc: u64 = 0x38;

const pl011_int_rx: u32 = 1 << 4;
const pl011_int_tx: u32 = 1 << 5;

const Pl011State = struct {
    cr: u32 = 0,
    lcrh: u32 = 0,
    ibrd: u32 = 0,
    fbrd: u32 = 0,
    imsc: u32 = 0,
    pending: u32 = 0,
};

var pl011_state = Pl011State{};
var pl011_seen = std.atomic.Value(bool).init(false);
var virtio_console_seen = std.atomic.Value(bool).init(false);
var virtio_rng_seen = std.atomic.Value(bool).init(false);

fn arm64RegFromIndex(index: u5) !arm64_bindings.Reg {
    return switch (index) {
        0 => .X0,
        1 => .X1,
        2 => .X2,
        3 => .X3,
        4 => .X4,
        5 => .X5,
        6 => .X6,
        7 => .X7,
        8 => .X8,
        9 => .X9,
        10 => .X10,
        11 => .X11,
        12 => .X12,
        13 => .X13,
        14 => .X14,
        15 => .X15,
        16 => .X16,
        17 => .X17,
        18 => .X18,
        19 => .X19,
        20 => .X20,
        21 => .X21,
        22 => .X22,
        23 => .X23,
        24 => .X24,
        25 => .X25,
        26 => .X26,
        27 => .X27,
        28 => .X28,
        29 => .X29,
        30 => .X30,
        31 => return error.NotSupported,
    };
}

fn arm64ReadRegByIndex(vcpu: arm64_bindings.VcpuId, index: u5) !u64 {
    if (index == 31) return 0;
    const reg = try arm64RegFromIndex(index);
    return arm64_bindings.readReg(vcpu, reg);
}

fn arm64WriteRegByIndex(vcpu: arm64_bindings.VcpuId, index: u5, value: u64) !void {
    if (index == 31) return;
    const reg = try arm64RegFromIndex(index);
    try arm64_bindings.writeReg(vcpu, reg, value);
}

fn handlePl011Mmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
    const width: usize = @min(size, 4);
    if (!pl011_seen.swap(true, .seq_cst)) {
        log.info("hvf pl011 mmio first access offset=0x{x} write={s}", .{ offset, if (is_write) "yes" else "no" });
    }
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            pl011_reg_dr => {
                const byte: u8 = @intCast(value & 0xFF);
                if (std.ascii.isPrint(byte)) {
                    log.debug("hvf uart tx byte=0x{x:0>2} '{c}'", .{ byte, byte });
                } else {
                    log.debug("hvf uart tx byte=0x{x:0>2}", .{byte});
                }
                SerialIo.writeToStdout(@min(width, 1), value);
                pl011_state.pending |= pl011_int_tx;
            },
            pl011_reg_ibrd => pl011_state.ibrd = v32,
            pl011_reg_fbrd => pl011_state.fbrd = v32,
            pl011_reg_lcrh => pl011_state.lcrh = v32,
            pl011_reg_cr => pl011_state.cr = v32,
            pl011_reg_imsc => pl011_state.imsc = v32,
            pl011_reg_icr => pl011_state.pending = 0,
            else => {},
        }
        updateUartInterrupt();
        return 0;
    }
    if (offset == pl011_reg_dr) {
        const byte = serial_io.readPort(0x3F8, @min(width, 1));
        if (serial_io.hasData()) {
            pl011_state.pending |= pl011_int_rx;
        } else {
            pl011_state.pending &= ~pl011_int_rx;
        }
        updateUartInterrupt();
        return byte;
    }
    if (offset == pl011_reg_fr) {
        var flags: u64 = 0;
        if (!serial_io.hasData()) flags |= 1 << 4; // RXFE
        flags |= 1 << 7; // TXFE
        if (serial_io.hasData()) {
            pl011_state.pending |= pl011_int_rx;
        } else {
            pl011_state.pending &= ~pl011_int_rx;
        }
        updateUartInterrupt();
        return flags;
    }
    if (offset == pl011_reg_ris) return pl011_state.pending;
    if (offset == pl011_reg_mis) return pl011_state.pending & pl011_state.imsc;
    if (offset == pl011_reg_ibrd) return pl011_state.ibrd;
    if (offset == pl011_reg_fbrd) return pl011_state.fbrd;
    if (offset == pl011_reg_lcrh) return pl011_state.lcrh;
    if (offset == pl011_reg_cr) return pl011_state.cr;
    if (offset == pl011_reg_imsc) return pl011_state.imsc;
    return 0;
}

const virtio_mmio_magic: u32 = 0x74726976; // "virt"
const virtio_mmio_version: u32 = 2;
const virtio_mmio_device_id_blk: u32 = 2;
const virtio_mmio_device_id_net: u32 = 1;
const virtio_mmio_device_id_console: u32 = 3;
const virtio_mmio_device_id_rng: u32 = 4;
const virtio_mmio_device_id_fs: u32 = 26;
const virtio_mmio_vendor_id: u32 = 0x4d3830; // "M80"
const virtio_mmio_int_vring: u32 = 1 << 0;

const virtio_mmio_reg_magic: u64 = 0x000;
const virtio_mmio_reg_version: u64 = 0x004;
const virtio_mmio_reg_device_id: u64 = 0x008;
const virtio_mmio_reg_vendor_id: u64 = 0x00c;
const virtio_mmio_reg_device_features: u64 = 0x010;
const virtio_mmio_reg_device_features_sel: u64 = 0x014;
const virtio_mmio_reg_driver_features: u64 = 0x020;
const virtio_mmio_reg_driver_features_sel: u64 = 0x024;
const virtio_mmio_reg_queue_sel: u64 = 0x030;
const virtio_mmio_reg_queue_num_max: u64 = 0x034;
const virtio_mmio_reg_queue_num: u64 = 0x038;
const virtio_mmio_reg_queue_ready: u64 = 0x044;
const virtio_mmio_reg_queue_notify: u64 = 0x050;
const virtio_mmio_reg_interrupt_status: u64 = 0x060;
const virtio_mmio_reg_interrupt_ack: u64 = 0x064;
const virtio_mmio_reg_status: u64 = 0x070;
const virtio_mmio_reg_queue_desc_low: u64 = 0x080;
const virtio_mmio_reg_queue_desc_high: u64 = 0x084;
const virtio_mmio_reg_queue_driver_low: u64 = 0x090;
const virtio_mmio_reg_queue_driver_high: u64 = 0x094;
const virtio_mmio_reg_queue_device_low: u64 = 0x0a0;
const virtio_mmio_reg_queue_device_high: u64 = 0x0a4;
const virtio_mmio_reg_config_generation: u64 = 0x0fc;
const virtio_mmio_reg_config: u64 = 0x100;

const virtio_blk_f_ro: u32 = 1 << 5;
const virtio_f_version_1: u32 = 1 << 0;
const virtio_net_f_mac: u32 = 1 << 5;

const virtio_console_f_size: u32 = 1 << 0;
const virtio_console_f_multiport: u32 = 1 << 1;
const virtio_console_f_emerg_write: u32 = 1 << 2;

const virtio_blk_t_in: u32 = 0;
const virtio_blk_t_out: u32 = 1;
const virtio_blk_t_flush: u32 = 4;

const virtio_blk_s_ok: u8 = 0;
const virtio_blk_s_ioerr: u8 = 1;
const virtio_blk_s_unsupported: u8 = 2;

const VirtqDesc = packed struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

const virtq_desc_flag_next: u16 = 1;
const virtq_desc_flag_write: u16 = 2;
const virtq_desc_flag_indirect: u16 = 4;

const VirtioBlkReq = packed struct {
    @"type": u32,
    reserved: u32,
    sector: u64,
};

fn virtioBlkDeviceFeatures(device: *const VirtioBlkDevice, sel: u32) u32 {
    if (sel == 0) {
        return if (device.readonly) virtio_blk_f_ro else 0;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

fn virtioConsoleDeviceFeatures(sel: u32) u32 {
    if (sel == 0) {
        return 0;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

fn virtioRngDeviceFeatures(sel: u32) u32 {
    switch (sel) {
        0 => return 0,
        1 => return virtio_f_version_1,
        else => return 0,
    }
}

fn virtioNetDeviceFeatures(sel: u32) u32 {
    if (sel == 0) {
        return virtio_net_f_mac;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

fn virtioFsDeviceFeatures(sel: u32) u32 {
    const device = virtio_fs_device orelse return 0;
    const features = device.features;
    return switch (sel) {
        0 => @intCast(features & 0xFFFF_FFFF),
        1 => @intCast((features >> 32) & 0xFFFF_FFFF),
        else => 0,
    };
}

fn resetVirtioBlkQueue(device: *VirtioBlkDevice) void {
    device.queue = .{};
    device.queue_sel = 0;
}

fn resetVirtioBlkDevice(index: usize) void {
    if (index >= virtio_blk_devices.len) return;
    if (virtio_blk_devices[index].file) |*file| file.close();
    virtio_blk_devices[index] = .{};
    gic_virtio_blk_intid[index] = null;
    virtio_blk_irq_level[index] = false;
}

fn resetVirtioBlkState() void {
    var i: usize = 0;
    while (i < virtio_blk_devices.len) : (i += 1) {
        resetVirtioBlkDevice(i);
    }
}

fn resetVirtioConsoleState() void {
    virtio_console_state = .{};
    gic_virtio_console_intid = null;
    virtio_console_irq_level = false;
    virtio_console_input.mutex.lock();
    virtio_console_input.buf.clearRetainingCapacity();
    virtio_console_input.mutex.unlock();
}

fn resetVirtioRngState() void {
    virtio_rng_state = .{};
    gic_virtio_rng_intid = null;
    virtio_rng_irq_level = false;
}

fn resetVirtioNetState() void {
    virtio_net_state = .{};
    gic_virtio_net_intid = null;
    virtio_net_irq_level = false;
    virtio_net_seen.store(false, .seq_cst);
}

fn resetVirtioFsState() void {
    virtio_fs_state = .{};
    gic_virtio_fs_intid = null;
    virtio_fs_irq_level = false;
    virtio_fs_seen.store(false, .seq_cst);
    if (virtio_fs_device) |*device| {
        device.deinit();
        virtio_fs_device = null;
    }
    if (virtio_fs_mount_manager) |*manager| {
        manager.deinit();
        virtio_fs_mount_manager = null;
    }
}

fn setupVirtioConsole(enabled: bool) void {
    resetVirtioConsoleState();
    if (!enabled) return;
    virtio_console_state.enabled = true;
    log.info("hvf virtio-console enabled", .{});
}

fn setupVirtioRng(enabled: bool) void {
    resetVirtioRngState();
    if (!enabled) return;
    virtio_rng_state.enabled = true;
    log.info("hvf virtio-rng enabled", .{});
}

fn setupVirtioNet(enabled: bool, mac: [6]u8) void {
    resetVirtioNetState();
    if (!enabled) return;
    virtio_net_state.enabled = true;
    virtio_net_state.mac = mac;
    log.info(
        "hvf virtio-net enabled mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    );
}

fn setupVirtioFs(allocator: std.mem.Allocator, cfg: config.VmConfig) !void {
    resetVirtioFsState();
    if (cfg.mounts.len == 0) return;
    if (cfg.mounts.len > 1) return error.MountsUnsupported;
    if (cfg.mounts[0].mount_type != .virtio_fs) return error.MountsUnsupported;

    var manager = mounts.MountManager.init(allocator);
    errdefer manager.deinit();
    for (cfg.mount_roots) |root| {
        try manager.addAllowedRoot(root);
    }
    for (cfg.mounts) |mount_cfg| {
        manager.addMount(mount_cfg) catch |e| {
            log.err("hvf mount rejected tag={s} host={s} err={s}", .{
                mount_cfg.tag,
                mount_cfg.host_path,
                @errorName(e),
            });
            return error.MountsInvalid;
        };
    }
    virtio_fs_mount_manager = manager;

    const mount_tag = manager.mounts.items[0].tag;
    const device = virtio_fs.VirtioFsDevice.init(allocator, &virtio_fs_mount_manager.?, mount_tag);
    virtio_fs_device = device;
    virtio_fs_state.enabled = true;
    @memset(&virtio_fs_state.tag, 0);
    const tag_len = @min(mount_tag.len, virtio_fs_state.tag.len);
    @memcpy(virtio_fs_state.tag[0..tag_len], mount_tag[0..tag_len]);
    virtio_fs_state.num_queues = 1;
    log.info("hvf virtio-fs enabled tag={s}", .{mount_tag});
}

fn initNetworkPolicy(cfg: config.VmConfig) !void {
    var policy = net_policy.NetworkPolicy.init(std.heap.page_allocator);
    policy.mode = cfg.network_mode;
    errdefer policy.deinit();

    for (cfg.allowed_domains) |domain| {
        if (domain.len == 0) continue;
        try policy.addDomainRule(domain);
    }
    for (cfg.allowed_ips) |ip_str| {
        if (ip_str.len == 0) continue;
        const rule = net_policy.parseCidr(ip_str) orelse {
            log.err("hvf network allowlist invalid IP/CIDR: {s}", .{ip_str});
            return error.InvalidNetworkConfig;
        };
        try policy.addIpRule(rule.address, rule.prefix_len);
    }
    if (policy.mode == .allowlist and policy.allowed_domains.items.len == 0 and policy.allowed_ips.items.len == 0) {
        log.warn("hvf network allowlist enabled with no rules; all outbound traffic will be blocked", .{});
    }
    net_policy_state = policy;
}

fn startVmnetInterface() !void {
    const iface = vmnet.startShared() catch |e| {
        switch (e) {
            error.NotAuthorized => log.err(
                "hvf vmnet not authorized; ensure com.apple.vm.networking entitlement is present and codesign succeeded",
                .{},
            ),
            else => log.err("hvf vmnet start failed: {s}", .{@errorName(e)}),
        }
        return error.NetworkUnavailable;
    };
    vmnet_iface = iface;
    setupVirtioNet(true, iface.mac);

    const q = vmnet.c_types.dispatch_queue_create("m80.vmnet", null);
    vmnet_dispatch_queue = q;
    vmnet.setEventCallback(iface, q, vmnetEventCallback, null) catch |e| {
        log.warn("hvf vmnet event callback failed: {s}", .{@errorName(e)});
    };

    vmnet_rx_running.store(true, .seq_cst);
    vmnet_rx_thread = std.Thread.spawn(.{}, vmnetRxLoop, .{}) catch |e| {
        vmnet_rx_running.store(false, .seq_cst);
        log.warn("hvf vmnet rx thread failed: {s}", .{@errorName(e)});
        return;
    };
    vmnet_rx_mutex.lock();
    vmnet_rx_pending = true;
    vmnet_rx_cond.signal();
    vmnet_rx_mutex.unlock();
}

fn stopVmnetInterface() void {
    vmnet_rx_running.store(false, .seq_cst);
    vmnet_rx_mutex.lock();
    vmnet_rx_pending = true;
    vmnet_rx_cond.signal();
    vmnet_rx_mutex.unlock();
    if (vmnet_rx_thread) |thread| {
        thread.join();
        vmnet_rx_thread = null;
    }
    if (vmnet_iface) |iface| {
        vmnet.stop(iface) catch |e| {
            log.warn("hvf vmnet stop failed: {s}", .{@errorName(e)});
        };
        vmnet_iface = null;
    }
    vmnet_dispatch_queue = null;
    if (net_policy_state) |*policy| {
        policy.deinit();
        net_policy_state = null;
    }
}

export fn vmnetEventCallback(event_mask: vmnet.c_types.interface_event_t, _: vmnet.c_types.xpc_object_t, _: ?*anyopaque) callconv(.c) void {
    if ((event_mask & vmnet.c_types.VMNET_INTERFACE_PACKETS_AVAILABLE) == 0) return;
    vmnet_rx_mutex.lock();
    vmnet_rx_pending = true;
    vmnet_rx_cond.signal();
    vmnet_rx_mutex.unlock();
}

fn vmnetRxLoop() void {
    var buf: [4096]u8 = undefined;
    var iov = vmnet.c_types.iovec{
        .iov_base = @ptrCast(buf[0..].ptr),
        .iov_len = buf.len,
    };
    var pkt = vmnet.c_types.vmpktdesc{
        .vm_pkt_size = buf.len,
        .vm_pkt_iov = &iov,
        .vm_pkt_iovcnt = 1,
        .vm_flags = 0,
    };

    while (vmnet_rx_running.load(.seq_cst)) {
        vmnet_rx_mutex.lock();
        while (!vmnet_rx_pending and vmnet_rx_running.load(.seq_cst)) {
            vmnet_rx_cond.wait(&vmnet_rx_mutex);
        }
        vmnet_rx_pending = false;
        vmnet_rx_mutex.unlock();

        if (!vmnet_rx_running.load(.seq_cst)) break;

        const iface = vmnet_iface orelse continue;
        while (true) {
            var pktcnt: c_int = 1;
            pkt.vm_pkt_size = buf.len;
            const result = vmnet.readPackets(iface, @ptrCast(&pkt), &pktcnt);
            if (result) |_| {} else |_| {
                break;
            }
            if (pktcnt == 0) break;
            const frame = buf[0..pkt.vm_pkt_size];
            handleInboundFrame(frame);
        }
    }
}

const ether_type_ipv4: u16 = 0x0800;
const ether_type_arp: u16 = 0x0806;
const ip_proto_udp: u8 = 17;

fn handleInboundFrame(frame: []const u8) void {
    if (!virtio_net_state.enabled) return;
    if (frame.len < 14) return;
    if (net_policy_state != null) {
        maybeCacheDnsResponse(frame);
    }
    virtioNetRxPacket(frame) catch |e| {
        log.debug("hvf virtio-net rx drop: {s}", .{@errorName(e)});
    };
}

fn maybeCacheDnsResponse(frame: []const u8) void {
    if (frame.len < 14) return;
    const ethertype = std.mem.readInt(u16, frame[12..14], .big);
    if (ethertype != ether_type_ipv4) return;
    const ip_offset: usize = 14;
    if (frame.len < ip_offset + 20) return;
    const ihl = (frame[ip_offset] & 0x0F) * 4;
    if (frame.len < ip_offset + ihl + 8) return;
    const protocol = frame[ip_offset + 9];
    if (protocol != ip_proto_udp) return;
    const udp_offset = ip_offset + ihl;
    const src_port = std.mem.readInt(u16, frame[udp_offset..][0..2], .big);
    if (src_port != 53) return;
    const payload_offset = udp_offset + 8;
    if (payload_offset >= frame.len) return;
    const payload = frame[payload_offset..];

    net_policy_mutex.lock();
    defer net_policy_mutex.unlock();
    if (net_policy_state) |*policy| {
        if (policy.mode != .allowlist) return;
        var name_buf: [256]u8 = undefined;
        const domain = dns.parseResponseDomain(payload, &name_buf) catch return;
        const records = dns.parseResponse(std.heap.page_allocator, payload) catch return;
        defer std.heap.page_allocator.free(records);
        for (records) |record| {
            policy.addResolvedIp(domain, record.ip, record.ttl) catch continue;
        }
    }
}

fn isDhcpPort(port: u16) bool {
    return port == 67 or port == 68;
}

fn outboundFrameAllowed(frame: []const u8) bool {
    net_policy_mutex.lock();
    defer net_policy_mutex.unlock();
    if (net_policy_state == null) return true;
    const policy = &net_policy_state.?;
    if (policy.mode == .open) return true;

    if (frame.len < 14) return false;
    const ethertype = std.mem.readInt(u16, frame[12..14], .big);
    if (ethertype == ether_type_arp) return true;
    if (ethertype != ether_type_ipv4) return false;

    const ip_offset: usize = 14;
    if (frame.len < ip_offset + 20) return false;
    const ihl = (frame[ip_offset] & 0x0F) * 4;
    if (frame.len < ip_offset + ihl + 8) return false;
    const protocol = frame[ip_offset + 9];
    const dst_ip: [4]u8 = frame[ip_offset + 16 .. ip_offset + 20].*;

    if (protocol == ip_proto_udp) {
        const udp_offset = ip_offset + ihl;
        const src_port = std.mem.readInt(u16, frame[udp_offset..][0..2], .big);
        const dst_port = std.mem.readInt(u16, frame[udp_offset + 2 ..][0..2], .big);
        if (isDhcpPort(src_port) or isDhcpPort(dst_port)) return true;
        if (dst_port == 53) {
            const payload_offset = udp_offset + 8;
            if (payload_offset >= frame.len) return false;
            const payload = frame[payload_offset..];
            var name_buf: [256]u8 = undefined;
            const domain = dns.parseQueryDomain(payload, &name_buf) catch return false;
            return policy.isDomainAllowed(domain);
        }
    }

    return policy.isIpAllowed(dst_ip);
}

fn virtioConsoleInputLen() usize {
    virtio_console_input.mutex.lock();
    defer virtio_console_input.mutex.unlock();
    return virtio_console_input.buf.items.len;
}

fn appendVirtioConsoleInput(bytes: []const u8) void {
    if (bytes.len == 0) return;
    virtio_console_input.mutex.lock();
    defer virtio_console_input.mutex.unlock();
    virtio_console_input.buf.appendSlice(std.heap.page_allocator, bytes) catch {};
}

fn takeVirtioConsoleInput(dst: []u8) usize {
    if (dst.len == 0) return 0;
    virtio_console_input.mutex.lock();
    defer virtio_console_input.mutex.unlock();
    if (virtio_console_input.buf.items.len == 0) return 0;
    const to_copy = @min(dst.len, virtio_console_input.buf.items.len);
    std.mem.copyForwards(u8, dst[0..to_copy], virtio_console_input.buf.items[0..to_copy]);
    const remaining = virtio_console_input.buf.items.len - to_copy;
    if (remaining > 0) {
        std.mem.copyForwards(
            u8,
            virtio_console_input.buf.items[0..remaining],
            virtio_console_input.buf.items[to_copy .. to_copy + remaining],
        );
    }
    virtio_console_input.buf.items.len = remaining;
    return to_copy;
}

fn setVirtioConsoleInputFromEnv(allocator: std.mem.Allocator) void {
    const env = std.process.getEnvVarOwned(allocator, "M80_SERIAL_IN") catch return;
    defer allocator.free(env);
    appendVirtioConsoleInput(env);
}

fn setupVirtioBlk(cfg: config.VmConfig) !void {
    resetVirtioBlkState();
    if (cfg.disk_path) |disk_path| {
        try setupVirtioBlkDevice(0, disk_path, cfg.disk_readonly);
    }
    if (cfg.seed_path) |seed_path| {
        try setupVirtioBlkDevice(1, seed_path, true);
    }
    if (cfg.data_disk_path) |data_path| {
        try setupVirtioBlkDevice(2, data_path, cfg.data_disk_readonly);
    }
}

fn setupVirtioBlkDevice(index: usize, path: []const u8, readonly: bool) !void {
    if (index >= virtio_blk_devices.len) return error.InvalidGuestLayout;

    const file = if (readonly)
        try std.fs.cwd().openFile(path, .{ .mode = .read_only })
    else
        try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    errdefer file.close();

    const stat = try file.stat();
    const sectors = stat.size / 512;
    if (stat.size % 512 != 0) {
        log.warn("hvf virtio-blk[{d}] size not multiple of 512 bytes path={s} size={d}", .{ index, path, stat.size });
    }

    var device = &virtio_blk_devices[index];
    device.* = .{};
    device.enabled = true;
    device.readonly = readonly;
    device.capacity_sectors = sectors;
    device.file = file;

    log.info("hvf virtio-blk[{d}] enabled path={s} sectors={d} ro={s}", .{
        index,
        path,
        sectors,
        if (readonly) "true" else "false",
    });
}

fn writeVirtioBlkStatus(status_addr: u64, status: u8) !void {
    writeGuestByte(status_addr, status) catch |e| {
        log.warn("hvf virtio-blk failed to write status: {s}", .{@errorName(e)});
        return e;
    };
}

fn readVirtqDesc(desc_addr: u64) !VirtqDesc {
    var buf: [@sizeOf(VirtqDesc)]u8 = undefined;
    try readGuestBytes(desc_addr, &buf);
    return std.mem.bytesToValue(VirtqDesc, &buf);
}

fn readVirtioBlkReq(req_addr: u64) !VirtioBlkReq {
    var buf: [@sizeOf(VirtioBlkReq)]u8 = undefined;
    try readGuestBytes(req_addr, &buf);
    return std.mem.bytesToValue(VirtioBlkReq, &buf);
}

fn processVirtioBlkRequest(device: *VirtioBlkDevice, head: u16) !u32 {
    const queue = &device.queue;
    const queue_size = queue.num;
    if (queue_size == 0) return 0;
    if (head >= queue_size) return error.InvalidGuestLayout;

    var desc_index: u16 = head;
    var desc_seen: u16 = 0;

    const desc0_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
    const desc0 = try readVirtqDesc(desc0_addr);
    if (desc0.flags & virtq_desc_flag_indirect != 0) {
        return error.NotSupported;
    }
    if (desc0.len < @sizeOf(VirtioBlkReq)) {
        return error.InvalidGuestLayout;
    }
    const req = try readVirtioBlkReq(desc0.addr);

    if (desc0.flags & virtq_desc_flag_next == 0) {
        return error.InvalidGuestLayout;
    }
    desc_index = desc0.next;
    desc_seen += 1;
    if (desc_seen > queue_size) return error.InvalidGuestLayout;

    const data_desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
    const data_desc = try readVirtqDesc(data_desc_addr);
    if (data_desc.flags & virtq_desc_flag_indirect != 0) {
        return error.NotSupported;
    }

    if (data_desc.flags & virtq_desc_flag_next == 0) {
        return error.InvalidGuestLayout;
    }
    desc_index = data_desc.next;
    desc_seen += 1;
    if (desc_seen > queue_size) return error.InvalidGuestLayout;

    const status_desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
    const status_desc = try readVirtqDesc(status_desc_addr);
    if (status_desc.flags & virtq_desc_flag_write == 0) {
        return error.InvalidGuestLayout;
    }
    if (status_desc.len < 1) {
        return error.InvalidGuestLayout;
    }

    const sector_size: u64 = 512;
    const disk_offset = req.sector * sector_size;
    const data_len: u64 = data_desc.len;
    var status: u8 = virtio_blk_s_ok;
    const disk_len = device.capacity_sectors * sector_size;
    if (disk_offset + data_len > disk_len) {
        status = virtio_blk_s_ioerr;
    }

    switch (req.@"type") {
        virtio_blk_t_in => {
            if (status != virtio_blk_s_ok) {
                // status already set
            } else if ((data_desc.flags & virtq_desc_flag_write) == 0) {
                status = virtio_blk_s_ioerr;
            } else if (device.file) |*file| {
                var remaining = data_len;
                var offset: u64 = 0;
                var buf: [64 * 1024]u8 = undefined;
                while (remaining > 0) {
                    const chunk: usize = @intCast(@min(remaining, buf.len));
                    const n = file.preadAll(buf[0..chunk], disk_offset + offset) catch |e| {
                        log.warn("hvf virtio-blk read failed: {s}", .{@errorName(e)});
                        status = virtio_blk_s_ioerr;
                        break;
                    };
                    if (n != chunk) {
                        status = virtio_blk_s_ioerr;
                        break;
                    }
                    writeGuestBytes(data_desc.addr + offset, buf[0..n]) catch |e| {
                        log.warn("hvf virtio-blk write guest failed: {s}", .{@errorName(e)});
                        status = virtio_blk_s_ioerr;
                        break;
                    };
                    remaining -= @as(u64, n);
                    offset += @as(u64, n);
                }
            } else {
                status = virtio_blk_s_ioerr;
            }
        },
        virtio_blk_t_out => {
            if (status != virtio_blk_s_ok) {
                // status already set
            } else if (device.readonly) {
                status = virtio_blk_s_ioerr;
            } else if ((data_desc.flags & virtq_desc_flag_write) != 0) {
                status = virtio_blk_s_ioerr;
            } else if (device.file) |*file| {
                var remaining = data_len;
                var offset: u64 = 0;
                var buf: [64 * 1024]u8 = undefined;
                while (remaining > 0) {
                    const chunk: usize = @intCast(@min(remaining, buf.len));
                    readGuestBytes(data_desc.addr + offset, buf[0..chunk]) catch |e| {
                        log.warn("hvf virtio-blk read guest failed: {s}", .{@errorName(e)});
                        status = virtio_blk_s_ioerr;
                        break;
                    };
                    file.pwriteAll(buf[0..chunk], disk_offset + offset) catch |e| {
                        log.warn("hvf virtio-blk write failed: {s}", .{@errorName(e)});
                        status = virtio_blk_s_ioerr;
                        break;
                    };
                    remaining -= @as(u64, chunk);
                    offset += @as(u64, chunk);
                }
            } else {
                status = virtio_blk_s_ioerr;
            }
        },
        virtio_blk_t_flush => {
            // no-op for file-backed images
        },
        else => status = virtio_blk_s_unsupported,
    }

    try writeVirtioBlkStatus(status_desc.addr, status);
    if (device.log_remaining > 0) {
        device.log_remaining -= 1;
        log.info(
            "hvf virtio-blk req type={d} sector={d} len={d} status={d}",
            .{ req.@"type", req.sector, data_len, status },
        );
    }
    return @intCast(data_len);
}

fn processVirtioBlkQueue(index: usize) !void {
    if (index >= virtio_blk_devices.len) return;
    const device = &virtio_blk_devices[index];
    if (!device.enabled) return;
    const queue = &device.queue;
    if (!queue.ready or queue.num == 0) return;

    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);
        const used_len = processVirtioBlkRequest(device, head) catch |e| blk: {
            log.warn("hvf virtio-blk[{d}] request failed: {s}", .{ index, @errorName(e) });
            break :blk 0;
        };
        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, used_len);
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
    }
    device.interrupt_status |= virtio_mmio_int_vring;
    updateVirtioBlkInterrupt(index);
}

fn handleVirtioBlkMmio(index: usize, offset: u64, is_write: bool, size: usize, value: u64) u64 {
    if (index >= virtio_blk_devices.len) return 0;
    const device = &virtio_blk_devices[index];
    if (!device.enabled) return 0;
    const width: usize = @min(size, 4);
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            virtio_mmio_reg_device_features_sel => device.device_features_sel = v32,
            virtio_mmio_reg_driver_features_sel => device.driver_features_sel = v32,
            virtio_mmio_reg_driver_features => {
                const sel = device.driver_features_sel;
                if (sel < device.driver_features.len) {
                    device.driver_features[sel] = v32;
                }
            },
            virtio_mmio_reg_queue_sel => device.queue_sel = @intCast(v32 & 0xFFFF),
            virtio_mmio_reg_queue_num => {
                if (device.queue_sel == 0) {
                    const requested: u16 = @intCast(v32 & 0xFFFF);
                    device.queue.num = @min(requested, virtio_blk_queue_max);
                }
            },
            virtio_mmio_reg_queue_ready => {
                if (device.queue_sel == 0) {
                    device.queue.ready = (v32 & 0x1) == 1;
                    log.info("hvf virtio-blk[{d}] queue ready={s}", .{ index, if (device.queue.ready) "true" else "false" });
                }
            },
            virtio_mmio_reg_queue_desc_low => if (device.queue_sel == 0) {
                device.queue.desc_addr = (device.queue.desc_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_desc_high => if (device.queue_sel == 0) {
                device.queue.desc_addr = (@as(u64, v32) << 32) | (device.queue.desc_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_driver_low => if (device.queue_sel == 0) {
                device.queue.avail_addr = (device.queue.avail_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_driver_high => if (device.queue_sel == 0) {
                device.queue.avail_addr = (@as(u64, v32) << 32) | (device.queue.avail_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_device_low => if (device.queue_sel == 0) {
                device.queue.used_addr = (device.queue.used_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_device_high => if (device.queue_sel == 0) {
                device.queue.used_addr = (@as(u64, v32) << 32) | (device.queue.used_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_notify => {
                const queue_index: u16 = @intCast(v32 & 0xFFFF);
                if (queue_index == 0) {
                    processVirtioBlkQueue(index) catch |e| {
                        log.warn("hvf virtio-blk[{d}] queue notify failed: {s}", .{ index, @errorName(e) });
                    };
                    log.debug("hvf virtio-blk[{d}] queue notify", .{index});
                } else {
                    log.warn("hvf virtio-blk[{d}] queue notify unsupported index={d}", .{ index, queue_index });
                }
            },
            virtio_mmio_reg_interrupt_ack => {
                device.interrupt_status &= ~v32;
                updateVirtioBlkInterrupt(index);
                log.debug("hvf virtio-blk[{d}] interrupt ack=0x{x}", .{ index, v32 });
            },
            virtio_mmio_reg_status => {
                if (v32 == 0) {
                    device.status = 0;
                    resetVirtioBlkQueue(device);
                } else {
                    device.status = v32;
                }
                if (device.status != device.status_last) {
                    log.info("hvf virtio-blk[{d}] status=0x{x}", .{ index, device.status });
                    device.status_last = device.status;
                }
            },
            else => {},
        }
        return 0;
    }

    switch (offset) {
        virtio_mmio_reg_magic => return virtio_mmio_magic,
        virtio_mmio_reg_version => return virtio_mmio_version,
        virtio_mmio_reg_device_id => return virtio_mmio_device_id_blk,
        virtio_mmio_reg_vendor_id => return virtio_mmio_vendor_id,
        virtio_mmio_reg_device_features => return virtioBlkDeviceFeatures(device, device.device_features_sel),
        virtio_mmio_reg_device_features_sel => return device.device_features_sel,
        virtio_mmio_reg_driver_features_sel => return device.driver_features_sel,
        virtio_mmio_reg_driver_features => {
            const sel = device.driver_features_sel;
            if (sel < device.driver_features.len) return device.driver_features[sel];
            return 0;
        },
        virtio_mmio_reg_queue_sel => return device.queue_sel,
        virtio_mmio_reg_queue_num_max => return virtio_blk_queue_max,
        virtio_mmio_reg_queue_num => return device.queue.num,
        virtio_mmio_reg_queue_ready => return if (device.queue.ready) 1 else 0,
        virtio_mmio_reg_interrupt_status => return device.interrupt_status,
        virtio_mmio_reg_status => return device.status,
        virtio_mmio_reg_queue_desc_low => return @intCast(device.queue.desc_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_desc_high => return @intCast(device.queue.desc_addr >> 32),
        virtio_mmio_reg_queue_driver_low => return @intCast(device.queue.avail_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_driver_high => return @intCast(device.queue.avail_addr >> 32),
        virtio_mmio_reg_queue_device_low => return @intCast(device.queue.used_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_device_high => return @intCast(device.queue.used_addr >> 32),
        virtio_mmio_reg_config_generation => return 0,
        else => {
            if (offset >= virtio_mmio_reg_config) {
                const config_offset = offset - virtio_mmio_reg_config;
                if (config_offset < 8) {
                    var buf: [8]u8 = undefined;
                    std.mem.writeInt(u64, &buf, device.capacity_sectors, .little);
                    const config_start: usize = @intCast(config_offset);
                    const end = @min(config_start + width, buf.len);
                    var val: u32 = 0;
                    var shift: u6 = 0;
                    var i: usize = config_start;
                    while (i < end) : (i += 1) {
                        val |= @as(u32, buf[i]) << @intCast(shift);
                        shift += 8;
                    }
                    return val;
                }
            }
            return 0;
        },
    }
}

fn processVirtioConsoleQueue(queue_index: u16) !void {
    if (!virtio_console_state.enabled) return;
    if (queue_index >= virtio_console_state.queues.len) return;
    if (queue_index != 1) return;
    const queue = &virtio_console_state.queues[queue_index];
    if (!queue.ready or queue.num == 0) return;

    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);
        var desc_index = head;
        var desc_seen: u16 = 0;
        var total_len: u32 = 0;

        while (true) {
            if (desc_seen > queue.num) return error.InvalidGuestLayout;
            const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
            const desc = try readVirtqDesc(desc_addr);
            if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;

            if ((desc.flags & virtq_desc_flag_write) == 0 and desc.len > 0) {
                var buf: [4096]u8 = undefined;
                var remaining: u64 = desc.len;
                var offset: u64 = 0;
                while (remaining > 0) {
                    const chunk: usize = @intCast(@min(remaining, buf.len));
                    try readGuestBytes(desc.addr + offset, buf[0..chunk]);
                    for (buf[0..chunk]) |b| {
                        SerialIo.writeToStdout(1, b);
                    }
                    remaining -= @as(u64, chunk);
                    offset += @as(u64, chunk);
                }
                total_len += desc.len;
            }

            desc_seen += 1;
            if (desc.flags & virtq_desc_flag_next == 0) break;
            desc_index = desc.next;
        }

        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, total_len);
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
    }

    virtio_console_state.interrupt_status |= virtio_mmio_int_vring;
    updateVirtioConsoleInterrupt();
}

const virtio_net_hdr_len: usize = 10;

fn virtioNetRxPacket(frame: []const u8) !void {
    if (!virtio_net_state.enabled) return;
    const queue = &virtio_net_state.queues[0];
    if (!queue.ready or queue.num == 0) return;

    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    if (queue.last_avail_idx == avail_idx) return;

    const ring_index = queue.last_avail_idx % queue.num;
    const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);
    var desc_index = head;
    var desc_seen: u16 = 0;
    var total_written: u32 = 0;
    var header_offset: usize = 0;
    var frame_offset: usize = 0;
    var header: [virtio_net_hdr_len]u8 = undefined;
    @memset(&header, 0);

    while (true) {
        if (desc_seen > queue.num) return error.InvalidGuestLayout;
        const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
        const desc = try readVirtqDesc(desc_addr);
        if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;
        if ((desc.flags & virtq_desc_flag_write) == 0) return error.InvalidGuestLayout;

        var remaining: u64 = desc.len;
        var offset: u64 = 0;
        while (remaining > 0 and header_offset < header.len) {
            const chunk: usize = @intCast(@min(@as(u64, header.len - header_offset), remaining));
            try writeGuestBytes(desc.addr + offset, header[header_offset .. header_offset + chunk]);
            header_offset += chunk;
            remaining -= @as(u64, chunk);
            offset += @as(u64, chunk);
            total_written += @intCast(chunk);
        }
        while (remaining > 0 and frame_offset < frame.len) {
            const chunk: usize = @intCast(@min(@as(u64, frame.len - frame_offset), remaining));
            try writeGuestBytes(desc.addr + offset, frame[frame_offset .. frame_offset + chunk]);
            frame_offset += chunk;
            remaining -= @as(u64, chunk);
            offset += @as(u64, chunk);
            total_written += @intCast(chunk);
        }

        desc_seen += 1;
        if (header_offset >= header.len and frame_offset >= frame.len) break;
        if (desc.flags & virtq_desc_flag_next == 0) break;
        desc_index = desc.next;
    }

    if (header_offset < header.len or frame_offset < frame.len) return error.OutOfMemory;

    const used_slot = queue.used_idx % queue.num;
    try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
    try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, total_written);
    queue.used_idx +%= 1;
    try writeGuestU16(queue.used_addr + 2, queue.used_idx);
    queue.last_avail_idx +%= 1;

    virtio_net_state.interrupt_status |= virtio_mmio_int_vring;
    updateVirtioNetInterrupt();
}

fn processVirtioNetTxQueue() !void {
    if (!virtio_net_state.enabled) return;
    const queue = &virtio_net_state.queues[1];
    if (!queue.ready or queue.num == 0) return;
    const iface = vmnet_iface orelse return;

    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);
        var desc_index = head;
        var desc_seen: u16 = 0;
        var total_len: u32 = 0;
        var header_skip: usize = virtio_net_hdr_len;
        var frame_buf: [4096]u8 = undefined;
        var frame_len: usize = 0;

        while (true) {
            if (desc_seen > queue.num) return error.InvalidGuestLayout;
            const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
            const desc = try readVirtqDesc(desc_addr);
            if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;

            if ((desc.flags & virtq_desc_flag_write) == 0 and desc.len > 0) {
                var remaining: u64 = desc.len;
                var offset: u64 = 0;
                while (remaining > 0) {
                    var chunk: usize = @intCast(@min(remaining, frame_buf.len));
                    if (header_skip > 0) {
                        const skip_now = @min(header_skip, chunk);
                        header_skip -= skip_now;
                        remaining -= @as(u64, skip_now);
                        offset += @as(u64, skip_now);
                        total_len += @intCast(skip_now);
                        if (remaining == 0) break;
                        chunk = @intCast(@min(remaining, frame_buf.len));
                    }
                    if (frame_len + chunk > frame_buf.len) {
                        remaining = 0;
                        break;
                    }
                    try readGuestBytes(desc.addr + offset, frame_buf[frame_len .. frame_len + chunk]);
                    frame_len += chunk;
                    remaining -= @as(u64, chunk);
                    offset += @as(u64, chunk);
                    total_len += @intCast(chunk);
                }
            }

            desc_seen += 1;
            if (desc.flags & virtq_desc_flag_next == 0) break;
            desc_index = desc.next;
        }

        if (frame_len > 0 and outboundFrameAllowed(frame_buf[0..frame_len])) {
            var iov = vmnet.c_types.iovec{
                .iov_base = @ptrCast(frame_buf[0..].ptr),
                .iov_len = frame_len,
            };
            var pkt = vmnet.c_types.vmpktdesc{
                .vm_pkt_size = frame_len,
                .vm_pkt_iov = &iov,
                .vm_pkt_iovcnt = 1,
                .vm_flags = 0,
            };
            var pktcnt: c_int = 1;
            vmnet.writePackets(iface, @ptrCast(&pkt), &pktcnt) catch |e| {
                log.debug("hvf vmnet write failed: {s}", .{@errorName(e)});
            };
        }

        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, total_len);
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
    }

    virtio_net_state.interrupt_status |= virtio_mmio_int_vring;
    updateVirtioNetInterrupt();
}

fn processVirtioFsQueue(queue_index: usize) !void {
    if (!virtio_fs_state.enabled) return;
    if (queue_index >= virtio_fs_state.queues.len) return;
    const queue = &virtio_fs_state.queues[queue_index];
    if (!queue.ready or queue.num == 0) return;

    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);
        var desc_index = head;
        var desc_seen: u16 = 0;

        var request = std.ArrayList(u8).empty;
        defer request.deinit(std.heap.page_allocator);
        var write_descs = std.ArrayList(struct { addr: u64, len: u32 }).empty;
        defer write_descs.deinit(std.heap.page_allocator);

        while (true) {
            if (desc_seen > queue.num) return error.InvalidGuestLayout;
            const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
            const desc = try readVirtqDesc(desc_addr);
            if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;

            if ((desc.flags & virtq_desc_flag_write) == 0) {
                var remaining: u64 = desc.len;
                var offset: u64 = 0;
                var buf: [4096]u8 = undefined;
                while (remaining > 0) {
                    const chunk: usize = @intCast(@min(remaining, buf.len));
                    try readGuestBytes(desc.addr + offset, buf[0..chunk]);
                    try request.appendSlice(std.heap.page_allocator, buf[0..chunk]);
                    remaining -= @as(u64, chunk);
                    offset += @as(u64, chunk);
                }
            } else {
                try write_descs.append(std.heap.page_allocator, .{ .addr = desc.addr, .len = desc.len });
            }

            desc_seen += 1;
            if (desc.flags & virtq_desc_flag_next == 0) break;
            desc_index = desc.next;
        }

        if (write_descs.items.len == 0) return error.InvalidGuestLayout;

        var total_write_len: usize = 0;
        for (write_descs.items) |entry| total_write_len += entry.len;
        if (total_write_len == 0) return error.InvalidGuestLayout;

        var response_buf = try std.heap.page_allocator.alloc(u8, total_write_len);
        defer std.heap.page_allocator.free(response_buf);

        var response_len: usize = 0;
        if (virtio_fs_device) |*device| {
            response_len = device.handleRequest(request.items, response_buf) catch |e| blk: {
                log.warn("hvf virtio-fs request failed: {s}", .{@errorName(e)});
                break :blk 0;
            };
        }

        if (response_len == 0 and request.items.len >= @sizeOf(virtio_fs.FuseInHeader)) {
            var in_header: virtio_fs.FuseInHeader = undefined;
            @memcpy(std.mem.asBytes(&in_header), request.items[0..@sizeOf(virtio_fs.FuseInHeader)]);
            const out_header: *virtio_fs.FuseOutHeader = @ptrCast(@alignCast(response_buf.ptr));
            out_header.len = @intCast(@sizeOf(virtio_fs.FuseOutHeader));
            out_header.@"error" = -5;
            out_header.unique = in_header.unique;
            response_len = @sizeOf(virtio_fs.FuseOutHeader);
        }

        response_len = @min(response_len, response_buf.len);
        var remaining = response_len;
        var resp_offset: usize = 0;
        for (write_descs.items) |entry| {
            if (remaining == 0) break;
            const chunk = @min(@as(usize, entry.len), remaining);
            try writeGuestBytes(entry.addr, response_buf[resp_offset .. resp_offset + chunk]);
            resp_offset += chunk;
            remaining -= chunk;
        }

        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, @intCast(response_len));
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
    }

    virtio_fs_state.interrupt_status |= virtio_mmio_int_vring;
    updateVirtioFsInterrupt();
}

fn processVirtioConsoleRxQueue() !void {
    if (!virtio_console_state.enabled) return;
    if (virtioConsoleInputLen() == 0) return;
    const queue = &virtio_console_state.queues[0];
    if (!queue.ready or queue.num == 0) return;

    var wrote_any = false;
    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        if (virtioConsoleInputLen() == 0) break;
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);

        var desc_index: u16 = head;
        var desc_seen: u16 = 0;
        var total_written: u32 = 0;

        while (true) {
            if (desc_index >= queue.num) return error.InvalidGuestLayout;
            const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
            const desc = try readVirtqDesc(desc_addr);
            if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;
            if ((desc.flags & virtq_desc_flag_write) == 0) return error.InvalidGuestLayout;

            var remaining: u64 = desc.len;
            var offset: u64 = 0;
            var buf: [256]u8 = undefined;
            while (remaining > 0) {
                const chunk = @min(remaining, buf.len);
                const n = takeVirtioConsoleInput(buf[0..@intCast(chunk)]);
                if (n == 0) break;
                try writeGuestBytes(desc.addr + offset, buf[0..n]);
                total_written += @intCast(n);
                remaining -= @as(u64, n);
                offset += @as(u64, n);
            }

            if (desc.flags & virtq_desc_flag_next == 0) break;
            desc_index = desc.next;
            desc_seen += 1;
            if (desc_seen > queue.num) return error.InvalidGuestLayout;
            if (virtioConsoleInputLen() == 0) break;
        }

        if (total_written == 0) break;

        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, total_written);
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
        wrote_any = true;
    }

    if (wrote_any) {
        virtio_console_state.interrupt_status |= virtio_mmio_int_vring;
        updateVirtioConsoleInterrupt();
    }
}

fn processVirtioRngQueue() !void {
    if (!virtio_rng_state.enabled) return;
    const queue = &virtio_rng_state.queue;
    if (!queue.ready or queue.num == 0) return;

    var wrote_any = false;
    const avail_idx = try readGuestU16(queue.avail_addr + 2);
    while (queue.last_avail_idx != avail_idx) {
        const ring_index = queue.last_avail_idx % queue.num;
        const head = try readGuestU16(queue.avail_addr + 4 + @as(u64, ring_index) * 2);

        var desc_index: u16 = head;
        var desc_seen: u16 = 0;
        var total_written: u32 = 0;

        while (true) {
            if (desc_index >= queue.num) return error.InvalidGuestLayout;
            const desc_addr = queue.desc_addr + @as(u64, desc_index) * @sizeOf(VirtqDesc);
            const desc = try readVirtqDesc(desc_addr);
            if (desc.flags & virtq_desc_flag_indirect != 0) return error.NotSupported;
            if ((desc.flags & virtq_desc_flag_write) == 0) return error.InvalidGuestLayout;

            var remaining: u64 = desc.len;
            var offset: u64 = 0;
            var buf: [256]u8 = undefined;
            while (remaining > 0) {
                const chunk = @min(remaining, buf.len);
                std.crypto.random.bytes(buf[0..@intCast(chunk)]);
                try writeGuestBytes(desc.addr + offset, buf[0..@intCast(chunk)]);
                total_written += @intCast(chunk);
                remaining -= @as(u64, chunk);
                offset += @as(u64, chunk);
            }

            if (desc.flags & virtq_desc_flag_next == 0) break;
            desc_index = desc.next;
            desc_seen += 1;
            if (desc_seen > queue.num) return error.InvalidGuestLayout;
        }

        const used_slot = queue.used_idx % queue.num;
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8, head);
        try writeGuestU32(queue.used_addr + 4 + @as(u64, used_slot) * 8 + 4, total_written);
        queue.used_idx +%= 1;
        try writeGuestU16(queue.used_addr + 2, queue.used_idx);
        queue.last_avail_idx +%= 1;
        wrote_any = true;
    }

    if (wrote_any) {
        virtio_rng_state.interrupt_status |= virtio_mmio_int_vring;
        updateVirtioRngInterrupt();
    }
}

fn handleVirtioConsoleMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
    if (!virtio_console_state.enabled) return 0;
    if (!virtio_console_seen.swap(true, .seq_cst)) {
        log.info("hvf virtio-console mmio first access offset=0x{x} write={s}", .{ offset, if (is_write) "yes" else "no" });
    }
    const width: usize = @min(size, 4);
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            virtio_mmio_reg_device_features_sel => virtio_console_state.device_features_sel = v32,
            virtio_mmio_reg_driver_features_sel => virtio_console_state.driver_features_sel = v32,
            virtio_mmio_reg_driver_features => {
                const sel = virtio_console_state.driver_features_sel;
                if (sel < virtio_console_state.driver_features.len) {
                    virtio_console_state.driver_features[sel] = v32;
                }
            },
            virtio_mmio_reg_queue_sel => virtio_console_state.queue_sel = @intCast(v32 & 0xFFFF),
            virtio_mmio_reg_queue_num => {
                if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                    const requested: u16 = @intCast(v32 & 0xFFFF);
                    virtio_console_state.queues[virtio_console_state.queue_sel].num = @min(requested, virtio_console_queue_max);
                }
            },
            virtio_mmio_reg_queue_ready => {
                if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                    virtio_console_state.queues[virtio_console_state.queue_sel].ready = (v32 & 0x1) == 1;
                    log.info("hvf virtio-console queue {d} ready={s}", .{
                        virtio_console_state.queue_sel,
                        if (virtio_console_state.queues[virtio_console_state.queue_sel].ready) "true" else "false",
                    });
                }
            },
            virtio_mmio_reg_queue_desc_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.desc_addr = (q.desc_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_desc_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.desc_addr = (@as(u64, v32) << 32) | (q.desc_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_driver_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.avail_addr = (q.avail_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_driver_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.avail_addr = (@as(u64, v32) << 32) | (q.avail_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_device_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.used_addr = (q.used_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_device_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                const q = &virtio_console_state.queues[virtio_console_state.queue_sel];
                q.used_addr = (@as(u64, v32) << 32) | (q.used_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_notify => {
                const queue_index: u16 = @intCast(v32 & 0xFFFF);
                if (queue_index < virtio_console_state.queues.len) {
                    if (queue_index == 0) {
                        processVirtioConsoleRxQueue() catch |e| {
                            log.warn("hvf virtio-console rx notify failed: {s}", .{@errorName(e)});
                        };
                    } else {
                        processVirtioConsoleQueue(queue_index) catch |e| {
                            log.warn("hvf virtio-console queue notify failed: {s}", .{@errorName(e)});
                        };
                    }
                    log.debug("hvf virtio-console queue notify={d}", .{queue_index});
                } else {
                    log.warn("hvf virtio-console queue notify unsupported index={d}", .{queue_index});
                }
            },
            virtio_mmio_reg_interrupt_ack => {
                virtio_console_state.interrupt_status &= ~v32;
                updateVirtioConsoleInterrupt();
            },
            virtio_mmio_reg_status => {
                if (v32 == 0) {
                    virtio_console_state.status = 0;
                    virtio_console_state.queues = .{ .{}, .{} };
                } else {
                    virtio_console_state.status = v32;
                }
                if (virtio_console_state.status != virtio_console_state.status_last) {
                    log.info("hvf virtio-console status=0x{x}", .{virtio_console_state.status});
                    virtio_console_state.status_last = virtio_console_state.status;
                }
            },
            else => {},
        }
        return 0;
    }

    return switch (offset) {
        virtio_mmio_reg_magic => virtio_mmio_magic,
        virtio_mmio_reg_version => virtio_mmio_version,
        virtio_mmio_reg_device_id => virtio_mmio_device_id_console,
        virtio_mmio_reg_vendor_id => virtio_mmio_vendor_id,
        virtio_mmio_reg_device_features => virtioConsoleDeviceFeatures(virtio_console_state.device_features_sel),
        virtio_mmio_reg_device_features_sel => virtio_console_state.device_features_sel,
        virtio_mmio_reg_driver_features_sel => virtio_console_state.driver_features_sel,
        virtio_mmio_reg_driver_features => blk: {
            const sel = virtio_console_state.driver_features_sel;
            if (sel < virtio_console_state.driver_features.len) break :blk virtio_console_state.driver_features[sel];
            break :blk 0;
        },
        virtio_mmio_reg_queue_sel => virtio_console_state.queue_sel,
        virtio_mmio_reg_queue_num_max => virtio_console_queue_max,
        virtio_mmio_reg_queue_num => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            virtio_console_state.queues[virtio_console_state.queue_sel].num
        else
            0,
        virtio_mmio_reg_queue_ready => blk: {
            var ready = false;
            if (virtio_console_state.queue_sel < virtio_console_state.queues.len) {
                ready = virtio_console_state.queues[virtio_console_state.queue_sel].ready;
            }
            break :blk @intFromBool(ready);
        },
        virtio_mmio_reg_interrupt_status => virtio_console_state.interrupt_status,
        virtio_mmio_reg_status => virtio_console_state.status,
        virtio_mmio_reg_queue_desc_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].desc_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_desc_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].desc_addr >> 32))
        else
            0,
        virtio_mmio_reg_queue_driver_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].avail_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_driver_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].avail_addr >> 32))
        else
            0,
        virtio_mmio_reg_queue_device_low => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].used_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_device_high => if (virtio_console_state.queue_sel < virtio_console_state.queues.len)
            @as(u64, @intCast(virtio_console_state.queues[virtio_console_state.queue_sel].used_addr >> 32))
        else
            0,
        virtio_mmio_reg_config_generation => 0,
        else => blk: {
            if (offset >= virtio_mmio_reg_config) {
                const config_offset = offset - virtio_mmio_reg_config;
                var buf: [12]u8 = undefined;
                std.mem.writeInt(u16, buf[0..2], 80, .little);
                std.mem.writeInt(u16, buf[2..4], 24, .little);
                std.mem.writeInt(u32, buf[4..8], 1, .little);
                std.mem.writeInt(u32, buf[8..12], 0, .little);
                if (config_offset < buf.len) {
                    const config_start: usize = @intCast(config_offset);
                    const end = @min(config_start + width, buf.len);
                    var val: u32 = 0;
                    var shift: u6 = 0;
                    var i: usize = config_start;
                    while (i < end) : (i += 1) {
                        val |= @as(u32, buf[i]) << @intCast(shift);
                        shift += 8;
                    }
                    break :blk val;
                }
            }
            break :blk 0;
        },
    };
}

fn handleVirtioNetMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
    if (!virtio_net_state.enabled) return 0;
    if (!virtio_net_seen.swap(true, .seq_cst)) {
        log.info("hvf virtio-net mmio first access offset=0x{x} write={s}", .{ offset, if (is_write) "yes" else "no" });
    }
    const width: usize = @min(size, 4);
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            virtio_mmio_reg_device_features_sel => virtio_net_state.device_features_sel = v32,
            virtio_mmio_reg_driver_features_sel => virtio_net_state.driver_features_sel = v32,
            virtio_mmio_reg_driver_features => {
                const sel = virtio_net_state.driver_features_sel;
                if (sel < virtio_net_state.driver_features.len) {
                    virtio_net_state.driver_features[sel] = v32;
                }
            },
            virtio_mmio_reg_queue_sel => virtio_net_state.queue_sel = @intCast(v32 & 0xFFFF),
            virtio_mmio_reg_queue_num => {
                const requested: u16 = @intCast(v32 & 0xFFFF);
                if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                    virtio_net_state.queues[virtio_net_state.queue_sel].num = @min(requested, virtio_net_queue_max);
                }
            },
            virtio_mmio_reg_queue_ready => {
                if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                    virtio_net_state.queues[virtio_net_state.queue_sel].ready = (v32 & 0x1) == 1;
                }
            },
            virtio_mmio_reg_queue_desc_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.desc_addr = (q.desc_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_desc_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.desc_addr = (@as(u64, v32) << 32) | (q.desc_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_driver_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.avail_addr = (q.avail_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_driver_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.avail_addr = (@as(u64, v32) << 32) | (q.avail_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_device_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.used_addr = (q.used_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_device_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                const q = &virtio_net_state.queues[virtio_net_state.queue_sel];
                q.used_addr = (@as(u64, v32) << 32) | (q.used_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_notify => {
                const queue_index: u16 = @intCast(v32 & 0xFFFF);
                if (queue_index == 1) {
                    processVirtioNetTxQueue() catch |e| {
                        log.warn("hvf virtio-net tx notify failed: {s}", .{@errorName(e)});
                    };
                }
            },
            virtio_mmio_reg_interrupt_ack => {
                virtio_net_state.interrupt_status &= ~v32;
                updateVirtioNetInterrupt();
            },
            virtio_mmio_reg_status => {
                if (v32 == 0) {
                    virtio_net_state.status = 0;
                    virtio_net_state.queues = .{ .{}, .{} };
                } else {
                    virtio_net_state.status = v32;
                }
                if (virtio_net_state.status != virtio_net_state.status_last) {
                    log.info("hvf virtio-net status=0x{x}", .{virtio_net_state.status});
                    virtio_net_state.status_last = virtio_net_state.status;
                }
            },
            else => {},
        }
        return 0;
    }

    return switch (offset) {
        virtio_mmio_reg_magic => virtio_mmio_magic,
        virtio_mmio_reg_version => virtio_mmio_version,
        virtio_mmio_reg_device_id => virtio_mmio_device_id_net,
        virtio_mmio_reg_vendor_id => virtio_mmio_vendor_id,
        virtio_mmio_reg_device_features => virtioNetDeviceFeatures(virtio_net_state.device_features_sel),
        virtio_mmio_reg_device_features_sel => virtio_net_state.device_features_sel,
        virtio_mmio_reg_driver_features_sel => virtio_net_state.driver_features_sel,
        virtio_mmio_reg_driver_features => blk: {
            const sel = virtio_net_state.driver_features_sel;
            if (sel < virtio_net_state.driver_features.len) break :blk virtio_net_state.driver_features[sel];
            break :blk 0;
        },
        virtio_mmio_reg_queue_sel => virtio_net_state.queue_sel,
        virtio_mmio_reg_queue_num_max => virtio_net_queue_max,
        virtio_mmio_reg_queue_num => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            virtio_net_state.queues[virtio_net_state.queue_sel].num
        else
            0,
        virtio_mmio_reg_queue_ready => blk: {
            var ready = false;
            if (virtio_net_state.queue_sel < virtio_net_state.queues.len) {
                ready = virtio_net_state.queues[virtio_net_state.queue_sel].ready;
            }
            break :blk @intFromBool(ready);
        },
        virtio_mmio_reg_interrupt_status => virtio_net_state.interrupt_status,
        virtio_mmio_reg_status => virtio_net_state.status,
        virtio_mmio_reg_queue_desc_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].desc_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_desc_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].desc_addr >> 32))
        else
            0,
        virtio_mmio_reg_queue_driver_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].avail_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_driver_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].avail_addr >> 32))
        else
            0,
        virtio_mmio_reg_queue_device_low => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].used_addr & 0xFFFF_FFFF))
        else
            0,
        virtio_mmio_reg_queue_device_high => if (virtio_net_state.queue_sel < virtio_net_state.queues.len)
            @as(u64, @intCast(virtio_net_state.queues[virtio_net_state.queue_sel].used_addr >> 32))
        else
            0,
        virtio_mmio_reg_config_generation => 0,
        else => blk: {
            if (offset >= virtio_mmio_reg_config) {
                const config_offset = offset - virtio_mmio_reg_config;
                if (config_offset < virtio_net_state.mac.len) {
                    const config_start: usize = @intCast(config_offset);
                    const end = @min(config_start + width, virtio_net_state.mac.len);
                    var val: u32 = 0;
                    var shift: u6 = 0;
                    var i: usize = config_start;
                    while (i < end) : (i += 1) {
                        val |= @as(u32, virtio_net_state.mac[i]) << @intCast(shift);
                        shift += 8;
                    }
                    break :blk val;
                }
            }
            break :blk 0;
        },
    };
}

fn handleVirtioFsMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
    if (!virtio_fs_state.enabled) return 0;
    if (!virtio_fs_seen.swap(true, .seq_cst)) {
        log.info("hvf virtio-fs mmio first access offset=0x{x} write={s}", .{ offset, if (is_write) "yes" else "no" });
    }
    const cfg_width: usize = @min(size, 8);
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            virtio_mmio_reg_device_features_sel => virtio_fs_state.device_features_sel = v32,
            virtio_mmio_reg_driver_features_sel => virtio_fs_state.driver_features_sel = v32,
            virtio_mmio_reg_driver_features => {
                const sel = virtio_fs_state.driver_features_sel;
                if (sel < virtio_fs_state.driver_features.len) {
                    virtio_fs_state.driver_features[sel] = v32;
                }
            },
            virtio_mmio_reg_queue_sel => virtio_fs_state.queue_sel = @intCast(v32 & 0xFFFF),
            virtio_mmio_reg_queue_num => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                const requested: u16 = @intCast(v32 & 0xFFFF);
                queue.num = @min(requested, virtio_fs_queue_max);
            },
            virtio_mmio_reg_queue_ready => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.ready = (v32 & 0x1) == 1;
            },
            virtio_mmio_reg_queue_desc_low => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.desc_addr = (queue.desc_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_desc_high => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.desc_addr = (@as(u64, v32) << 32) | (queue.desc_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_driver_low => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.avail_addr = (queue.avail_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_driver_high => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.avail_addr = (@as(u64, v32) << 32) | (queue.avail_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_device_low => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.used_addr = (queue.used_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_device_high => {
                const queue = &virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)];
                queue.used_addr = (@as(u64, v32) << 32) | (queue.used_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_notify => {
                const notify_index: usize = @intCast(v32 & 0xFFFF);
                processVirtioFsQueue(notify_index) catch |e| {
                    log.warn("hvf virtio-fs queue notify failed: {s}", .{@errorName(e)});
                };
            },
            virtio_mmio_reg_interrupt_ack => {
                virtio_fs_state.interrupt_status &= ~v32;
                updateVirtioFsInterrupt();
            },
            virtio_mmio_reg_status => {
                if (v32 == 0) {
                    virtio_fs_state.status = 0;
                    virtio_fs_state.queues = .{ .{}, .{} };
                } else {
                    virtio_fs_state.status = v32;
                }
                if (virtio_fs_state.status != virtio_fs_state.status_last) {
                    log.info("hvf virtio-fs status=0x{x}", .{virtio_fs_state.status});
                    virtio_fs_state.status_last = virtio_fs_state.status;
                }
            },
            else => {},
        }
        return 0;
    }

    return switch (offset) {
        virtio_mmio_reg_magic => virtio_mmio_magic,
        virtio_mmio_reg_version => virtio_mmio_version,
        virtio_mmio_reg_device_id => virtio_mmio_device_id_fs,
        virtio_mmio_reg_vendor_id => virtio_mmio_vendor_id,
        virtio_mmio_reg_device_features => virtioFsDeviceFeatures(virtio_fs_state.device_features_sel),
        virtio_mmio_reg_device_features_sel => virtio_fs_state.device_features_sel,
        virtio_mmio_reg_driver_features_sel => virtio_fs_state.driver_features_sel,
        virtio_mmio_reg_driver_features => blk: {
            const sel = virtio_fs_state.driver_features_sel;
            if (sel < virtio_fs_state.driver_features.len) break :blk virtio_fs_state.driver_features[sel];
            break :blk 0;
        },
        virtio_mmio_reg_queue_sel => virtio_fs_state.queue_sel,
        virtio_mmio_reg_queue_num_max => virtio_fs_queue_max,
        virtio_mmio_reg_queue_num => virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].num,
        virtio_mmio_reg_queue_ready => @intFromBool(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].ready),
        virtio_mmio_reg_interrupt_status => virtio_fs_state.interrupt_status,
        virtio_mmio_reg_status => virtio_fs_state.status,
        virtio_mmio_reg_queue_desc_low => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].desc_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_desc_high => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].desc_addr >> 32),
        virtio_mmio_reg_queue_driver_low => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].avail_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_driver_high => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].avail_addr >> 32),
        virtio_mmio_reg_queue_device_low => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].used_addr & 0xFFFF_FFFF),
        virtio_mmio_reg_queue_device_high => @intCast(virtio_fs_state.queues[@min(@as(usize, virtio_fs_state.queue_sel), virtio_fs_state.queues.len - 1)].used_addr >> 32),
        virtio_mmio_reg_config_generation => 0,
        else => blk: {
            if (offset >= virtio_mmio_reg_config) {
                const config_offset = offset - virtio_mmio_reg_config;
                const cfg_len = virtio_fs_state.tag.len + @sizeOf(u32);
                if (config_offset < cfg_len) {
                    var cfg_buf: [virtio_fs_tag_len + @sizeOf(u32)]u8 = undefined;
                    @memcpy(cfg_buf[0..virtio_fs_state.tag.len], virtio_fs_state.tag[0..]);
                    std.mem.writeInt(u32, cfg_buf[virtio_fs_state.tag.len..][0..4], virtio_fs_state.num_queues, .little);
                    if (config_offset == 0 and !virtio_fs_config_logged.swap(true, .seq_cst)) {
                        log.info("hvf virtio-fs config tag bytes={any}", .{cfg_buf[0..virtio_fs_state.tag.len]});
                    }
                    const config_start: usize = @intCast(config_offset);
                    const end = @min(config_start + cfg_width, cfg_buf.len);
                    var val: u64 = 0;
                    var shift: u6 = 0;
                    var i: usize = config_start;
                    while (i < end) : (i += 1) {
                        val |= @as(u64, cfg_buf[i]) << @intCast(shift);
                        shift += 8;
                    }
                    break :blk val;
                }
            }
            break :blk 0;
        },
    };
}

fn handleVirtioRngMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
    if (!virtio_rng_state.enabled) return 0;
    if (!virtio_rng_seen.swap(true, .seq_cst)) {
        log.info("hvf virtio-rng mmio first access offset=0x{x} write={s}", .{ offset, if (is_write) "yes" else "no" });
    }
    const width: usize = @min(size, 4);
    if (is_write) {
        const v32: u32 = @intCast(value & 0xFFFF_FFFF);
        switch (offset) {
            virtio_mmio_reg_device_features_sel => virtio_rng_state.device_features_sel = v32,
            virtio_mmio_reg_driver_features_sel => virtio_rng_state.driver_features_sel = v32,
            virtio_mmio_reg_driver_features => {
                const sel = virtio_rng_state.driver_features_sel;
                if (sel < virtio_rng_state.driver_features.len) {
                    virtio_rng_state.driver_features[sel] = v32;
                }
            },
            virtio_mmio_reg_queue_sel => virtio_rng_state.queue_sel = @intCast(v32 & 0xFFFF),
            virtio_mmio_reg_queue_num => {
                const requested: u16 = @intCast(v32 & 0xFFFF);
                virtio_rng_state.queue.num = @min(requested, virtio_rng_queue_max);
            },
            virtio_mmio_reg_queue_ready => {
                virtio_rng_state.queue.ready = (v32 & 0x1) == 1;
                log.info("hvf virtio-rng queue ready={s}", .{if (virtio_rng_state.queue.ready) "true" else "false"});
            },
            virtio_mmio_reg_queue_desc_low => {
                virtio_rng_state.queue.desc_addr = (virtio_rng_state.queue.desc_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_desc_high => {
                virtio_rng_state.queue.desc_addr = (@as(u64, v32) << 32) | (virtio_rng_state.queue.desc_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_driver_low => {
                virtio_rng_state.queue.avail_addr = (virtio_rng_state.queue.avail_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_driver_high => {
                virtio_rng_state.queue.avail_addr = (@as(u64, v32) << 32) | (virtio_rng_state.queue.avail_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_device_low => {
                virtio_rng_state.queue.used_addr = (virtio_rng_state.queue.used_addr & 0xFFFF_FFFF_0000_0000) | v32;
            },
            virtio_mmio_reg_queue_device_high => {
                virtio_rng_state.queue.used_addr = (@as(u64, v32) << 32) | (virtio_rng_state.queue.used_addr & 0xFFFF_FFFF);
            },
            virtio_mmio_reg_queue_notify => {
                processVirtioRngQueue() catch |e| {
                    log.warn("hvf virtio-rng queue notify failed: {s}", .{@errorName(e)});
                };
                log.debug("hvf virtio-rng queue notify", .{});
            },
            virtio_mmio_reg_interrupt_ack => {
                virtio_rng_state.interrupt_status &= ~v32;
                updateVirtioRngInterrupt();
            },
            virtio_mmio_reg_status => {
                if (v32 == 0) {
                    virtio_rng_state.status = 0;
                    virtio_rng_state.queue = .{};
                } else {
                    virtio_rng_state.status = v32;
                }
                if (virtio_rng_state.status != virtio_rng_state.status_last) {
                    log.info("hvf virtio-rng status=0x{x}", .{virtio_rng_state.status});
                    virtio_rng_state.status_last = virtio_rng_state.status;
                }
            },
            else => {},
        }
        return 0;
    }

    return switch (offset) {
        virtio_mmio_reg_magic => virtio_mmio_magic,
        virtio_mmio_reg_version => virtio_mmio_version,
        virtio_mmio_reg_device_id => virtio_mmio_device_id_rng,
        virtio_mmio_reg_vendor_id => virtio_mmio_vendor_id,
        virtio_mmio_reg_device_features => virtioRngDeviceFeatures(virtio_rng_state.device_features_sel),
        virtio_mmio_reg_device_features_sel => virtio_rng_state.device_features_sel,
        virtio_mmio_reg_driver_features_sel => virtio_rng_state.driver_features_sel,
        virtio_mmio_reg_driver_features => blk: {
            const sel = virtio_rng_state.driver_features_sel;
            if (sel < virtio_rng_state.driver_features.len) break :blk virtio_rng_state.driver_features[sel];
            break :blk 0;
        },
        virtio_mmio_reg_queue_sel => virtio_rng_state.queue_sel,
        virtio_mmio_reg_queue_num_max => virtio_rng_queue_max,
        virtio_mmio_reg_queue_num => virtio_rng_state.queue.num,
        virtio_mmio_reg_queue_ready => @intFromBool(virtio_rng_state.queue.ready),
        virtio_mmio_reg_interrupt_status => virtio_rng_state.interrupt_status,
        virtio_mmio_reg_status => virtio_rng_state.status,
        virtio_mmio_reg_queue_desc_low => @as(u64, @intCast(virtio_rng_state.queue.desc_addr & 0xFFFF_FFFF)),
        virtio_mmio_reg_queue_desc_high => @as(u64, @intCast(virtio_rng_state.queue.desc_addr >> 32)),
        virtio_mmio_reg_queue_driver_low => @as(u64, @intCast(virtio_rng_state.queue.avail_addr & 0xFFFF_FFFF)),
        virtio_mmio_reg_queue_driver_high => @as(u64, @intCast(virtio_rng_state.queue.avail_addr >> 32)),
        virtio_mmio_reg_queue_device_low => @as(u64, @intCast(virtio_rng_state.queue.used_addr & 0xFFFF_FFFF)),
        virtio_mmio_reg_queue_device_high => @as(u64, @intCast(virtio_rng_state.queue.used_addr >> 32)),
        virtio_mmio_reg_config_generation => 0,
        else => blk: {
            if (offset >= virtio_mmio_reg_config) {
                const config_offset = offset - virtio_mmio_reg_config;
                if (config_offset < 4) {
                    const max_bytes: u32 = 4096;
                    var buf: [4]u8 = undefined;
                    std.mem.writeInt(u32, &buf, max_bytes, .little);
                    const config_start: usize = @intCast(config_offset);
                    const end = @min(config_start + width, buf.len);
                    var val: u32 = 0;
                    var shift: u6 = 0;
                    var i: usize = config_start;
                    while (i < end) : (i += 1) {
                        val |= @as(u32, buf[i]) << @intCast(shift);
                        shift += 8;
                    }
                    break :blk val;
                }
            }
            break :blk 0;
        },
    };
}
fn serialInputLoop() void {
    const fd = std.fs.File.stdin().handle;
    var buf: [256]u8 = undefined;
    while (serial_input_running.load(.seq_cst)) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(fds[0..], 100) catch continue;
        if (ready <= 0) continue;
        if ((fds[0].revents & std.posix.POLL.IN) == 0) continue;
        const n = std.posix.read(fd, buf[0..]) catch continue;
        if (n <= 0) continue;
        const chunk = buf[0..@intCast(n)];
        appendSerialInput(chunk);
    }
}

fn startSerialInputThread() void {
    if (serial_input_running.load(.seq_cst)) return;
    serial_input_running.store(true, .seq_cst);
    serial_input_thread = std.Thread.spawn(.{}, serialInputLoop, .{}) catch |e| {
        serial_input_running.store(false, .seq_cst);
        log.warn("hvf serial stdin thread failed: {s}", .{@errorName(e)});
        return;
    };
    log.info("hvf serial stdin enabled", .{});
}

fn stopSerialInputThread() void {
    if (!serial_input_running.load(.seq_cst)) return;
    serial_input_running.store(false, .seq_cst);
    if (serial_input_thread) |thread| {
        thread.join();
        serial_input_thread = null;
    }
}

fn shouldEnableSerialStdin(allocator: std.mem.Allocator) bool {
    if (envFlagPresent(allocator, "M80_SERIAL_STDIN")) return true;
    return std.posix.isatty(std.fs.File.stdin().handle);
}

fn appendSerialInput(bytes: []const u8) void {
    if (virtio_console_state.enabled) {
        appendVirtioConsoleInput(bytes);
        processVirtioConsoleRxQueue() catch |e| {
            log.warn("hvf virtio-console rx process failed: {s}", .{@errorName(e)});
        };
        return;
    }
    serial_io.append(std.heap.page_allocator, bytes);
}

fn consoleSocketLoop() void {
    const path = console_socket_path orelse return;
    std.fs.cwd().deleteFile(path) catch {};

    const address = std.net.Address.initUnix(path) catch |e| {
        log.warn("hvf console socket invalid path: {s}", .{@errorName(e)});
        return;
    };
    var server = std.net.Address.listen(address, .{
        .kernel_backlog = 4,
        .reuse_address = false,
        .force_nonblocking = true,
    }) catch |e| {
        log.warn("hvf console socket listen failed: {s}", .{@errorName(e)});
        return;
    };
    defer {
        server.deinit();
        std.fs.cwd().deleteFile(path) catch {};
    }

    var buf: [512]u8 = undefined;
    while (console_socket_running.load(.seq_cst)) {
        const conn = server.accept() catch |e| switch (e) {
            error.WouldBlock => {
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            },
            else => {
                log.warn("hvf console socket accept failed: {s}", .{@errorName(e)});
                break;
            },
        };
        defer conn.stream.close();

        if (builtin.os.tag != .windows) {
            const flags = std.posix.fcntl(conn.stream.handle, std.posix.F.GETFL, 0) catch 0;
            var oflags = @as(std.posix.O, @bitCast(@as(u32, @intCast(flags))));
            oflags.NONBLOCK = false;
            _ = std.posix.fcntl(conn.stream.handle, std.posix.F.SETFL, @as(u32, @bitCast(oflags))) catch {};
        }

        serial.setConsoleFd(conn.stream.handle);
        defer serial.clearConsoleFd();
        serial.writeConsoleBacklog(conn.stream.handle) catch |e| {
            log.warn("hvf console backlog send failed: {s}", .{@errorName(e)});
        };

        while (console_socket_running.load(.seq_cst)) {
            var fds = [_]std.posix.pollfd{.{ .fd = conn.stream.handle, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(fds[0..], 100) catch break;
            if (ready == 0) continue;
            if ((fds[0].revents & std.posix.POLL.IN) == 0) break;
            const n = std.posix.read(conn.stream.handle, &buf) catch break;
            if (n <= 0) break;
            const chunk = buf[0..@intCast(n)];
            appendSerialInput(chunk);
        }
    }
}

fn startConsoleSocketServer(allocator: std.mem.Allocator) void {
    if (console_socket_running.load(.seq_cst)) return;
    const env = std.process.getEnvVarOwned(allocator, "M80_CONSOLE_SOCKET") catch null;
    if (env == null) return;
    console_socket_path = env;
    console_socket_running.store(true, .seq_cst);
    console_socket_thread = std.Thread.spawn(.{}, consoleSocketLoop, .{}) catch |e| {
        console_socket_running.store(false, .seq_cst);
        if (console_socket_path) |path| {
            allocator.free(path);
            console_socket_path = null;
        }
        log.warn("hvf console socket thread failed: {s}", .{@errorName(e)});
        return;
    };
    log.info("hvf console socket enabled", .{});
}

fn stopConsoleSocketServer(allocator: std.mem.Allocator) void {
    if (!console_socket_running.load(.seq_cst)) return;
    console_socket_running.store(false, .seq_cst);
    if (console_socket_thread) |thread| {
        thread.join();
        console_socket_thread = null;
    }
    serial.clearConsoleFd();
    if (console_socket_path) |path| {
        allocator.free(path);
        console_socket_path = null;
    }
}

fn advanceArmPc(vcpu: arm64_bindings.VcpuId, il: u64) !void {
    const pc = try arm64_bindings.readReg(vcpu, .PC);
    const step: u64 = if (il == 1) 4 else 2;
    try arm64_bindings.writeReg(vcpu, .PC, pc + step);
}

fn handleArm64Mmio(vcpu: arm64_bindings.VcpuId, exit: HvfArmExitException) !bool {
    const esr = exit.syndrome;
    const ec = (esr >> 26) & 0x3F;
    if (ec != arm64_ec_data_abort_lower and ec != arm64_ec_data_abort_same) return false;

    const iss = esr & 0x1FFFFFF;
    const isv = (iss >> 24) & 0x1;
    if (isv == 0) return false;

    const sas: u2 = @intCast((iss >> 22) & 0x3);
    const size: usize = switch (sas) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    const srt: u5 = @intCast((iss >> 16) & 0x1F);
    const is_write = ((iss >> 6) & 0x1) == 1;
    const il = (esr >> 25) & 0x1;

    const addr = exit.physical_address;
    if (addr >= pl011_base and addr < pl011_base + pl011_size) {
        const offset = addr - pl011_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handlePl011Mmio(offset, true, size, value);
        } else {
            const value = handlePl011Mmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtioBlkIndexForAddr(addr)) |index| {
        if (!virtio_blk_devices[index].enabled) return false;
        const offset = addr - virtioBlkMmioBase(index);
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handleVirtioBlkMmio(index, offset, true, size, value);
        } else {
            const value = handleVirtioBlkMmio(index, offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio_console_state.enabled and addr >= virtio_console_mmio_base and addr < virtio_console_mmio_base + virtio_console_mmio_size) {
        const offset = addr - virtio_console_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handleVirtioConsoleMmio(offset, true, size, value);
        } else {
            const value = handleVirtioConsoleMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio_rng_state.enabled and addr >= virtio_rng_mmio_base and addr < virtio_rng_mmio_base + virtio_rng_mmio_size) {
        const offset = addr - virtio_rng_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handleVirtioRngMmio(offset, true, size, value);
        } else {
            const value = handleVirtioRngMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio_net_state.enabled and addr >= virtio_net_mmio_base and addr < virtio_net_mmio_base + virtio_net_mmio_size) {
        const offset = addr - virtio_net_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handleVirtioNetMmio(offset, true, size, value);
        } else {
            const value = handleVirtioNetMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio_fs_state.enabled and addr >= virtio_fs_mmio_base and addr < virtio_fs_mmio_base + virtio_fs_mmio_size) {
        const offset = addr - virtio_fs_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = handleVirtioFsMmio(offset, true, size, value);
        } else {
            const value = handleVirtioFsMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }

    return false;
}

fn handleArm64SysRegTrap(vcpu: arm64_bindings.VcpuId, exit: HvfArmExitException) !bool {
    const esr = exit.syndrome;
    const ec = (esr >> 26) & 0x3F;
    if (ec != arm64_ec_sysreg) return false;

    const iss = esr & 0x1FFFFFF;
    const op0: u2 = @intCast((iss >> arm64_sysreg_op0_shift) & 0x3);
    const op1: u3 = @intCast((iss >> arm64_sysreg_op1_shift) & 0x7);
    const op2: u3 = @intCast((iss >> arm64_sysreg_op2_shift) & 0x7);
    const crn: u4 = @intCast((iss >> arm64_sysreg_crn_shift) & 0xF);
    const crm: u4 = @intCast((iss >> arm64_sysreg_crm_shift) & 0xF);
    const rt: u5 = @intCast((iss >> arm64_sysreg_rt_shift) & 0x1F);
    const is_read = (iss & arm64_sysreg_dir_mask) == 1;
    const il = (esr >> 25) & 0x1;

    const is_oslar = op0 == 2 and op1 == 0 and crn == 1 and crm == 0 and op2 == 4;
    const is_oslsr = op0 == 2 and op1 == 0 and crn == 1 and crm == 1 and op2 == 4;
    const is_osdlr = op0 == 2 and op1 == 0 and crn == 1 and crm == 3 and op2 == 4;

    if (is_oslar or is_oslsr or is_osdlr) {
        if (is_read) {
            try arm64WriteRegByIndex(vcpu, rt, 0);
        }
        log.warn(
            "hvf arm64 sysreg trap os-lock reg op0={d} op1={d} crn={d} crm={d} op2={d} dir={s} rt={d} (ignored)",
            .{ op0, op1, crn, crm, op2, if (is_read) "read" else "write", rt },
        );
        try advanceArmPc(vcpu, il);
        return true;
    }

    log.err(
        "hvf arm64 sysreg trap op0={d} op1={d} crn={d} crm={d} op2={d} dir={s} rt={d}",
        .{ op0, op1, crn, crm, op2, if (is_read) "read" else "write", rt },
    );
    return false;
}

fn decodeVmxIoExit(qualification: u64, rax: u64) IoExit {
    const size_field: u3 = @intCast(qualification & 0x7);
    const size: usize = switch (size_field) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => 1,
    };
    const is_write = ((qualification >> 3) & 0x1) == 0;
    const is_string = ((qualification >> 4) & 0x1) == 1;
    const has_rep = ((qualification >> 5) & 0x1) == 1;
    const port: u16 = @intCast(qualification & 0xFFFF);
    return .{
        .port = port,
        .is_write = is_write,
        .size = size,
        .rax = rax,
        .is_string = is_string,
        .has_rep = has_rep,
    };
}

fn handleVmxIoExit(vcpu: HvfVcpuId) !void {
    const qualification = try x86_vcpu_bindings.readVmcs(vcpu, vmcs_exit_qualification_field);
    const rax = try hvfReadReg(vcpu, .RAX);
    const exit = decodeVmxIoExit(qualification, rax);
    if (exit.is_string or exit.has_rep) {
        log.warn("hvf x86 string io not supported port=0x{x}", .{exit.port});
        return error.NotSupported;
    }

    if (exit.is_write) {
        _ = handleIoExit(exit);
    } else {
        const value = handleIoExit(exit);
        const mask: u64 = if (exit.size >= 8)
            std.math.maxInt(u64)
        else
            (@as(u64, 1) << @as(u6, @intCast(exit.size * 8))) - 1;
        try hvfWriteReg(vcpu, .RAX, value & mask);
    }

    const rip = try hvfReadReg(vcpu, .RIP);
    const instr_len = try x86_vcpu_bindings.readVmcs(vcpu, vmcs_exit_instr_len_field);
    try hvfWriteReg(vcpu, .RIP, rip + instr_len);
}

const VcpuInit = struct {
    x86_regset: ?HvfRegSet = null,
    arm_regset: ?HvfArmRegSet = null,
};

fn runVcpu(index: u32, init: VcpuInit) void {
    if (builtin.os.tag != .macos) return;
    if (builtin.cpu.arch == .aarch64) {
        runVcpuArm(index, init);
        return;
    }
    if (builtin.cpu.arch == .x86_64) {
        runVcpuX86(index, init);
        return;
    }
}

const runVcpuArm = if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64)
    struct {
        fn run(index: u32, init: VcpuInit) void {
            log.info("hvf arm64 vcpu {d} run loop entered", .{index});
            var exit_ptr: *arm64_bindings.Exit = undefined;
            const vcpu = arm64_bindings.createVcpu(&exit_ptr) catch |e| {
                log.err("hvf arm64 vcpu create failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            active_vcpu_id_arm = vcpu;
            defer {
                arm64_bindings.destroyVcpu(vcpu) catch |e| {
                    log.err("hvf arm64 vcpu destroy failed: {s}", .{@errorName(e)});
                };
                active_vcpu_id_arm = null;
            }

            const regset = init.arm_regset orelse {
                log.err("hvf arm64 missing regset", .{});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            arm64_bindings.setRegs(vcpu, regset.regs) catch |e| {
                log.err("hvf arm64 set regs failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            arm64_bindings.setSregs(vcpu, regset.sregs) catch |e| {
                log.err("hvf arm64 set sregs failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };

            while (vcpu_running.load(.seq_cst)) {
                arm64_bindings.run(vcpu) catch |e| {
                    log.err("hvf arm64 vcpu run failed: {s}", .{@errorName(e)});
                    break;
                };
                const exit = exit_ptr.*;
                switch (exit.reason) {
                    .Canceled => break,
                    .VtimerActivated => {
                        log.debug("hvf arm64 vtimer activated", .{});
                        continue;
                    },
                    .Exception => {
                        const handled_sysreg = handleArm64SysRegTrap(vcpu, exit.exception) catch |e| {
                            log.err("hvf arm64 sysreg handler failed: {s}", .{@errorName(e)});
                            break;
                        };
                        if (handled_sysreg) continue;
                        const handled_mmio = handleArm64Mmio(vcpu, exit.exception) catch |e| {
                            log.err("hvf arm64 mmio handler failed: {s}", .{@errorName(e)});
                            break;
                        };
                        if (handled_mmio) continue;
                        log.err(
                            "hvf arm64 exception syndrome=0x{x} ipa=0x{x} va=0x{x}",
                            .{ exit.exception.syndrome, exit.exception.physical_address, exit.exception.virtual_address },
                        );
                        break;
                    },
                    .Unknown => {
                        log.err("hvf arm64 unknown exit reason", .{});
                        break;
                    },
                }
            }
            vcpu_running.store(false, .seq_cst);
            log.info("hvf arm64 vcpu {d} run loop exited", .{index});
        }
    }.run
else
    struct {
        fn run(index: u32, init: VcpuInit) void {
            _ = index;
            _ = init;
            log.err("hvf arm64 run requested on unsupported target", .{});
        }
    }.run;

const runVcpuX86 = if (builtin.os.tag == .macos and builtin.cpu.arch == .x86_64)
    struct {
        fn run(index: u32, init: VcpuInit) void {
            log.info("hvf x86 vcpu {d} run loop entered", .{index});
            const vcpu = x86_vcpu_bindings.createVcpu() catch |e| {
                log.err("hvf x86 vcpu create failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            active_vcpu_id_x86 = vcpu;
            defer {
                x86_vcpu_bindings.destroyVcpu(vcpu) catch |e| {
                    log.err("hvf x86 vcpu destroy failed: {s}", .{@errorName(e)});
                };
                active_vcpu_id_x86 = null;
            }

            const regset = init.x86_regset orelse {
                log.err("hvf x86 missing regset", .{});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            hvfSetRegs(vcpu, regset.regs) catch |e| {
                log.err("hvf x86 set regs failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };
            hvfSetSregs(vcpu, regset.sregs) catch |e| {
                log.err("hvf x86 set sregs failed: {s}", .{@errorName(e)});
                vcpu_running.store(false, .seq_cst);
                return;
            };

            while (vcpu_running.load(.seq_cst)) {
                if (simulate_io.swap(false, .seq_cst)) {
                    _ = handleIoExit(.{ .port = 0x3F8, .is_write = true, .size = 1, .rax = '>', .is_string = false, .has_rep = false });
                    _ = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
                }
                x86_vcpu_bindings.run(vcpu) catch |e| {
                    log.err("hvf x86 vcpu run failed: {s}", .{@errorName(e)});
                    break;
                };
                const exit_reason_raw = x86_vcpu_bindings.readVmcs(vcpu, vmcs_exit_reason_field) catch |e| {
                    log.err("hvf x86 read exit reason failed: {s}", .{@errorName(e)});
                    break;
                };
                const exit_reason: u32 = @intCast(exit_reason_raw & 0xFFFF);
                if (exit_reason == vmx_exit_reason_io) {
                    handleVmxIoExit(vcpu) catch |e| {
                        log.warn("hvf x86 io handling failed: {s}", .{@errorName(e)});
                        break;
                    };
                    continue;
                }
                log.warn("hvf x86 exit reason=0x{x}", .{exit_reason});
                break;
            }
            vcpu_running.store(false, .seq_cst);
            log.info("hvf x86 vcpu {d} run loop exited", .{index});
        }
    }.run
else
    struct {
        fn run(index: u32, init: VcpuInit) void {
            _ = index;
            _ = init;
            log.err("hvf x86 run requested on unsupported target", .{});
        }
    }.run;

fn prepareGuestImage(memory_size_bytes: u64) !void {
    const guest_kernel_offset = guestKernelOffset();
    if (guest_cmdline_offset >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_kernel_offset >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_initrd_offset >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_cmdline_offset >= guest_kernel_offset) return error.InvalidGuestLayout;
    if (guest_kernel_offset >= guest_initrd_offset) return error.InvalidGuestLayout;

    log.info(
        "hvf guest layout kernel=0x{x} initrd=0x{x} cmdline=0x{x}",
        .{ guestKernelBase(), guestInitrdBase(), guestCmdlineBase() },
    );
}

fn copyFileToGuest(
    memory_size_bytes: u64,
    guest_base: u64,
    path: []const u8,
    label: []const u8,
) !u64 {
    const base = guestMemoryBase();
    if (guest_base < base) return error.GuestImageTooLarge;
    const offset_base = guest_base - base;
    if (offset_base >= memory_size_bytes) return error.GuestImageTooLarge;

    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.size > std.math.maxInt(usize)) return error.GuestImageTooLarge;
    if (stat.size > memory_size_bytes - offset_base) return error.GuestImageTooLarge;

    var buf: [4096]u8 = undefined;
    var reader = file.reader(&buf);
    const r = &reader.interface;
    var remaining: usize = @intCast(stat.size);
    var offset: usize = 0;
    while (remaining > 0) {
        const chunk = @min(remaining, 64 * 1024);
        const n = try r.readSliceShort(buf[0..@min(buf.len, chunk)]);
        if (n == 0) return error.UnexpectedEof;
        const guest_addr = guest_base + @as(u64, @intCast(offset));
        try writeGuestBytes(guest_addr, buf[0..n]);
        remaining -= n;
        offset += n;
    }

    log.info("hvf loaded {s} ({d} bytes) at 0x{x}", .{ label, stat.size, guest_base });
    return stat.size;
}

fn copyGzipToGuest(
    memory_size_bytes: u64,
    guest_base: u64,
    file: std.fs.File,
    label: []const u8,
) !u64 {
    const base = guestMemoryBase();
    if (guest_base < base) return error.GuestImageTooLarge;
    const offset_base = guest_base - base;
    if (offset_base >= memory_size_bytes) return error.GuestImageTooLarge;

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(&read_buf);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor = std.compress.flate.Decompress.init(&reader.interface, .gzip, window[0..]);

    var out_buf: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = try decompressor.reader.readSliceShort(&out_buf);
        if (n == 0) break;
        if (total + n > memory_size_bytes - offset_base) return error.GuestImageTooLarge;
        try writeGuestBytes(guest_base + total, out_buf[0..n]);
        total += @as(u64, n);
    }

    log.info("hvf loaded {s} ({d} bytes) at 0x{x}", .{ label, total, guest_base });
    return total;
}

fn writeCmdlineToGuest(memory_size_bytes: u64, state: boot.BootState, cmdline: []const u8) !void {
    const base = guestMemoryBase();
    if (state.cmdline_addr < base) return error.GuestImageTooLarge;
    const end = (state.cmdline_addr - base) + @as(u64, state.cmdline_len) + 1;
    if (end > memory_size_bytes) return error.GuestImageTooLarge;
    try writeGuestBytes(state.cmdline_addr, cmdline);
    try writeGuestBytes(state.cmdline_addr + cmdline.len, &[_]u8{0});
}

fn setActiveGuestMemory(buffer: []u8) void {
    active_guest_memory = buffer;
}

fn clearActiveGuestMemory() void {
    active_guest_memory = null;
}

fn mapActiveGuestMemory() !void {
    if (builtin.os.tag != .macos) return;
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const page_size = std.heap.page_size_min;
    if (memory.len % page_size != 0) return error.InvalidGuestLayout;
    if (@intFromPtr(memory.ptr) % page_size != 0) return error.InvalidGuestLayout;
    if (builtin.cpu.arch == .aarch64) {
        try arm64_vm_bindings.map(memory, guestMemoryBase(), hvf_memory_read | hvf_memory_write | hvf_memory_exec);
        return;
    }
    if (builtin.cpu.arch == .x86_64) {
        try x86_vm_bindings.map(memory, 0, hvf_memory_read | hvf_memory_write | hvf_memory_exec);
        return;
    }
}

fn unmapActiveGuestMemory() void {
    if (builtin.os.tag != .macos) return;
    const memory = active_guest_memory orelse return;
    if (builtin.cpu.arch == .aarch64) {
        arm64_vm_bindings.unmap(guestMemoryBase(), memory.len) catch |e| {
            log.err("failed to unmap guest memory: {s}", .{@errorName(e)});
        };
        return;
    }
    if (builtin.cpu.arch == .x86_64) {
        x86_vm_bindings.unmap(0, memory.len) catch |e| {
            log.err("failed to unmap guest memory: {s}", .{@errorName(e)});
        };
        return;
    }
}

fn writeGuestBytes(guest_addr: u64, data: []const u8) !void {
    // Caller must ensure guest memory has been mapped and registered via
    // setActiveGuestMemory (or future HVF memory mapping hooks).
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    if (guest_addr < base) return error.InvalidGuestLayout;
    const offset = guest_addr - base;
    const end_addr = offset + data.len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    const start_offset: usize = @intCast(offset);
    const end_offset: usize = @intCast(end_addr);
    std.mem.copyForwards(u8, memory[start_offset..end_offset], data);
}

fn readGuestBytes(guest_addr: u64, out: []u8) !void {
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    if (guest_addr < base) return error.InvalidGuestLayout;
    const offset = guest_addr - base;
    const end_addr = offset + out.len;
    if (end_addr > memory.len) return error.InvalidGuestLayout;
    const start_offset: usize = @intCast(offset);
    const end_offset: usize = @intCast(end_addr);
    std.mem.copyForwards(u8, out, memory[start_offset..end_offset]);
}

fn readGuestU16(guest_addr: u64) !u16 {
    var buf: [2]u8 = undefined;
    try readGuestBytes(guest_addr, &buf);
    return std.mem.readInt(u16, &buf, .little);
}

fn readGuestU32(guest_addr: u64) !u32 {
    var buf: [4]u8 = undefined;
    try readGuestBytes(guest_addr, &buf);
    return std.mem.readInt(u32, &buf, .little);
}

fn readGuestU64(guest_addr: u64) !u64 {
    var buf: [8]u8 = undefined;
    try readGuestBytes(guest_addr, &buf);
    return std.mem.readInt(u64, &buf, .little);
}

fn writeGuestU16(guest_addr: u64, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try writeGuestBytes(guest_addr, &buf);
}

fn writeGuestU32(guest_addr: u64, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try writeGuestBytes(guest_addr, &buf);
}

fn writeGuestU64(guest_addr: u64, value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try writeGuestBytes(guest_addr, &buf);
}

fn writeGuestByte(guest_addr: u64, value: u8) !void {
    var buf: [1]u8 = .{value};
    try writeGuestBytes(guest_addr, &buf);
}

const KernelLoadResult = struct {
    entry: ?u64 = null,
};

fn isArm64Image(header: []const u8) bool {
    if (header.len < 0x3c) return false;
    const magic = std.mem.readInt(u32, header[0x38..0x3c], .little);
    return magic == arm64_image_magic;
}

fn isGzipImage(header: []const u8) bool {
    return header.len >= 2 and header[0] == 0x1f and header[1] == 0x8b;
}

fn copyFileRangeToGuest(
    file: std.fs.File,
    file_offset: u64,
    guest_addr: u64,
    size: u64,
    label: []const u8,
) !void {
    var buf: [4096]u8 = undefined;
    var remaining = size;
    var offset: u64 = 0;
    while (remaining > 0) {
        const chunk: usize = @intCast(@min(remaining, buf.len));
        const n = try file.preadAll(buf[0..chunk], file_offset + offset);
        if (n == 0) return error.UnexpectedEof;
        try writeGuestBytes(guest_addr + offset, buf[0..n]);
        remaining -= @as(u64, n);
        offset += @as(u64, n);
    }
    log.info("hvf loaded {s} ({d} bytes) at 0x{x}", .{ label, size, guest_addr });
}

fn loadGuestKernel(memory_size_bytes: u64, kernel_path: ?[]const u8) !KernelLoadResult {
    if (kernel_path == null) {
        log.warn("hvf kernel path not set; skipping kernel load", .{});
        return .{};
    }

    var file = try std.fs.cwd().openFile(kernel_path.?, .{});
    defer file.close();

    var header: [256]u8 = undefined;
    const header_len = try file.preadAll(&header, 0);
    const header_slice = header[0..header_len];

    if (isArm64Image(header_slice)) {
        _ = try copyFileToGuest(memory_size_bytes, guestKernelBase(), kernel_path.?, "kernel");
        if (header_len >= 0x10) {
            const text_offset = std.mem.readInt(u64, header[0x08..0x10], .little);
            if (text_offset != 0) {
                log.info("hvf kernel text_offset=0x{x}", .{text_offset});
            }
        }
        return .{};
    }

    if (isGzipImage(header_slice)) {
        log.info("hvf kernel detected gzip image; inflating", .{});
        _ = try copyGzipToGuest(memory_size_bytes, guestKernelBase(), file, "kernel");
        return .{};
    }

    log.warn("hvf kernel header missing arm64 magic; treating as raw image", .{});
    _ = try copyFileToGuest(memory_size_bytes, guestKernelBase(), kernel_path.?, "kernel");
    return .{};
}

fn loadGuestInitrd(memory_size_bytes: u64, initrd_path: ?[]const u8) !u64 {
    if (initrd_path == null) {
        log.warn("hvf initrd path not set; skipping initrd load", .{});
        return 0;
    }
    return try copyFileToGuest(memory_size_bytes, guestInitrdBase(), initrd_path.?, "initrd");
}

/// Starts a VM with the HVF backend.
///
/// This function performs the following steps:
/// 1. Validates no VM is already running
/// 2. Creates and configures the VM partition
/// 3. Prepares guest memory layout and loads kernel/initrd
/// 4. Sets up initial CPU register state for Linux boot
/// 5. Spawns the vCPU thread to begin execution
///
/// Parameters:
///   - cfg: VM configuration (memory, CPU cores, kernel/initrd paths)
///
/// Errors:
///   - error.AlreadyRunning: A VM is already active
///   - error.NotSupported: HVF APIs not available on this platform
///   - error.InvalidGuestLayout: Memory too small for guest layout
///   - error.MemoryTooLarge: Memory size exceeds platform limits
pub fn start(cfg: config.VmConfig) !void {
    log.info("hvf backend starting", .{});

    // Ensure no VM is already running (single VM at a time)
    if (vcpu_running.load(.seq_cst) or active_vm != null or active_vcpu_thread != null) return error.AlreadyRunning;

    const handle = Hvf.createVm() catch |e| {
        log.err("hvf createVm failed: {s}", .{@errorName(e)});
        return e;
    };
    errdefer Hvf.deleteVm(handle) catch {};

    Hvf.setupVm(handle, .{
        .cpu_cores = cfg.cpu_cores,
        .memory_mb = cfg.memory_mb,
    }) catch |e| {
        log.err("hvf setupVm failed: {s}", .{@errorName(e)});
        return e;
    };
    active_vm = handle;

    const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
    if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;

    // Allocate guest memory backing for HVF mappings.
    const guest_memory = try std.heap.page_allocator.alloc(u8, @intCast(size_bytes_u64));
    errdefer std.heap.page_allocator.free(guest_memory);
    @memset(guest_memory, 0);
    setActiveGuestMemory(guest_memory);
    errdefer clearActiveGuestMemory();
    mapActiveGuestMemory() catch |e| {
        log.err("hvf map guest memory failed: {s}", .{@errorName(e)});
        return e;
    };
    errdefer unmapActiveGuestMemory();

    prepareGuestImage(size_bytes_u64) catch |e| {
        log.err("hvf prepareGuestImage failed: {s}", .{@errorName(e)});
        return e;
    };
    const kernel_load = loadGuestKernel(size_bytes_u64, cfg.kernel_path) catch |e| {
        log.err("hvf loadGuestKernel failed: {s}", .{@errorName(e)});
        return e;
    };
    const initrd_size = loadGuestInitrd(size_bytes_u64, cfg.initrd_path) catch |e| {
        log.err("hvf loadGuestInitrd failed: {s}", .{@errorName(e)});
        return e;
    };
    setupVirtioBlk(cfg) catch |e| {
        log.err("hvf virtio-blk setup failed: {s}", .{@errorName(e)});
        return e;
    };
    const enable_virtio_console = envFlagPresent(std.heap.page_allocator, "M80_VIRTIO_CONSOLE") or
        (cfg.kernel_cmdline != null and std.mem.indexOf(u8, cfg.kernel_cmdline.?, "hvc0") != null);
    setupVirtioConsole(enable_virtio_console);
    setupVirtioRng(true);
    setupVirtioFs(std.heap.page_allocator, cfg) catch |e| {
        log.err("hvf virtio-fs setup failed: {s}", .{@errorName(e)});
        return e;
    };
    if (cfg.network_mode != .locked_down) {
        try initNetworkPolicy(cfg);
        errdefer stopVmnetInterface();
        try startVmnetInterface();
    }
    const cmdline = if (cfg.kernel_cmdline) |value| value else defaultCmdlineForConfig(cfg);
    var boot_state = if (builtin.cpu.arch == .aarch64)
        boot.computeBootStateWithBase(
            guestMemoryBase(),
            size_bytes_u64,
            guestKernelOffset(),
            guest_cmdline_offset,
            cmdline,
        ) catch |e| {
            log.err("hvf computeBootState failed: {s}", .{@errorName(e)});
            return e;
        }
    else
        boot.computeBootState(
            size_bytes_u64,
            guestKernelBase(),
            guestCmdlineBase(),
            cmdline,
        ) catch |e| {
            log.err("hvf computeBootState failed: {s}", .{@errorName(e)});
            return e;
        };
    if (kernel_load.entry) |entry| {
        boot_state.entry = entry;
        log.info("hvf kernel entry override=0x{x}", .{entry});
    }
    writeCmdlineToGuest(size_bytes_u64, boot_state, cmdline) catch |e| {
        log.err("hvf writeCmdlineToGuest failed: {s}", .{@errorName(e)});
        return e;
    };
    log.info(
        "hvf boot state entry=0x{x} stack=0x{x} cmdline=0x{x} len={d}",
        .{
            boot_state.entry,
            boot_state.stack_top,
            boot_state.cmdline_addr,
            boot_state.cmdline_len,
        },
    );

    var vcpu_init = VcpuInit{};
    if (builtin.cpu.arch == .aarch64) {
        const gic_layout_local = computeGicLayout();
        gic_layout = gic_layout_local;
        var spi_base: u32 = 32;
        var spi_count: u32 = 0;
        gic_bindings.getSpiRange(&spi_base, &spi_count) catch |e| {
            log.warn("hvf gic spi range unavailable; using default base=32: {s}", .{@errorName(e)});
        };
        const uart_intid = spi_base + pl011_irq_offset;
        var virtio_blk0_intid: ?u32 = null;
        var virtio_blk1_intid: ?u32 = null;
        var virtio_blk2_intid: ?u32 = null;
        if (cfg.disk_path != null) {
            const candidate = spi_base;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-blk0 irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_blk0_intid = candidate;
        }
        if (cfg.seed_path != null) {
            const candidate = spi_base + pl011_irq_offset + 2;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-blk1 irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_blk1_intid = candidate;
        }
        if (cfg.data_disk_path != null) {
            const candidate = spi_base + pl011_irq_offset + 6;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-blk2 irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_blk2_intid = candidate;
        }
        gic_virtio_blk_intid = .{ virtio_blk0_intid, virtio_blk1_intid, virtio_blk2_intid };
        var virtio_console_intid: ?u32 = null;
        var virtio_rng_intid: ?u32 = null;
        var virtio_net_intid: ?u32 = null;
        var virtio_fs_intid: ?u32 = null;
        if (enable_virtio_console) {
            const candidate = spi_base + pl011_irq_offset + 1;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-console irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_console_intid = candidate;
            gic_virtio_console_intid = candidate;
        }
        if (virtio_rng_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 3;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-rng irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_rng_intid = candidate;
            gic_virtio_rng_intid = candidate;
        }
        if (virtio_net_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 4;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-net irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_net_intid = candidate;
            gic_virtio_net_intid = candidate;
        }
        if (virtio_fs_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 5;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-fs irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_fs_intid = candidate;
            gic_virtio_fs_intid = candidate;
        }
        const uart_irq = uart_intid - spi_base;
        const virtio_blk0_irq = if (virtio_blk0_intid) |intid| intid - spi_base else null;
        const virtio_blk1_irq = if (virtio_blk1_intid) |intid| intid - spi_base else null;
        const virtio_blk2_irq = if (virtio_blk2_intid) |intid| intid - spi_base else null;
        const virtio_console_irq = if (virtio_console_intid) |intid| intid - spi_base else null;
        const virtio_rng_irq = if (virtio_rng_intid) |intid| intid - spi_base else null;
        const virtio_net_irq = if (virtio_net_intid) |intid| intid - spi_base else null;
        const virtio_fs_irq = if (virtio_fs_intid) |intid| intid - spi_base else null;
        const initrd_start = if (initrd_size > 0) guestInitrdBase() else null;
        const initrd_end = if (initrd_size > 0) guestInitrdBase() + initrd_size else null;
        if (cfg.disk_path != null and virtio_blk0_irq != null) {
            log.info(
                "hvf virtio-blk[0] dtb base=0x{x} irq={d} intid={d}",
                .{ virtioBlkMmioBase(0), virtio_blk0_irq.?, virtio_blk0_intid.? },
            );
        }
        if (cfg.seed_path != null and virtio_blk1_irq != null) {
            log.info(
                "hvf virtio-blk[1] dtb base=0x{x} irq={d} intid={d}",
                .{ virtioBlkMmioBase(1), virtio_blk1_irq.?, virtio_blk1_intid.? },
            );
        }
        if (cfg.data_disk_path != null and virtio_blk2_irq != null) {
            log.info(
                "hvf virtio-blk[2] dtb base=0x{x} irq={d} intid={d}",
                .{ virtioBlkMmioBase(2), virtio_blk2_irq.?, virtio_blk2_intid.? },
            );
        }
        if (enable_virtio_console and virtio_console_irq != null) {
            log.info(
                "hvf virtio-console dtb base=0x{x} irq={d} intid={d}",
                .{ virtio_console_mmio_base, virtio_console_irq.?, virtio_console_intid.? },
            );
        }
        if (virtio_rng_state.enabled and virtio_rng_irq != null) {
            log.info(
                "hvf virtio-rng dtb base=0x{x} irq={d} intid={d}",
                .{ virtio_rng_mmio_base, virtio_rng_irq.?, virtio_rng_intid.? },
            );
        }
        if (virtio_net_state.enabled and virtio_net_irq != null) {
            log.info(
                "hvf virtio-net dtb base=0x{x} irq={d} intid={d}",
                .{ virtio_net_mmio_base, virtio_net_irq.?, virtio_net_intid.? },
            );
        }
        if (virtio_fs_state.enabled and virtio_fs_irq != null) {
            log.info(
                "hvf virtio-fs dtb base=0x{x} irq={d} intid={d}",
                .{ virtio_fs_mmio_base, virtio_fs_irq.?, virtio_fs_intid.? },
            );
        }
        const dtb_blob = dtb.buildVirtDtb(std.heap.page_allocator, .{
            .memory_base = guestMemoryBase(),
            .memory_size = size_bytes_u64,
            .cmdline = cmdline,
            .gic_dist_base = gic_layout_local.dist_base,
            .gic_redist_base = gic_layout_local.redist_base,
            .uart_irq = uart_irq,
            .initrd_start = initrd_start,
            .initrd_end = initrd_end,
            .virtio_blk_base = if (cfg.disk_path != null) virtioBlkMmioBase(0) else null,
            .virtio_blk_irq = virtio_blk0_irq,
            .virtio_blk2_base = if (cfg.seed_path != null) virtioBlkMmioBase(1) else null,
            .virtio_blk2_irq = virtio_blk1_irq,
            .virtio_blk3_base = if (cfg.data_disk_path != null) virtioBlkMmioBase(2) else null,
            .virtio_blk3_irq = virtio_blk2_irq,
            .virtio_console_base = if (enable_virtio_console) virtio_console_mmio_base else null,
            .virtio_console_irq = virtio_console_irq,
            .virtio_rng_base = if (virtio_rng_state.enabled) virtio_rng_mmio_base else null,
            .virtio_rng_irq = virtio_rng_irq,
            .virtio_net_base = if (virtio_net_state.enabled) virtio_net_mmio_base else null,
            .virtio_net_irq = virtio_net_irq,
            .virtio_fs_base = if (virtio_fs_state.enabled) virtio_fs_mmio_base else null,
            .virtio_fs_irq = virtio_fs_irq,
        }) catch |e| {
            log.err("hvf buildVirtDtb failed: {s}", .{@errorName(e)});
            return e;
        };
        defer std.heap.page_allocator.free(dtb_blob);
        if (cfg.disk_path != null) {
            if (std.mem.indexOf(u8, dtb_blob, "virtio,mmio") != null) {
                log.info("hvf dtb includes virtio-mmio node", .{});
            } else {
                log.warn("hvf dtb missing virtio-mmio node", .{});
            }
        }

        const layout = computeArmBootLayout(guestMemoryBase(), size_bytes_u64, boot_state, dtb_blob.len) catch |e| {
            log.err("hvf computeArmBootLayout failed: {s}", .{@errorName(e)});
            return e;
        };
        const page_tables = buildArmIdentityMap(std.heap.page_allocator, layout.page_table_addr, guestMemoryBase()) catch |e| {
            log.err("hvf buildArmIdentityMap failed: {s}", .{@errorName(e)});
            return e;
        };
        defer std.heap.page_allocator.free(page_tables);

        log.info("hvf arm64 dtb addr=0x{x} size={d} bytes", .{ layout.dtb_addr, dtb_blob.len });
        log.info("hvf arm64 page tables addr=0x{x} size={d} bytes", .{ layout.page_table_addr, page_tables.len });

        writeGuestBytes(layout.dtb_addr, dtb_blob) catch |e| {
            log.err("hvf writeGuestBytes dtb failed: {s}", .{@errorName(e)});
            return e;
        };
        writeGuestBytes(layout.page_table_addr, page_tables) catch |e| {
            log.err("hvf writeGuestBytes page tables failed: {s}", .{@errorName(e)});
            return e;
        };

        const hvf_regset = buildHvfArmRegSet(boot_state, layout);
        log.debug("hvf arm64 regs pc=0x{x} sp=0x{x} cpsr=0x{x} x0=0x{x}", .{
            hvf_regset.regs.pc,
            hvf_regset.sregs.sp_el1,
            hvf_regset.regs.cpsr,
            hvf_regset.regs.x0,
        });
        vcpu_init.arm_regset = hvf_regset;
    } else {
        const boot_regs = boot.buildBootRegs(boot_state);
        const hvf_regset = buildHvfRegSet(boot_regs);
        log.debug("hvf boot regs rip=0x{x} rsp=0x{x} rflags=0x{x} rsi=0x{x}", .{
            hvf_regset.regs.rip,
            hvf_regset.regs.rsp,
            hvf_regset.regs.rflags,
            hvf_regset.regs.rsi,
        });
        vcpu_init.x86_regset = hvf_regset;
    }
    active_memory_size = @intCast(size_bytes_u64);

    if (cfg.kernel_path == null) {
        log.warn("hvf kernel path not set; skipping vcpu run (set kernel_path in m80.conf)", .{});
        log.info("hvf backend ready (no vcpu running)", .{});
        return;
    }

    vcpu_running.store(true, .seq_cst);
    if (builtin.cpu.arch == .aarch64) {
        setupGic();
    }
    if (envFlagPresent(std.heap.page_allocator, "M80_IO_SIM")) {
        simulate_io.store(true, .seq_cst);
    }
    serial_io.setFromEnv(std.heap.page_allocator);
    if (virtio_console_state.enabled) {
        setVirtioConsoleInputFromEnv(std.heap.page_allocator);
    }
    serial.setCaptureFromEnv(std.heap.page_allocator);
    serial.clearConsoleBacklog();
    startConsoleSocketServer(std.heap.page_allocator);
    if (shouldEnableSerialStdin(std.heap.page_allocator)) {
        startSerialInputThread();
    }
    if (builtin.cpu.arch == .aarch64) {
        resetPl011State();
    }
    active_vcpu_thread = try std.Thread.spawn(.{}, runVcpu, .{ 0, vcpu_init });
    log.info("hvf backend ready", .{});
}

/// Stops the running VM and cleans up resources.
///
/// This function:
/// 1. Signals the vCPU thread to stop (via vcpu_running flag)
/// 2. Waits for the vCPU thread to exit
/// 3. Cleans up serial I/O state
/// 4. Destroys the VM partition
pub fn stop() !void {
    log.info("hvf backend stopping", .{});

    // Signal vCPU thread to stop
    vcpu_running.store(false, .seq_cst);
    stopSerialInputThread();
    stopConsoleSocketServer(std.heap.page_allocator);

    if (builtin.os.tag == .macos) {
        if (builtin.cpu.arch == .aarch64) {
            if (active_vcpu_id_arm) |vcpu| {
                arm64_bindings.exit(vcpu) catch |e| {
                    log.warn("failed to exit arm64 vcpu: {s}", .{@errorName(e)});
                };
            }
        } else if (builtin.cpu.arch == .x86_64) {
            if (active_vcpu_id_x86) |vcpu| {
                x86_vcpu_bindings.interrupt(vcpu) catch |e| {
                    log.warn("failed to interrupt x86 vcpu: {s}", .{@errorName(e)});
                };
            }
        }
    }

    // Wait for vCPU thread to exit
    if (active_vcpu_thread) |t| {
        t.join();
        active_vcpu_thread = null;
    }

    // Clean up serial I/O state
    serial_io.clear(std.heap.page_allocator);
    serial.clearCapture(std.heap.page_allocator);
    serial.clearConsoleBacklog();
    pl011_state = .{};
    resetVirtioBlkState();
    resetVirtioConsoleState();
    resetVirtioRngState();
    resetVirtioNetState();
    resetVirtioFsState();
    stopVmnetInterface();

    if (active_guest_memory) |buffer| {
        unmapActiveGuestMemory();
        std.heap.page_allocator.free(buffer);
        active_guest_memory = null;
    }

    // Destroy the VM partition
    if (active_vm) |handle| {
        Hvf.deleteVm(handle) catch |e| {
            log.err("failed to delete hvf vm: {s}", .{@errorName(e)});
            return e;
        };
        active_vm = null;
    }
    active_memory_size = 0;
    clearActiveGuestMemory();
    gic_enabled = false;
    gic_uart_intid = null;
    gic_virtio_blk_intid = .{ null, null, null };
    gic_virtio_console_intid = null;
    gic_virtio_net_intid = null;
    gic_virtio_fs_intid = null;
    gic_layout = null;
}

// =============================================================================
// TESTS
// =============================================================================
// Tests use the "hvf:" prefix to identify which module they belong to.

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

fn allocZ(allocator: std.mem.Allocator, value: []const u8) ![:0]u8 {
    var buf = try allocator.alloc(u8, value.len + 1);
    @memcpy(buf[0..value.len], value);
    buf[value.len] = 0;
    return buf[0..value.len :0];
}

test "smoke: hvf backend start/stop" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    start(cfg_mut) catch |e| switch (e) {
        error.NotImplemented => return error.SkipZigTest,
        error.HvfFailure => return,
        else => return e,
    };
    try stop();
}

test "hvf: handleIoExit reads serial data" {
    serial_io.clear(std.testing.allocator);
    serial_io.append(std.testing.allocator, "Z");
    defer serial_io.clear(std.testing.allocator);

    const b = handleIoExit(.{ .port = 0x3F8, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    try std.testing.expectEqual(@as(u8, 'Z'), @as(u8, @intCast(b)));

    const lsr = handleIoExit(.{ .port = 0x3FD, .is_write = false, .size = 1, .rax = 0, .is_string = false, .has_rep = false });
    try std.testing.expect((lsr & 0x01) == 0);
}

test "hvf: io exit mapping" {
    var raw = HvfVcpuExit{
        .reason = .Io,
        .data = .{ .io = .{
            .port = 0x3F8,
            .access_size = 1,
            .access_type = 1,
            .is_string = false,
            .has_rep = true,
            .rax = 'A',
        } },
    };
    const mapped = try decodeHvfIoExit(&raw);
    try std.testing.expectEqual(@as(u16, 0x3F8), mapped.port);
    try std.testing.expect(mapped.is_write);
    try std.testing.expectEqual(@as(usize, 1), mapped.size);
    try std.testing.expectEqual(@as(u64, 'A'), mapped.rax);
    try std.testing.expect(mapped.has_rep);
}

test "hvf: io exit mapping defaults unknown size to 1" {
    var raw = HvfVcpuExit{
        .reason = .Io,
        .data = .{ .io = .{
            .port = 0x3F8,
            .access_size = 3,
            .access_type = 0,
            .is_string = false,
            .has_rep = false,
            .rax = 0,
        } },
    };
    const mapped = try decodeHvfIoExit(&raw);
    try std.testing.expectEqual(@as(usize, 1), mapped.size);
    try std.testing.expect(!mapped.is_write);
}

test "hvf: io exit rejects non-io reason" {
    var raw = HvfVcpuExit{
        .reason = .Unknown,
        .data = .{ .io = .{
            .port = 0,
            .access_size = 1,
            .access_type = 0,
            .is_string = false,
            .has_rep = false,
            .rax = 0,
        } },
    };
    try std.testing.expectError(error.NotIoExit, decodeHvfIoExit(&raw));
}

test "hvf: buildHvfRegs mirrors boot regs" {
    const state = try boot.computeBootStateWithBase(guestMemoryBase(), 32 * 1024 * 1024, guestKernelOffset(), guest_cmdline_offset, "root=/dev/vda");
    const regs = boot.buildBootRegs(state);
    const hvf_regs = buildHvfRegs(regs);
    try std.testing.expectEqual(regs.rip, hvf_regs.rip);
    try std.testing.expectEqual(regs.rsp, hvf_regs.rsp);
    try std.testing.expectEqual(regs.rflags, hvf_regs.rflags);
    try std.testing.expectEqual(regs.rsi, hvf_regs.rsi);
}

test "hvf: buildHvfArmRegSet mirrors boot state" {
    const state = try boot.computeBootStateWithBase(guestMemoryBase(), 32 * 1024 * 1024, guestKernelOffset(), guest_cmdline_offset, "root=/dev/vda");
    const layout = try computeArmBootLayout(guestMemoryBase(), 32 * 1024 * 1024, state, 256);
    const regset = buildHvfArmRegSet(state, layout);
    try std.testing.expectEqual(state.entry, regset.regs.pc);
    try std.testing.expectEqual(state.stack_top, regset.sregs.sp_el1);
    try std.testing.expectEqual(layout.dtb_addr, regset.regs.x0);
    try std.testing.expectEqual(arm64_default_pstate_el1h, regset.regs.cpsr);
}

test "hvf: setRegs not supported off macos/x86_64" {
    if (builtin.os.tag == .macos and builtin.cpu.arch == .x86_64) return error.SkipZigTest;
    const state = try boot.computeBootStateWithBase(guestMemoryBase(), 32 * 1024 * 1024, guestKernelOffset(), guest_cmdline_offset, "root=/dev/vda");
    const regs = boot.buildBootRegs(state);
    const hvf_regset = buildHvfRegSet(regs);
    try std.testing.expectError(error.NotSupported, Hvf.setRegs(0, hvf_regset.regs));
    try std.testing.expectError(error.NotSupported, Hvf.setSregs(0, hvf_regset.sregs));
}

test "hvf: setArmRegs not supported off macos/aarch64" {
    if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64) return error.SkipZigTest;
    const state = try boot.computeBootStateWithBase(guestMemoryBase(), 32 * 1024 * 1024, guestKernelOffset(), guest_cmdline_offset, "root=/dev/vda");
    const layout = try computeArmBootLayout(guestMemoryBase(), 32 * 1024 * 1024, state, 128);
    const hvf_regset = buildHvfArmRegSet(state, layout);
    try std.testing.expectError(error.NotSupported, Hvf.setArmRegs(0, hvf_regset.regs));
    try std.testing.expectError(error.NotSupported, Hvf.setArmSregs(0, hvf_regset.sregs));
}

test "hvf: computeArmBootLayout places dtb and tables after cmdline" {
    const state = try boot.computeBootStateWithBase(guestMemoryBase(), 64 * 1024 * 1024, guestKernelOffset(), guest_cmdline_offset, "console=ttyS0");
    const layout = try computeArmBootLayout(guestMemoryBase(), 64 * 1024 * 1024, state, 512);
    try std.testing.expect(layout.dtb_addr >= state.cmdline_addr + state.cmdline_len + 1);
    try std.testing.expect(layout.page_table_addr > layout.dtb_addr);
}

test "hvf: buildArmIdentityMap returns two pages" {
    const allocator = std.testing.allocator;
    const table = try buildArmIdentityMap(allocator, 0x30000, guestMemoryBase());
    defer allocator.free(table);
    try std.testing.expectEqual(@as(usize, arm64_page_table_bytes), table.len);
}

test "hvf: writeGuestBytes copies data" {
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    setActiveGuestMemory(buf[0..]);
    defer clearActiveGuestMemory();

    const payload = "dtb";
    const addr = guestMemoryBase() + 16;
    try writeGuestBytes(addr, payload);
    try std.testing.expectEqualStrings(payload, buf[16 .. 16 + payload.len]);
}

test "hvf: virtio-console rx writes guest buffers" {
    var guest_memory: [0x8000]u8 = undefined;
    @memset(&guest_memory, 0);
    setActiveGuestMemory(guest_memory[0..]);
    defer clearActiveGuestMemory();

    resetVirtioConsoleState();
    defer resetVirtioConsoleState();
    virtio_console_state.enabled = true;

    const base = guestMemoryBase();
    const desc_addr = base + 0x1000;
    const avail_addr = base + 0x2000;
    const used_addr = base + 0x3000;
    const data_addr = base + 0x4000;

    virtio_console_state.queues[0] = .{
        .num = 8,
        .ready = true,
        .desc_addr = desc_addr,
        .avail_addr = avail_addr,
        .used_addr = used_addr,
        .last_avail_idx = 0,
        .used_idx = 0,
    };

    const desc = VirtqDesc{
        .addr = data_addr,
        .len = 4,
        .flags = virtq_desc_flag_write,
        .next = 0,
    };
    var desc_buf: [@sizeOf(VirtqDesc)]u8 = undefined;
    std.mem.copyForwards(u8, &desc_buf, std.mem.asBytes(&desc));
    try writeGuestBytes(desc_addr, desc_buf[0..]);

    try writeGuestU16(avail_addr, 0); // flags
    try writeGuestU16(avail_addr + 2, 1); // idx
    try writeGuestU16(avail_addr + 4, 0); // ring[0]
    try writeGuestU16(used_addr + 2, 0); // used idx

    appendVirtioConsoleInput("ping");
    try processVirtioConsoleRxQueue();

    var out: [4]u8 = undefined;
    try readGuestBytes(data_addr, out[0..]);
    try std.testing.expectEqualStrings("ping", out[0..]);

    const used_idx = try readGuestU16(used_addr + 2);
    try std.testing.expectEqual(@as(u16, 1), used_idx);
    const used_id = try readGuestU32(used_addr + 4);
    const used_len = try readGuestU32(used_addr + 8);
    try std.testing.expectEqual(@as(u32, 0), used_id);
    try std.testing.expectEqual(@as(u32, 4), used_len);
    try std.testing.expectEqual(@as(u16, 1), virtio_console_state.queues[0].last_avail_idx);
}

test "hvf: prepareGuestImage rejects too small memory" {
    try std.testing.expectError(error.InvalidGuestLayout, prepareGuestImage(0x1000));
}

test "hvf: start rejects already running state" {
    vcpu_running.store(true, .seq_cst);
    defer vcpu_running.store(false, .seq_cst);

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);

    try std.testing.expectError(error.AlreadyRunning, start(cfg_mut));
}

test "hvf: loadGuestKernel errors on missing file" {
    try std.testing.expectError(error.FileNotFound, loadGuestKernel(64 * 1024 * 1024, "missing-kernel"));
}

test "hvf: loadGuestInitrd errors on missing file" {
    try std.testing.expectError(error.FileNotFound, loadGuestInitrd(128 * 1024 * 1024, "missing-initrd"));
}

test "hvf: loadGuestKernel skips when unset" {
    _ = try loadGuestKernel(64 * 1024 * 1024, null);
}

test "hvf: loadGuestInitrd skips when unset" {
    const size = try loadGuestInitrd(64 * 1024 * 1024, null);
    try std.testing.expectEqual(@as(u64, 0), size);
}

test "hvf: loadGuestKernel inflates gzip image" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const gz_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "kernel.gz" });
    defer std.testing.allocator.free(gz_path);

    const gzip_data = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xff, 0xf3, 0x76, 0x0d, 0xf2, 0x03, 0x00,
        0x4a, 0x1c, 0xe9, 0x02, 0x04, 0x00, 0x00, 0x00,
    };

    var file = try std.fs.cwd().createFile(gz_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(&gzip_data);

    const memory_size: usize = 8 * 1024 * 1024;
    var guest_memory = try std.testing.allocator.alloc(u8, memory_size);
    defer std.testing.allocator.free(guest_memory);
    @memset(guest_memory, 0);

    setActiveGuestMemory(guest_memory);
    defer clearActiveGuestMemory();

    const result = try loadGuestKernel(memory_size, gz_path);
    try std.testing.expect(result.entry == null);

    const offset = guestKernelBase() - guestMemoryBase();
    try std.testing.expectEqualStrings("KERN", guest_memory[@intCast(offset) .. @intCast(offset + 4)]);
}

test "hvf: pl011 mmio reflects serial buffer" {
    serial_io.clear(std.testing.allocator);
    serial_io.append(std.testing.allocator, "B");
    defer serial_io.clear(std.testing.allocator);

    resetPl011State();

    const fr_with_data = handlePl011Mmio(pl011_reg_fr, false, 4, 0);
    try std.testing.expect((fr_with_data & (1 << 4)) == 0);
    try std.testing.expect((fr_with_data & (1 << 7)) != 0);

    const dr_val = handlePl011Mmio(pl011_reg_dr, false, 1, 0);
    try std.testing.expectEqual(@as(u8, 'B'), @as(u8, @intCast(dr_val)));

    const fr_empty = handlePl011Mmio(pl011_reg_fr, false, 4, 0);
    try std.testing.expect((fr_empty & (1 << 4)) != 0);
}

test "hvf: setupGic no-op off macos arm64" {
    if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64) return error.SkipZigTest;
    gic_enabled = false;
    gic_uart_intid = null;
    setupGic();
    try std.testing.expect(!gic_enabled);
    try std.testing.expect(gic_uart_intid == null);
}

test "hvf: gic parameters available on macos arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.SkipZigTest;

    var alignment: usize = 0;
    gic_bindings.getDistributorAlignment(&alignment) catch return error.SkipZigTest;
    gic_bindings.getRedistributorAlignment(&alignment) catch return error.SkipZigTest;

    var spi_base: u32 = 0;
    var spi_count: u32 = 0;
    gic_bindings.getSpiRange(&spi_base, &spi_count) catch return error.SkipZigTest;
    try std.testing.expect(spi_count > 0);
}

test "smoke: hvf arm64 boot emits serial output" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.SkipZigTest;

    const kernel = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
    defer if (initrd) |i| std.testing.allocator.free(i);
    const disk = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_DISK") catch null;
    defer if (disk) |d| std.testing.allocator.free(d);
    const expect = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_SERIAL_EXPECT") catch null;
    defer if (expect) |e| std.testing.allocator.free(e);
    if (kernel == null or (initrd == null and disk == null)) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const out_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "serial.log" });
    defer std.testing.allocator.free(out_path);

    var out_file = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    out_file.close();

    const name_z = try allocZ(std.testing.allocator, "M80_SERIAL_OUT");
    defer std.testing.allocator.free(name_z);
    const path_z = try allocZ(std.testing.allocator, out_path);
    defer std.testing.allocator.free(path_z);
    if (setenv(name_z, path_z, 1) != 0) return error.SkipZigTest;
    defer _ = unsetenv(name_z);

    const console_z = try allocZ(std.testing.allocator, "M80_VIRTIO_CONSOLE");
    defer std.testing.allocator.free(console_z);
    const console_val_z = try allocZ(std.testing.allocator, "1");
    defer std.testing.allocator.free(console_val_z);
    _ = setenv(console_z, console_val_z, 1);
    defer _ = unsetenv(console_z);

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.kernel_path = try std.testing.allocator.dupe(u8, kernel.?);
    if (initrd) |path| {
        cfg_mut.initrd_path = try std.testing.allocator.dupe(u8, path);
    }
    if (disk) |path| {
        cfg_mut.disk_path = try std.testing.allocator.dupe(u8, path);
        cfg_mut.disk_readonly = false;
    }
    cfg_mut.kernel_cmdline = try std.testing.allocator.dupe(
        u8,
        if (disk != null)
            "earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw loglevel=8"
        else
            "earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 loglevel=8",
    );

    const start_ms: i64 = std.time.milliTimestamp();
    var started = false;
    start(cfg_mut) catch |e| {
        std.debug.print("hvf arm64 boot test start failed: {s}\n", .{@errorName(e)});
        return error.SkipZigTest;
    };
    started = true;
    defer if (started) stop() catch {};

    var found = false;
    var tries: usize = 0;
    while (tries < 20) : (tries += 1) {
        std.Thread.sleep(500 * std.time.ns_per_ms);
        if (expect) |needle| {
            if (serial.captureContains(needle)) {
                found = true;
                break;
            }
        } else if (serial.captureLen() > 0) {
            found = true;
            break;
        }
    }

    if (found) {
        const elapsed_ms = std.time.milliTimestamp() - start_ms;
        std.debug.print("hvf boot host_ms={d}\n", .{elapsed_ms});
    }

    if (!found) {
        std.debug.print(
            "hvf boot serial capture path={s} mem_len={d}\n",
            .{ out_path, serial.captureLen() },
        );
    }

    try std.testing.expect(found);
}

test "hvf: arm64 boot accepts console input" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.SkipZigTest;

    const kernel = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const disk = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_DISK") catch null;
    defer if (disk) |d| std.testing.allocator.free(d);
    const login_input = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_LOGIN_INPUT") catch null;
    defer if (login_input) |v| std.testing.allocator.free(v);
    const login_expect = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_LOGIN_EXPECT") catch null;
    defer if (login_expect) |v| std.testing.allocator.free(v);
    if (kernel == null or disk == null or login_input == null or login_expect == null) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const out_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "serial.log" });
    defer std.testing.allocator.free(out_path);

    var out_file = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    out_file.close();

    const name_z = try allocZ(std.testing.allocator, "M80_SERIAL_OUT");
    defer std.testing.allocator.free(name_z);
    const path_z = try allocZ(std.testing.allocator, out_path);
    defer std.testing.allocator.free(path_z);
    if (setenv(name_z, path_z, 1) != 0) return error.SkipZigTest;
    defer _ = unsetenv(name_z);

    const console_z = try allocZ(std.testing.allocator, "M80_VIRTIO_CONSOLE");
    defer std.testing.allocator.free(console_z);
    const console_val_z = try allocZ(std.testing.allocator, "1");
    defer std.testing.allocator.free(console_val_z);
    _ = setenv(console_z, console_val_z, 1);
    defer _ = unsetenv(console_z);

    const cfg = try config.defaultConfig(std.testing.allocator, "test");
    var cfg_mut = cfg;
    defer config.freeConfig(std.testing.allocator, &cfg_mut);
    cfg_mut.kernel_path = try std.testing.allocator.dupe(u8, kernel.?);
    cfg_mut.disk_path = try std.testing.allocator.dupe(u8, disk.?);
    cfg_mut.disk_readonly = false;
    cfg_mut.kernel_cmdline = try std.testing.allocator.dupe(
        u8,
        "earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw loglevel=8",
    );

    var started = false;
    start(cfg_mut) catch |e| {
        std.debug.print("hvf arm64 login test start failed: {s}\n", .{@errorName(e)});
        return error.SkipZigTest;
    };
    started = true;
    defer if (started) stop() catch {};

    var saw_prompt = false;
    var saw_password = false;
    var saw_shell = false;
    const input = login_input.?;
    const split_idx = std.mem.indexOfScalar(u8, input, '\n');
    const user_line = if (split_idx) |idx| input[0..idx] else input;
    const pass_line = if (split_idx) |idx|
        if (idx + 1 <= input.len) input[(idx + 1)..] else ""
    else
        "";
    var tries: usize = 0;
    while (tries < 40) : (tries += 1) {
        std.Thread.sleep(500 * std.time.ns_per_ms);
        if (!saw_prompt and serial.captureContains("login:")) {
            saw_prompt = true;
            appendVirtioConsoleInput(user_line);
            appendVirtioConsoleInput("\n");
            processVirtioConsoleRxQueue() catch |e| {
                std.debug.print("hvf login rx failed: {s}\n", .{@errorName(e)});
            };
        }
        if (saw_prompt and !saw_password and serial.captureContains("Password:")) {
            saw_password = true;
            appendVirtioConsoleInput(pass_line);
            appendVirtioConsoleInput("\n");
            processVirtioConsoleRxQueue() catch |e| {
                std.debug.print("hvf password rx failed: {s}\n", .{@errorName(e)});
            };
        }
        if (serial.captureContains(login_expect.?)) {
            saw_shell = true;
            break;
        }
    }

    if (!saw_shell) {
        std.debug.print(
            "hvf login capture path={s} mem_len={d}\n",
            .{ out_path, serial.captureLen() },
        );
    }

    try std.testing.expect(saw_prompt);
    try std.testing.expect(saw_shell);
}

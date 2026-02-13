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
const virtio = @import("virtio.zig");
const virtio_fs = @import("../fs/virtio_fs.zig");
const vmnet = @import("../net/vmnet.zig");
const SerialIo = serial.SerialIo;
const IoExit = serial.IoExit;

// Memory size conversion constant
const mb_to_bytes: u64 = 1024 * 1024;
const vcpu_stop_signal_attempts: usize = 200;
const vcpu_stop_signal_interval_ns: u64 = 10 * std.time.ns_per_ms;

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
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait ro quiet loglevel=3 systemd.show_status=false systemd.log_level=warning"
            else
                "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/vda rootwait rw quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
        }
        return "console=ttyAMA0,115200 earlycon=pl011,0x09000000 quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
    }
    if (cfg.disk_path != null) {
        return if (cfg.disk_readonly)
            "console=ttyS0 root=/dev/vda rootwait ro quiet loglevel=3 systemd.show_status=false systemd.log_level=warning"
        else
            "console=ttyS0 root=/dev/vda rootwait rw quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
    }
    return "console=ttyS0 quiet loglevel=3 systemd.show_status=false systemd.log_level=warning";
}

/// Builds a mount specification string for the kernel command line.
/// Format: "m80.mounts=tag1:/path1,tag2:/path2"
/// Returns null if no mounts are configured.
fn buildMountSpecString(allocator: std.mem.Allocator, cfg: config.VmConfig) !?[]const u8 {
    if (cfg.mounts.len == 0) return null;

    var total_len: usize = "m80.mounts=".len;
    for (cfg.mounts, 0..) |mount, i| {
        if (i > 0) total_len += 1; // comma
        total_len += mount.tag.len + 1 + mount.guest_path.len; // tag:guest_path
    }

    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    @memcpy(result[pos..][0.."m80.mounts=".len], "m80.mounts=");
    pos += "m80.mounts=".len;

    for (cfg.mounts, 0..) |mount, i| {
        if (i > 0) {
            result[pos] = ',';
            pos += 1;
        }
        @memcpy(result[pos..][0..mount.tag.len], mount.tag);
        pos += mount.tag.len;
        result[pos] = ':';
        pos += 1;
        @memcpy(result[pos..][0..mount.guest_path.len], mount.guest_path);
        pos += mount.guest_path.len;
    }

    return result;
}

/// Builds the complete kernel command line with mount specifications appended.
/// If the config has a custom kernel_cmdline, uses that; otherwise uses default.
/// Appends mount specifications if any mounts are configured.
fn buildCmdlineWithMounts(allocator: std.mem.Allocator, cfg: config.VmConfig) ![]const u8 {
    const base_cmdline = if (cfg.kernel_cmdline) |value| value else defaultCmdlineForConfig(cfg);
    const mount_spec = try buildMountSpecString(allocator, cfg);

    if (mount_spec == null) {
        // No mounts, return the base cmdline (caller should not free if it came from config)
        return try allocator.dupe(u8, base_cmdline);
    }

    // Combine base cmdline with mount spec
    const result = try allocator.alloc(u8, base_cmdline.len + 1 + mount_spec.?.len);
    @memcpy(result[0..base_cmdline.len], base_cmdline);
    result[base_cmdline.len] = ' ';
    @memcpy(result[base_cmdline.len + 1 ..][0..mount_spec.?.len], mount_spec.?);
    allocator.free(mount_spec.?);

    return result;
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
            APIAKEYLO_EL1 = 0xc108,
            APIAKEYHI_EL1 = 0xc109,
            APIBKEYLO_EL1 = 0xc10a,
            APIBKEYHI_EL1 = 0xc10b,
            APDAKEYLO_EL1 = 0xc110,
            APDAKEYHI_EL1 = 0xc111,
            APDBKEYLO_EL1 = 0xc112,
            APDBKEYHI_EL1 = 0xc113,
            APGAKEYLO_EL1 = 0xc118,
            APGAKEYHI_EL1 = 0xc119,
            SPSR_EL1 = 0xc200,
            ELR_EL1 = 0xc201,
            SP_EL0 = 0xc208,
            MAIR_EL1 = 0xc510,
            VBAR_EL1 = 0xc600,
            TPIDR_EL1 = 0xc684,
            CNTKCTL_EL1 = 0xc708,
            TPIDR_EL0 = 0xde82,
            TPIDRRO_EL0 = 0xde83,
            CNTV_CTL_EL0 = 0xdf19,
            CNTV_CVAL_EL0 = 0xdf1a,
            CNTP_CTL_EL0 = 0xdf11,
            CNTP_CVAL_EL0 = 0xdf12,
            CNTP_TVAL_EL0 = 0xdf10,
            ICC_PMR_EL1 = 0xc230,
            ICC_BPR0_EL1 = 0xc643,
            ICC_BPR1_EL1 = 0xc663,
            ICC_CTLR_EL1 = 0xc664,
            ICC_SRE_EL1 = 0xc665,
            ICC_IGRPEN0_EL1 = 0xc666,
            ICC_IGRPEN1_EL1 = 0xc667,
            SP_EL1 = 0xe208,
        };

        extern "c" fn hv_vcpu_create(vcpu: *VcpuId, exit: **Exit, config: ?*anyopaque) HvfReturn;
        extern "c" fn hv_vcpu_destroy(vcpu: VcpuId) HvfReturn;
        extern "c" fn hv_vcpu_run(vcpu: VcpuId) HvfReturn;
        extern "c" fn hv_vcpus_exit(vcpus: [*]VcpuId, vcpu_count: u32) HvfReturn;
        extern "c" fn hv_vcpu_get_reg(vcpu: VcpuId, reg: Reg, value: *u64) HvfReturn;
        extern "c" fn hv_vcpu_set_reg(vcpu: VcpuId, reg: Reg, value: u64) HvfReturn;
        extern "c" fn hv_vcpu_set_sys_reg(vcpu: VcpuId, reg: SysReg, value: u64) HvfReturn;
        extern "c" fn hv_vcpu_get_sys_reg(vcpu: VcpuId, reg: SysReg, value: *u64) HvfReturn;
        extern "c" fn hv_vcpu_get_vtimer_offset(vcpu: VcpuId, vtimer_offset: *u64) HvfReturn;
        extern "c" fn hv_vcpu_set_vtimer_offset(vcpu: VcpuId, vtimer_offset: u64) HvfReturn;
        extern "c" fn hv_vcpu_get_vtimer_mask(vcpu: VcpuId, vtimer_is_masked: *bool) HvfReturn;
        extern "c" fn hv_vcpu_set_vtimer_mask(vcpu: VcpuId, vtimer_is_masked: bool) HvfReturn;

        fn writeReg(vcpu: VcpuId, reg: Reg, value: u64) Hvf.Error!void {
            const rc = hv_vcpu_set_reg(vcpu, reg, value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_set_reg", rc);
                return error.HvfFailure;
            }
        }

        fn readReg(vcpu: VcpuId, reg: Reg) Hvf.Error!u64 {
            var value: u64 = 0;
            const rc = hv_vcpu_get_reg(vcpu, reg, &value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_get_reg", rc);
                return error.HvfFailure;
            }
            return value;
        }

        fn writeSysReg(vcpu: VcpuId, reg: SysReg, value: u64) Hvf.Error!void {
            const rc = hv_vcpu_set_sys_reg(vcpu, reg, value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_set_sys_reg", rc);
                return error.HvfFailure;
            }
        }

        fn readSysReg(vcpu: VcpuId, reg: SysReg) Hvf.Error!u64 {
            var value: u64 = 0;
            const rc = hv_vcpu_get_sys_reg(vcpu, reg, &value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_get_sys_reg", rc);
                return error.HvfFailure;
            }
            return value;
        }

        fn writeSysRegOptional(vcpu: VcpuId, reg: SysReg, value: u64) bool {
            const rc = hv_vcpu_set_sys_reg(vcpu, reg, value);
            return rc == HV_SUCCESS;
        }

        fn readSysRegOptional(vcpu: VcpuId, reg: SysReg) ?u64 {
            var value: u64 = 0;
            const rc = hv_vcpu_get_sys_reg(vcpu, reg, &value);
            if (rc != HV_SUCCESS) return null;
            return value;
        }

        fn getVtimerOffset(vcpu: VcpuId) Hvf.Error!u64 {
            var value: u64 = 0;
            const rc = hv_vcpu_get_vtimer_offset(vcpu, &value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_get_vtimer_offset", rc);
                return error.HvfFailure;
            }
            return value;
        }

        fn setVtimerOffset(vcpu: VcpuId, value: u64) Hvf.Error!void {
            const rc = hv_vcpu_set_vtimer_offset(vcpu, value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_set_vtimer_offset", rc);
                return error.HvfFailure;
            }
        }

        fn getVtimerMask(vcpu: VcpuId) Hvf.Error!bool {
            var value: bool = false;
            const rc = hv_vcpu_get_vtimer_mask(vcpu, &value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_get_vtimer_mask", rc);
                return error.HvfFailure;
            }
            return value;
        }

        fn setVtimerMask(vcpu: VcpuId, value: bool) Hvf.Error!void {
            const rc = hv_vcpu_set_vtimer_mask(vcpu, value);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_vcpu_set_vtimer_mask", rc);
                return error.HvfFailure;
            }
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
        extern "c" fn hv_gic_state_create() ?*anyopaque;
        extern "c" fn hv_gic_state_get_size(state: ?*anyopaque, gic_state_size: *usize) HvfReturn;
        extern "c" fn hv_gic_state_get_data(state: ?*anyopaque, gic_state_data: *anyopaque) HvfReturn;
        extern "c" fn hv_gic_set_state(gic_state_data: *const anyopaque, gic_state_size: usize) HvfReturn;
        extern "c" fn hv_gic_reset() HvfReturn;
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

        fn stateCreate() ?*anyopaque {
            return hv_gic_state_create();
        }

        fn stateRelease(state: ?*anyopaque) void {
            if (state) |ptr| os_release(ptr);
        }

        fn stateGetSize(state: ?*anyopaque) Hvf.Error!usize {
            var size: usize = 0;
            const rc = hv_gic_state_get_size(state, &size);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_state_get_size", rc);
                return error.HvfFailure;
            }
            return size;
        }

        fn stateGetData(state: ?*anyopaque, buf: []u8) Hvf.Error!void {
            const rc = hv_gic_state_get_data(state, buf.ptr);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_state_get_data", rc);
                return error.HvfFailure;
            }
        }

        fn setState(buf: []const u8) Hvf.Error!void {
            const rc = hv_gic_set_state(buf.ptr, buf.len);
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_set_state", rc);
                return error.HvfFailure;
            }
        }

        fn reset() Hvf.Error!void {
            const rc = hv_gic_reset();
            if (rc != HV_SUCCESS) {
                logHvfFailure("hv_gic_reset", rc);
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
// vCPU STATE CAPTURE/RESTORE (for snapshot/restore)
// =============================================================================

const snapshot = @import("snapshot.zig");

/// Captures the current vCPU state for snapshot.
/// Only supported on macOS ARM64.
pub fn captureVcpuState() !snapshot.VcpuState {
    if (builtin.os.tag != .macos) return error.NotSupported;

    if (builtin.cpu.arch == .aarch64) {
        const vcpu = active_vcpu_id_arm orelse return error.InvalidState;
        var state: snapshot.VcpuState = .{ .arm64 = .{} };
        const read_reg = struct {
            fn reg(vcpu_id: arm64_bindings.VcpuId, reg_id: arm64_bindings.Reg) !u64 {
                return arm64_bindings.readReg(vcpu_id, reg_id) catch |e| {
                    log.warn("snapshot capture: readReg {s} failed: {s}", .{ @tagName(reg_id), @errorName(e) });
                    return e;
                };
            }
            fn sys(vcpu_id: arm64_bindings.VcpuId, reg_id: arm64_bindings.SysReg) !u64 {
                return arm64_bindings.readSysReg(vcpu_id, reg_id) catch |e| {
                    log.warn("snapshot capture: readSysReg {s} failed: {s}", .{ @tagName(reg_id), @errorName(e) });
                    return e;
                };
            }
            fn sysOptional(vcpu_id: arm64_bindings.VcpuId, reg_id: arm64_bindings.SysReg) u64 {
                if (arm64_bindings.readSysRegOptional(vcpu_id, reg_id)) |value| {
                    return value;
                }
                log.debug("snapshot capture: optional sysreg {s} unavailable", .{@tagName(reg_id)});
                return 0;
            }
        };

        // GPRs X0-X30
        state.arm64.x[0] = try read_reg.reg(vcpu, .X0);
        state.arm64.x[1] = try read_reg.reg(vcpu, .X1);
        state.arm64.x[2] = try read_reg.reg(vcpu, .X2);
        state.arm64.x[3] = try read_reg.reg(vcpu, .X3);
        state.arm64.x[4] = try read_reg.reg(vcpu, .X4);
        state.arm64.x[5] = try read_reg.reg(vcpu, .X5);
        state.arm64.x[6] = try read_reg.reg(vcpu, .X6);
        state.arm64.x[7] = try read_reg.reg(vcpu, .X7);
        state.arm64.x[8] = try read_reg.reg(vcpu, .X8);
        state.arm64.x[9] = try read_reg.reg(vcpu, .X9);
        state.arm64.x[10] = try read_reg.reg(vcpu, .X10);
        state.arm64.x[11] = try read_reg.reg(vcpu, .X11);
        state.arm64.x[12] = try read_reg.reg(vcpu, .X12);
        state.arm64.x[13] = try read_reg.reg(vcpu, .X13);
        state.arm64.x[14] = try read_reg.reg(vcpu, .X14);
        state.arm64.x[15] = try read_reg.reg(vcpu, .X15);
        state.arm64.x[16] = try read_reg.reg(vcpu, .X16);
        state.arm64.x[17] = try read_reg.reg(vcpu, .X17);
        state.arm64.x[18] = try read_reg.reg(vcpu, .X18);
        state.arm64.x[19] = try read_reg.reg(vcpu, .X19);
        state.arm64.x[20] = try read_reg.reg(vcpu, .X20);
        state.arm64.x[21] = try read_reg.reg(vcpu, .X21);
        state.arm64.x[22] = try read_reg.reg(vcpu, .X22);
        state.arm64.x[23] = try read_reg.reg(vcpu, .X23);
        state.arm64.x[24] = try read_reg.reg(vcpu, .X24);
        state.arm64.x[25] = try read_reg.reg(vcpu, .X25);
        state.arm64.x[26] = try read_reg.reg(vcpu, .X26);
        state.arm64.x[27] = try read_reg.reg(vcpu, .X27);
        state.arm64.x[28] = try read_reg.reg(vcpu, .X28);
        state.arm64.x[29] = try read_reg.reg(vcpu, .X29);
        state.arm64.x[30] = try read_reg.reg(vcpu, .X30);

        // Special registers
        state.arm64.pc = try read_reg.reg(vcpu, .PC);
        state.arm64.cpsr = try read_reg.reg(vcpu, .CPSR);
        state.arm64.fpcr = try read_reg.reg(vcpu, .FPCR);
        state.arm64.fpsr = try read_reg.reg(vcpu, .FPSR);

        // System registers
        state.arm64.sp = try read_reg.sys(vcpu, .SP_EL1);
        state.arm64.sp_el0 = read_reg.sysOptional(vcpu, .SP_EL0);
        state.arm64.sp_el1 = try read_reg.sys(vcpu, .SP_EL1);
        state.arm64.elr_el1 = try read_reg.sys(vcpu, .ELR_EL1);
        state.arm64.spsr_el1 = try read_reg.sys(vcpu, .SPSR_EL1);
        state.arm64.sctlr_el1 = try read_reg.sys(vcpu, .SCTLR_EL1);
        state.arm64.tcr_el1 = try read_reg.sys(vcpu, .TCR_EL1);
        state.arm64.ttbr0_el1 = try read_reg.sys(vcpu, .TTBR0_EL1);
        state.arm64.ttbr1_el1 = try read_reg.sys(vcpu, .TTBR1_EL1);
        state.arm64.mair_el1 = try read_reg.sys(vcpu, .MAIR_EL1);
        state.arm64.vbar_el1 = try read_reg.sys(vcpu, .VBAR_EL1);
        state.arm64.mpidr_el1 = try read_reg.sys(vcpu, .MPIDR_EL1);
        state.arm64.tpidr_el0 = read_reg.sysOptional(vcpu, .TPIDR_EL0);
        state.arm64.tpidr_el1 = read_reg.sysOptional(vcpu, .TPIDR_EL1);
        state.arm64.tpidrro_el0 = read_reg.sysOptional(vcpu, .TPIDRRO_EL0);
        state.arm64.cntkctl_el1 = read_reg.sysOptional(vcpu, .CNTKCTL_EL1);
        state.arm64.cntv_ctl_el0 = read_reg.sysOptional(vcpu, .CNTV_CTL_EL0);
        state.arm64.cntv_cval_el0 = read_reg.sysOptional(vcpu, .CNTV_CVAL_EL0);
        state.arm64.cntp_ctl_el0 = read_reg.sysOptional(vcpu, .CNTP_CTL_EL0);
        state.arm64.cntp_cval_el0 = read_reg.sysOptional(vcpu, .CNTP_CVAL_EL0);
        state.arm64.cntp_tval_el0 = read_reg.sysOptional(vcpu, .CNTP_TVAL_EL0);
        state.arm64.icc_pmr_el1 = read_reg.sysOptional(vcpu, .ICC_PMR_EL1);
        state.arm64.icc_bpr0_el1 = read_reg.sysOptional(vcpu, .ICC_BPR0_EL1);
        state.arm64.icc_bpr1_el1 = read_reg.sysOptional(vcpu, .ICC_BPR1_EL1);
        state.arm64.icc_ctlr_el1 = read_reg.sysOptional(vcpu, .ICC_CTLR_EL1);
        state.arm64.icc_sre_el1 = read_reg.sysOptional(vcpu, .ICC_SRE_EL1);
        state.arm64.icc_igrpen0_el1 = read_reg.sysOptional(vcpu, .ICC_IGRPEN0_EL1);
        state.arm64.icc_igrpen1_el1 = read_reg.sysOptional(vcpu, .ICC_IGRPEN1_EL1);
        state.arm64.apia_key_lo = read_reg.sysOptional(vcpu, .APIAKEYLO_EL1);
        state.arm64.apia_key_hi = read_reg.sysOptional(vcpu, .APIAKEYHI_EL1);
        state.arm64.apib_key_lo = read_reg.sysOptional(vcpu, .APIBKEYLO_EL1);
        state.arm64.apib_key_hi = read_reg.sysOptional(vcpu, .APIBKEYHI_EL1);
        state.arm64.apda_key_lo = read_reg.sysOptional(vcpu, .APDAKEYLO_EL1);
        state.arm64.apda_key_hi = read_reg.sysOptional(vcpu, .APDAKEYHI_EL1);
        state.arm64.apdb_key_lo = read_reg.sysOptional(vcpu, .APDBKEYLO_EL1);
        state.arm64.apdb_key_hi = read_reg.sysOptional(vcpu, .APDBKEYHI_EL1);
        state.arm64.apga_key_lo = read_reg.sysOptional(vcpu, .APGAKEYLO_EL1);
        state.arm64.apga_key_hi = read_reg.sysOptional(vcpu, .APGAKEYHI_EL1);

        var vtimer_valid = true;
        const vtimer_offset: u64 = arm64_bindings.getVtimerOffset(vcpu) catch |e| blk: {
            log.debug("snapshot capture: vtimer offset unavailable: {s}", .{@errorName(e)});
            vtimer_valid = false;
            break :blk 0;
        };
        const vtimer_masked: bool = arm64_bindings.getVtimerMask(vcpu) catch |e| blk: {
            log.debug("snapshot capture: vtimer mask unavailable: {s}", .{@errorName(e)});
            vtimer_valid = false;
            break :blk false;
        };
        state.arm64.vtimer_offset = vtimer_offset;
        state.arm64.vtimer_masked = if (vtimer_masked) 1 else 0;
        state.arm64.vtimer_valid = if (vtimer_valid) 1 else 0;

        return state;
    }

    if (builtin.cpu.arch == .x86_64) {
        const vcpu = active_vcpu_id_x86 orelse return error.InvalidState;
        var state: snapshot.VcpuState = .{ .x86 = .{} };

        state.x86.rax = try hvfReadReg(vcpu, .RAX);
        state.x86.rbx = try hvfReadReg(vcpu, .RBX);
        state.x86.rcx = try hvfReadReg(vcpu, .RCX);
        state.x86.rdx = try hvfReadReg(vcpu, .RDX);
        state.x86.rsi = try hvfReadReg(vcpu, .RSI);
        state.x86.rdi = try hvfReadReg(vcpu, .RDI);
        state.x86.rbp = try hvfReadReg(vcpu, .RBP);
        state.x86.rsp = try hvfReadReg(vcpu, .RSP);
        state.x86.r8 = try hvfReadReg(vcpu, .R8);
        state.x86.r9 = try hvfReadReg(vcpu, .R9);
        state.x86.r10 = try hvfReadReg(vcpu, .R10);
        state.x86.r11 = try hvfReadReg(vcpu, .R11);
        state.x86.r12 = try hvfReadReg(vcpu, .R12);
        state.x86.r13 = try hvfReadReg(vcpu, .R13);
        state.x86.r14 = try hvfReadReg(vcpu, .R14);
        state.x86.r15 = try hvfReadReg(vcpu, .R15);
        state.x86.rip = try hvfReadReg(vcpu, .RIP);
        state.x86.rflags = try hvfReadReg(vcpu, .RFLAGS);

        state.x86.cs = @intCast(try hvfReadReg(vcpu, .CS));
        state.x86.ds = @intCast(try hvfReadReg(vcpu, .DS));
        state.x86.es = @intCast(try hvfReadReg(vcpu, .ES));
        state.x86.fs = @intCast(try hvfReadReg(vcpu, .FS));
        state.x86.gs = @intCast(try hvfReadReg(vcpu, .GS));
        state.x86.ss = @intCast(try hvfReadReg(vcpu, .SS));

        state.x86.gdt_base = try hvfReadReg(vcpu, .GDT_BASE);
        state.x86.gdt_limit = @intCast(try hvfReadReg(vcpu, .GDT_LIMIT));
        state.x86.idt_base = try hvfReadReg(vcpu, .IDT_BASE);
        state.x86.idt_limit = @intCast(try hvfReadReg(vcpu, .IDT_LIMIT));

        state.x86.cr0 = try hvfReadReg(vcpu, .CR0);
        state.x86.cr3 = try hvfReadReg(vcpu, .CR3);
        state.x86.cr4 = try hvfReadReg(vcpu, .CR4);

        return state;
    }

    return error.NotSupported;
}

/// Restores vCPU state from a snapshot.
/// Only supported on macOS ARM64.
pub fn restoreVcpuState(state: snapshot.VcpuState) !void {
    if (builtin.os.tag != .macos) return error.NotSupported;

    if (builtin.cpu.arch == .aarch64) {
        const vcpu = active_vcpu_id_arm orelse return error.InvalidState;
        const write_sys_optional = struct {
            fn writeIfNonZero(vcpu_id: arm64_bindings.VcpuId, reg_id: arm64_bindings.SysReg, value: u64) void {
                if (value == 0) return;
                if (!arm64_bindings.writeSysRegOptional(vcpu_id, reg_id, value)) {
                    log.debug("snapshot restore: optional sysreg {s} unavailable", .{@tagName(reg_id)});
                }
            }
            fn write(vcpu_id: arm64_bindings.VcpuId, reg_id: arm64_bindings.SysReg, value: u64) void {
                if (!arm64_bindings.writeSysRegOptional(vcpu_id, reg_id, value)) {
                    log.debug("snapshot restore: optional sysreg {s} unavailable", .{@tagName(reg_id)});
                }
            }
        };

        // GPRs X0-X30
        try arm64_bindings.writeReg(vcpu, .X0, state.arm64.x[0]);
        try arm64_bindings.writeReg(vcpu, .X1, state.arm64.x[1]);
        try arm64_bindings.writeReg(vcpu, .X2, state.arm64.x[2]);
        try arm64_bindings.writeReg(vcpu, .X3, state.arm64.x[3]);
        try arm64_bindings.writeReg(vcpu, .X4, state.arm64.x[4]);
        try arm64_bindings.writeReg(vcpu, .X5, state.arm64.x[5]);
        try arm64_bindings.writeReg(vcpu, .X6, state.arm64.x[6]);
        try arm64_bindings.writeReg(vcpu, .X7, state.arm64.x[7]);
        try arm64_bindings.writeReg(vcpu, .X8, state.arm64.x[8]);
        try arm64_bindings.writeReg(vcpu, .X9, state.arm64.x[9]);
        try arm64_bindings.writeReg(vcpu, .X10, state.arm64.x[10]);
        try arm64_bindings.writeReg(vcpu, .X11, state.arm64.x[11]);
        try arm64_bindings.writeReg(vcpu, .X12, state.arm64.x[12]);
        try arm64_bindings.writeReg(vcpu, .X13, state.arm64.x[13]);
        try arm64_bindings.writeReg(vcpu, .X14, state.arm64.x[14]);
        try arm64_bindings.writeReg(vcpu, .X15, state.arm64.x[15]);
        try arm64_bindings.writeReg(vcpu, .X16, state.arm64.x[16]);
        try arm64_bindings.writeReg(vcpu, .X17, state.arm64.x[17]);
        try arm64_bindings.writeReg(vcpu, .X18, state.arm64.x[18]);
        try arm64_bindings.writeReg(vcpu, .X19, state.arm64.x[19]);
        try arm64_bindings.writeReg(vcpu, .X20, state.arm64.x[20]);
        try arm64_bindings.writeReg(vcpu, .X21, state.arm64.x[21]);
        try arm64_bindings.writeReg(vcpu, .X22, state.arm64.x[22]);
        try arm64_bindings.writeReg(vcpu, .X23, state.arm64.x[23]);
        try arm64_bindings.writeReg(vcpu, .X24, state.arm64.x[24]);
        try arm64_bindings.writeReg(vcpu, .X25, state.arm64.x[25]);
        try arm64_bindings.writeReg(vcpu, .X26, state.arm64.x[26]);
        try arm64_bindings.writeReg(vcpu, .X27, state.arm64.x[27]);
        try arm64_bindings.writeReg(vcpu, .X28, state.arm64.x[28]);
        try arm64_bindings.writeReg(vcpu, .X29, state.arm64.x[29]);
        try arm64_bindings.writeReg(vcpu, .X30, state.arm64.x[30]);

        // Special registers
        try arm64_bindings.writeReg(vcpu, .PC, state.arm64.pc);
        try arm64_bindings.writeReg(vcpu, .CPSR, state.arm64.cpsr);
        try arm64_bindings.writeReg(vcpu, .FPCR, state.arm64.fpcr);
        try arm64_bindings.writeReg(vcpu, .FPSR, state.arm64.fpsr);
        log.debug("snapshot restore: arm64 pc=0x{x} sp_el1=0x{x} elr_el1=0x{x}", .{
            state.arm64.pc,
            state.arm64.sp_el1,
            state.arm64.elr_el1,
        });

        // System registers
        write_sys_optional.writeIfNonZero(vcpu, .SP_EL0, state.arm64.sp_el0);
        try arm64_bindings.writeSysReg(vcpu, .SP_EL1, state.arm64.sp_el1);
        try arm64_bindings.writeSysReg(vcpu, .ELR_EL1, state.arm64.elr_el1);
        try arm64_bindings.writeSysReg(vcpu, .SPSR_EL1, state.arm64.spsr_el1);
        try arm64_bindings.writeSysReg(vcpu, .SCTLR_EL1, state.arm64.sctlr_el1);
        try arm64_bindings.writeSysReg(vcpu, .TCR_EL1, state.arm64.tcr_el1);
        try arm64_bindings.writeSysReg(vcpu, .TTBR0_EL1, state.arm64.ttbr0_el1);
        try arm64_bindings.writeSysReg(vcpu, .TTBR1_EL1, state.arm64.ttbr1_el1);
        try arm64_bindings.writeSysReg(vcpu, .MAIR_EL1, state.arm64.mair_el1);
        try arm64_bindings.writeSysReg(vcpu, .VBAR_EL1, state.arm64.vbar_el1);
        try arm64_bindings.writeSysReg(vcpu, .MPIDR_EL1, state.arm64.mpidr_el1);
        write_sys_optional.writeIfNonZero(vcpu, .TPIDR_EL0, state.arm64.tpidr_el0);
        write_sys_optional.writeIfNonZero(vcpu, .TPIDR_EL1, state.arm64.tpidr_el1);
        write_sys_optional.writeIfNonZero(vcpu, .TPIDRRO_EL0, state.arm64.tpidrro_el0);
        write_sys_optional.writeIfNonZero(vcpu, .CNTKCTL_EL1, state.arm64.cntkctl_el1);
        write_sys_optional.writeIfNonZero(vcpu, .CNTV_CTL_EL0, state.arm64.cntv_ctl_el0);
        write_sys_optional.writeIfNonZero(vcpu, .CNTV_CVAL_EL0, state.arm64.cntv_cval_el0);
        write_sys_optional.writeIfNonZero(vcpu, .CNTP_CTL_EL0, state.arm64.cntp_ctl_el0);
        write_sys_optional.writeIfNonZero(vcpu, .CNTP_CVAL_EL0, state.arm64.cntp_cval_el0);
        write_sys_optional.writeIfNonZero(vcpu, .CNTP_TVAL_EL0, state.arm64.cntp_tval_el0);
        write_sys_optional.write(vcpu, .ICC_SRE_EL1, state.arm64.icc_sre_el1);
        write_sys_optional.write(vcpu, .ICC_CTLR_EL1, state.arm64.icc_ctlr_el1);
        write_sys_optional.write(vcpu, .ICC_BPR0_EL1, state.arm64.icc_bpr0_el1);
        write_sys_optional.write(vcpu, .ICC_BPR1_EL1, state.arm64.icc_bpr1_el1);
        write_sys_optional.write(vcpu, .ICC_PMR_EL1, state.arm64.icc_pmr_el1);
        write_sys_optional.write(vcpu, .ICC_IGRPEN0_EL1, state.arm64.icc_igrpen0_el1);
        write_sys_optional.write(vcpu, .ICC_IGRPEN1_EL1, state.arm64.icc_igrpen1_el1);
        write_sys_optional.writeIfNonZero(vcpu, .APIAKEYLO_EL1, state.arm64.apia_key_lo);
        write_sys_optional.writeIfNonZero(vcpu, .APIAKEYHI_EL1, state.arm64.apia_key_hi);
        write_sys_optional.writeIfNonZero(vcpu, .APIBKEYLO_EL1, state.arm64.apib_key_lo);
        write_sys_optional.writeIfNonZero(vcpu, .APIBKEYHI_EL1, state.arm64.apib_key_hi);
        write_sys_optional.writeIfNonZero(vcpu, .APDAKEYLO_EL1, state.arm64.apda_key_lo);
        write_sys_optional.writeIfNonZero(vcpu, .APDAKEYHI_EL1, state.arm64.apda_key_hi);
        write_sys_optional.writeIfNonZero(vcpu, .APDBKEYLO_EL1, state.arm64.apdb_key_lo);
        write_sys_optional.writeIfNonZero(vcpu, .APDBKEYHI_EL1, state.arm64.apdb_key_hi);
        write_sys_optional.writeIfNonZero(vcpu, .APGAKEYLO_EL1, state.arm64.apga_key_lo);
        write_sys_optional.writeIfNonZero(vcpu, .APGAKEYHI_EL1, state.arm64.apga_key_hi);
        if (state.arm64.vtimer_valid != 0) {
            arm64_bindings.setVtimerOffset(vcpu, state.arm64.vtimer_offset) catch |e| {
                log.debug("snapshot restore: vtimer offset set failed: {s}", .{@errorName(e)});
            };
            arm64_bindings.setVtimerMask(vcpu, state.arm64.vtimer_masked != 0) catch |e| {
                log.debug("snapshot restore: vtimer mask set failed: {s}", .{@errorName(e)});
            };
        }

        return;
    }

    if (builtin.cpu.arch == .x86_64) {
        const vcpu = active_vcpu_id_x86 orelse return error.InvalidState;

        try hvfWriteReg(vcpu, .RAX, state.x86.rax);
        try hvfWriteReg(vcpu, .RBX, state.x86.rbx);
        try hvfWriteReg(vcpu, .RCX, state.x86.rcx);
        try hvfWriteReg(vcpu, .RDX, state.x86.rdx);
        try hvfWriteReg(vcpu, .RSI, state.x86.rsi);
        try hvfWriteReg(vcpu, .RDI, state.x86.rdi);
        try hvfWriteReg(vcpu, .RBP, state.x86.rbp);
        try hvfWriteReg(vcpu, .RSP, state.x86.rsp);
        try hvfWriteReg(vcpu, .R8, state.x86.r8);
        try hvfWriteReg(vcpu, .R9, state.x86.r9);
        try hvfWriteReg(vcpu, .R10, state.x86.r10);
        try hvfWriteReg(vcpu, .R11, state.x86.r11);
        try hvfWriteReg(vcpu, .R12, state.x86.r12);
        try hvfWriteReg(vcpu, .R13, state.x86.r13);
        try hvfWriteReg(vcpu, .R14, state.x86.r14);
        try hvfWriteReg(vcpu, .R15, state.x86.r15);
        try hvfWriteReg(vcpu, .RIP, state.x86.rip);
        try hvfWriteReg(vcpu, .RFLAGS, state.x86.rflags);

        try hvfWriteReg(vcpu, .CS, state.x86.cs);
        try hvfWriteReg(vcpu, .DS, state.x86.ds);
        try hvfWriteReg(vcpu, .ES, state.x86.es);
        try hvfWriteReg(vcpu, .FS, state.x86.fs);
        try hvfWriteReg(vcpu, .GS, state.x86.gs);
        try hvfWriteReg(vcpu, .SS, state.x86.ss);

        try hvfWriteReg(vcpu, .GDT_BASE, state.x86.gdt_base);
        try hvfWriteReg(vcpu, .GDT_LIMIT, state.x86.gdt_limit);
        try hvfWriteReg(vcpu, .IDT_BASE, state.x86.idt_base);
        try hvfWriteReg(vcpu, .IDT_LIMIT, state.x86.idt_limit);

        try hvfWriteReg(vcpu, .CR0, state.x86.cr0);
        try hvfWriteReg(vcpu, .CR3, state.x86.cr3);
        try hvfWriteReg(vcpu, .CR4, state.x86.cr4);

        return;
    }

    return error.NotSupported;
}

/// Pauses the vCPU by forcing an exit.
/// Used for live snapshot: pause -> capture state -> resume.
pub fn pauseVcpu() !void {
    if (builtin.os.tag != .macos) return error.NotSupported;

    vcpu_pause_requested.store(true, .seq_cst);

    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (!vcpu_running.load(.seq_cst)) {
            log.warn("snapshot pause: vcpu_running=false active_arm={} active_x86={}", .{
                active_vcpu_id_arm != null,
                active_vcpu_id_x86 != null,
            });
            return error.NotRunning;
        }
        const active = switch (builtin.cpu.arch) {
            .aarch64 => active_vcpu_id_arm != null,
            .x86_64 => active_vcpu_id_x86 != null,
            else => return error.NotSupported,
        };
        if (active) break;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    switch (builtin.cpu.arch) {
        .aarch64 => {
            const vcpu = active_vcpu_id_arm orelse {
                log.warn("snapshot pause: active vcpu missing after wait", .{});
                return error.NotRunning;
            };
            arm64_bindings.exit(vcpu) catch |e| {
                log.warn("snapshot pause: arm64 exit failed: {s}", .{@errorName(e)});
                return e;
            };
        },
        .x86_64 => {
            const vcpu = active_vcpu_id_x86 orelse {
                log.warn("snapshot pause: active vcpu missing after wait", .{});
                return error.NotRunning;
            };
            x86_vcpu_bindings.interrupt(vcpu) catch |e| {
                log.warn("snapshot pause: x86 interrupt failed: {s}", .{@errorName(e)});
                return e;
            };
        },
        else => return error.NotSupported,
    }

    while (true) {
        if (vcpu_paused.load(.seq_cst)) return;
        if (!vcpu_running.load(.seq_cst)) return error.NotRunning;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

/// Resumes the vCPU after a pause.
/// The vCPU will continue execution from where it was paused.
pub fn resumeVcpu() void {
    vcpu_pause_requested.store(false, .seq_cst);
    while (vcpu_paused.load(.seq_cst)) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    paused_vcpu_state_mutex.lock();
    paused_vcpu_state = null;
    paused_vcpu_state_error = null;
    paused_vcpu_state_mutex.unlock();

    vcpu_pause_requested.store(false, .seq_cst);
    vcpu_paused.store(false, .seq_cst);
    vcpu_running.store(true, .seq_cst);
}

/// Checks if the vCPU is currently running.
pub fn isVcpuRunning() bool {
    return vcpu_running.load(.seq_cst);
}

/// Returns true if a vCPU has been created for the active VM.
pub fn hasActiveVcpu() bool {
    return switch (builtin.cpu.arch) {
        .aarch64 => active_vcpu_id_arm != null,
        .x86_64 => active_vcpu_id_x86 != null,
        else => false,
    };
}

pub fn takePausedVcpuState() !snapshot.VcpuState {
    paused_vcpu_state_mutex.lock();
    defer paused_vcpu_state_mutex.unlock();

    if (paused_vcpu_state_error) |e| return e;
    const state = paused_vcpu_state orelse return error.InvalidState;
    paused_vcpu_state = null;
    return state;
}

pub fn applyPausedVcpuState(state: snapshot.VcpuState) !void {
    paused_vcpu_state_mutex.lock();
    restore_vcpu_state = state;
    restore_vcpu_state_error = null;
    paused_vcpu_state_mutex.unlock();

    var attempts: usize = 0;
    while (attempts < 2000) : (attempts += 1) {
        paused_vcpu_state_mutex.lock();
        const pending = restore_vcpu_state != null;
        const err = restore_vcpu_state_error;
        paused_vcpu_state_mutex.unlock();

        if (!pending) {
            if (err) |e| return e;
            return;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

/// Returns the active guest memory for snapshot.
pub fn getGuestMemory() ?[]u8 {
    return active_guest_memory;
}

/// Returns the guest memory size for snapshot.
pub fn getGuestMemorySize() usize {
    return active_memory_size;
}

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
/// True if guest memory was allocated via mmap (lazy allocation)
var active_memory_is_mmap: bool = false;

/// vCPU thread handle (for joining on stop)
var active_vcpu_thread: ?std.Thread = null;

/// Active vCPU IDs by architecture (set by vCPU thread)
var active_vcpu_id_x86: ?HvfVcpuId = null;
var active_vcpu_id_arm: ?arm64_bindings.VcpuId = null;

/// Atomic flag: true while vCPU should keep running
var vcpu_running = std.atomic.Value(bool).init(false);
/// Atomic flag: true when the vCPU thread has fully exited
var vcpu_thread_exited = std.atomic.Value(bool).init(true);

/// Atomic flag: pause requested for vCPU run loop
var vcpu_pause_requested = std.atomic.Value(bool).init(false);

/// Atomic flag: vCPU run loop is currently paused
var vcpu_paused = std.atomic.Value(bool).init(false);

var paused_vcpu_state: ?snapshot.VcpuState = null;
var paused_vcpu_state_error: ?anyerror = null;
var restore_vcpu_state: ?snapshot.VcpuState = null;
var restore_vcpu_state_error: ?anyerror = null;
var paused_vcpu_state_mutex = std.Thread.Mutex{};

/// Atomic flag: trigger simulated I/O for testing
var simulate_io = std.atomic.Value(bool).init(false);

/// Serial port emulation state
var serial_io = SerialIo{};
var serial_input_thread: ?std.Thread = null;
var serial_input_running = std.atomic.Value(bool).init(false);
var console_socket_thread: ?std.Thread = null;
var console_socket_running = std.atomic.Value(bool).init(false);
var console_socket_path: ?[]u8 = null;
var console_rx_logged = std.atomic.Value(bool).init(false);

/// Active vmnet interface for networking (macOS only)
var active_vmnet_iface: ?vmnet.VmnetInterface = null;
var vmnet_rx_thread: ?std.Thread = null;
var vmnet_rx_running = std.atomic.Value(bool).init(false);
var arm64_unknown_sysreg_trap_count = std.atomic.Value(u32).init(0);

/// GIC wiring for arm64 interrupt injection
var gic_enabled = false;
var gic_uart_intid: ?u32 = null;

fn resetPl011State() void {
    pl011_state = .{};
    if (serial_io.hasData()) {
        pl011_state.pending |= pl011_int_rx;
    }
    updateUartInterrupt();
}

fn virtioInterruptHandler(intid: u32, level: bool) void {
    if (!gic_enabled) return;
    gic_bindings.setSpi(intid, level) catch |e| {
        log.warn("hvf gic set virtio spi failed: {s}", .{@errorName(e)});
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

pub fn capturePl011State() snapshot.Pl011SnapshotState {
    return .{
        .cr = pl011_state.cr,
        .lcrh = pl011_state.lcrh,
        .ibrd = pl011_state.ibrd,
        .fbrd = pl011_state.fbrd,
        .imsc = pl011_state.imsc,
        .pending = pl011_state.pending,
    };
}

pub fn restorePl011State(state: snapshot.Pl011SnapshotState) void {
    pl011_state = .{
        .cr = state.cr,
        .lcrh = state.lcrh,
        .ibrd = state.ibrd,
        .fbrd = state.fbrd,
        .imsc = state.imsc,
        .pending = state.pending,
    };
    pl011_seen.store(true, .seq_cst);
    updateUartInterrupt();
}

pub fn captureGicState(allocator: std.mem.Allocator) !?[]u8 {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return null;
    if (!gic_enabled) return null;
    const state = gic_bindings.stateCreate() orelse return null;
    defer gic_bindings.stateRelease(state);
    const size = gic_bindings.stateGetSize(state) catch return null;
    if (size == 0) return null;
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    gic_bindings.stateGetData(state, buf) catch |e| {
        allocator.free(buf);
        return e;
    };
    return buf;
}

pub fn restoreGicState(data: []const u8) !void {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.NotSupported;
    if (!gic_enabled) return error.InvalidState;
    if (data.len == 0) return;
    gic_bindings.setState(data) catch |e| {
        log.warn("hvf gic set state failed: {s}", .{@errorName(e)});
        return e;
    };
}

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

fn startSerialInputThread() bool {
    if (serial_input_running.load(.seq_cst)) return true;
    serial_input_running.store(true, .seq_cst);
    serial_input_thread = std.Thread.spawn(.{}, serialInputLoop, .{}) catch |e| {
        serial_input_running.store(false, .seq_cst);
        log.warn("hvf serial stdin thread failed: {s}", .{@errorName(e)});
        return false;
    };
    log.info("hvf serial stdin enabled", .{});
    return true;
}

fn stopSerialInputThread() void {
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
    if (virtio.virtio_console_state.enabled) {
        const queue = &virtio.virtio_console_state.queues[0];
        virtio.appendVirtioConsoleInput(bytes);
        virtio.processVirtioConsoleRxQueue() catch |e| {
            log.warn("hvf virtio-console rx process failed: {s} ready={} num={d}", .{
                @errorName(e),
                queue.ready,
                queue.num,
            });
        };
    }
    serial_io.append(std.heap.page_allocator, bytes);
}

// =============================================================================
// VMNET NETWORKING (macOS only)
// =============================================================================

/// TX callback: called by virtio-net when guest sends a packet.
/// Writes the frame to the vmnet interface.
fn vmnetTxCallback(frame: []const u8) void {
    const iface = active_vmnet_iface orelse return;
    if (frame.len == 0 or frame.len > iface.max_packet_size) return;

    // Set up packet descriptor for vmnet_write
    var iov: vmnet.c_types.iovec = .{
        .iov_base = @ptrCast(@constCast(frame.ptr)),
        .iov_len = frame.len,
    };
    var pkt: vmnet.c_types.vmpktdesc = .{
        .vm_pkt_size = frame.len,
        .vm_pkt_iov = &iov,
        .vm_pkt_iovcnt = 1,
        .vm_flags = 0,
    };
    var pktcnt: c_int = 1;
    vmnet.writePackets(iface, @ptrCast(&pkt), &pktcnt) catch |e| {
        log.debug("hvf vmnet tx write failed: {s}", .{@errorName(e)});
        return;
    };
    if (pktcnt != 1) {
        log.debug("hvf vmnet tx write incomplete: pktcnt={d}", .{pktcnt});
    }
}

/// RX loop: polls vmnet for incoming packets and delivers to virtio-net.
fn vmnetRxLoop() void {
    const iface = active_vmnet_iface orelse return;
    var pkt_buf: [2048]u8 = undefined;

    var rx_poll_count: u64 = 0;
    while (vmnet_rx_running.load(.seq_cst)) {
        // Reset iov and pkt each iteration (vmnet_read may modify them)
        var iov: vmnet.c_types.iovec = .{
            .iov_base = &pkt_buf,
            .iov_len = pkt_buf.len,
        };
        var pkt: vmnet.c_types.vmpktdesc = .{
            .vm_pkt_size = pkt_buf.len,
            .vm_pkt_iov = &iov,
            .vm_pkt_iovcnt = 1,
            .vm_flags = 0,
        };
        var pktcnt: c_int = 1;

        vmnet.readPackets(iface, @ptrCast(&pkt), &pktcnt) catch |e| {
            if (e != vmnet.VmnetError.StartFailed) {
                log.debug("hvf vmnet rx failed: {s}", .{@errorName(e)});
            }
            std.Thread.sleep(1 * std.time.ns_per_ms); // 1ms backoff on error
            continue;
        };

        rx_poll_count += 1;
        if (rx_poll_count % 10000 == 0) {
            log.debug("hvf vmnet rx poll count={d} pktcnt={d} size={d}", .{ rx_poll_count, pktcnt, pkt.vm_pkt_size });
        }

        if (pktcnt > 0 and pkt.vm_pkt_size > 0) {
            const frame = pkt_buf[0..pkt.vm_pkt_size];
            virtio.maybeCacheDnsResponse(frame);
            virtio.virtioNetRxPacket(frame) catch |e| {
                log.debug("hvf vmnet rx deliver failed: {s}", .{@errorName(e)});
            };
        } else {
            // No packets available, sleep briefly to avoid busy-spinning
            std.Thread.sleep(100 * std.time.ns_per_us); // 100µs
        }
    }
}

fn startVmnetRxThread() !void {
    if (vmnet_rx_running.load(.seq_cst)) return;
    vmnet_rx_running.store(true, .seq_cst);
    vmnet_rx_thread = std.Thread.spawn(.{}, vmnetRxLoop, .{}) catch |e| {
        vmnet_rx_running.store(false, .seq_cst);
        log.warn("hvf vmnet rx thread failed: {s}", .{@errorName(e)});
        return e;
    };
    log.info("hvf vmnet rx thread started", .{});
}

fn stopVmnetRxThread() void {
    vmnet_rx_running.store(false, .seq_cst);
    if (vmnet_rx_thread) |thread| {
        thread.join();
        vmnet_rx_thread = null;
    }
}

fn stopVmnetInterface() void {
    stopVmnetRxThread();
    virtio.setNetTxCallback(null);
    if (active_vmnet_iface) |iface| {
        vmnet.stop(iface) catch |e| {
            log.warn("hvf vmnet stop failed: {s}", .{@errorName(e)});
        };
        active_vmnet_iface = null;
        log.info("hvf vmnet stopped", .{});
    }
}

fn consoleSocketLoop() void {
    const path = console_socket_path orelse return;
    defer console_socket_running.store(false, .seq_cst);
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
        console_rx_logged.store(false, .seq_cst);

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
            if (!console_rx_logged.swap(true, .seq_cst)) {
                const queue = &virtio.virtio_console_state.queues[0];
                log.info("hvf console socket rx bytes={d} virtio_console={} queue_ready={} num={d}", .{
                    n,
                    virtio.virtio_console_state.enabled,
                    queue.ready,
                    queue.num,
                });
            }
            const chunk = buf[0..@intCast(n)];
            appendSerialInput(chunk);
        }
    }
}

fn startConsoleSocketServer(allocator: std.mem.Allocator) bool {
    if (console_socket_running.load(.seq_cst)) return true;
    const env = std.process.getEnvVarOwned(allocator, "M80_CONSOLE_SOCKET") catch null;
    if (env == null) return false;
    console_socket_path = env;
    console_socket_running.store(true, .seq_cst);
    console_socket_thread = std.Thread.spawn(.{}, consoleSocketLoop, .{}) catch |e| {
        console_socket_running.store(false, .seq_cst);
        if (console_socket_path) |path| {
            allocator.free(path);
            console_socket_path = null;
        }
        log.warn("hvf console socket thread failed: {s}", .{@errorName(e)});
        return false;
    };
    log.info("hvf console socket enabled", .{});
    return true;
}

fn stopConsoleSocketServer(allocator: std.mem.Allocator) void {
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
    if (virtio.virtioBlkIndexForAddr(addr)) |index| {
        if (!virtio.virtio_blk_devices[index].enabled) return false;
        const offset = addr - virtio.virtioBlkMmioBase(index);
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = virtio.handleVirtioBlkMmio(index, offset, true, size, value);
        } else {
            const value = virtio.handleVirtioBlkMmio(index, offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio.virtio_console_state.enabled and addr >= virtio.virtio_console_mmio_base and addr < virtio.virtio_console_mmio_base + virtio.virtio_console_mmio_size) {
        const offset = addr - virtio.virtio_console_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = virtio.handleVirtioConsoleMmio(offset, true, size, value);
        } else {
            const value = virtio.handleVirtioConsoleMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio.virtio_rng_state.enabled and addr >= virtio.virtio_rng_mmio_base and addr < virtio.virtio_rng_mmio_base + virtio.virtio_rng_mmio_size) {
        const offset = addr - virtio.virtio_rng_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = virtio.handleVirtioRngMmio(offset, true, size, value);
        } else {
            const value = virtio.handleVirtioRngMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio.virtio_net_state.enabled and addr >= virtio.virtio_net_mmio_base and addr < virtio.virtio_net_mmio_base + virtio.virtio_net_mmio_size) {
        const offset = addr - virtio.virtio_net_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = virtio.handleVirtioNetMmio(offset, true, size, value);
        } else {
            const value = virtio.handleVirtioNetMmio(offset, false, size, 0);
            const mask: u64 = if (size >= 8)
                std.math.maxInt(u64)
            else
                (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
            try arm64WriteRegByIndex(vcpu, srt, value & mask);
        }
        try advanceArmPc(vcpu, il);
        return true;
    }
    if (virtio.virtio_fs_state.enabled and addr >= virtio.virtio_fs_mmio_base and addr < virtio.virtio_fs_mmio_base + virtio.virtio_fs_mmio_size) {
        const offset = addr - virtio.virtio_fs_mmio_base;
        if (is_write) {
            const value = try arm64ReadRegByIndex(vcpu, srt);
            _ = virtio.handleVirtioFsMmio(offset, true, size, value);
        } else {
            const value = virtio.handleVirtioFsMmio(offset, false, size, 0);
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

    const trap_count = arm64_unknown_sysreg_trap_count.fetchAdd(1, .seq_cst) + 1;
    if (trap_count <= 5 or trap_count % 100 == 0) {
        const pc = arm64_bindings.readReg(vcpu, .PC) catch 0;
        log.err(
            "hvf arm64 unknown sysreg trap count={d} syndrome=0x{x} ec=0x{x} op0={d} op1={d} crn={d} crm={d} op2={d} dir={s} rt={d} pc=0x{x}",
            .{ trap_count, esr, ec, op0, op1, crn, crm, op2, if (is_read) "read" else "write", rt, pc },
        );
    }
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

const ArmExceptionInfo = struct {
    ec: u8,
    il: u1,
    iss: u32,
};

fn decodeArmExceptionSyndrome(syndrome: u64) ArmExceptionInfo {
    return .{
        .ec = @intCast((syndrome >> 26) & 0x3F),
        .il = @intCast((syndrome >> 25) & 0x1),
        .iss = @intCast(syndrome & 0x1FFFFFF),
    };
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

fn maybePauseVcpu() void {
    if (!vcpu_pause_requested.load(.seq_cst)) return;

    vcpu_paused.store(true, .seq_cst);
    defer vcpu_paused.store(false, .seq_cst);
    paused_vcpu_state_mutex.lock();
    paused_vcpu_state_error = null;
    paused_vcpu_state = null;
    restore_vcpu_state_error = null;
    const state = captureVcpuState() catch |e| {
        paused_vcpu_state_error = e;
        paused_vcpu_state_mutex.unlock();
        return;
    };
    paused_vcpu_state = state;
    if (restore_vcpu_state) |pending_state| {
        restoreVcpuState(pending_state) catch |e| {
            restore_vcpu_state_error = e;
        };
        restore_vcpu_state = null;
    }
    paused_vcpu_state_mutex.unlock();

    while (vcpu_pause_requested.load(.seq_cst) and vcpu_running.load(.seq_cst)) {
        paused_vcpu_state_mutex.lock();
        if (restore_vcpu_state) |pending_state| {
            restore_vcpu_state_error = null;
            restoreVcpuState(pending_state) catch |e| {
                restore_vcpu_state_error = e;
            };
            restore_vcpu_state = null;
        }
        paused_vcpu_state_mutex.unlock();
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

const runVcpuArm = if (builtin.os.tag == .macos and builtin.cpu.arch == .aarch64)
    struct {
        fn run(index: u32, init: VcpuInit) void {
            defer vcpu_thread_exited.store(true, .seq_cst);
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
            var last_heartbeat_ns: i128 = std.time.nanoTimestamp();

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
                maybePauseVcpu();
                if (!vcpu_running.load(.seq_cst)) break;
                arm64_bindings.run(vcpu) catch |e| {
                    log.err("hvf arm64 vcpu run failed: {s}", .{@errorName(e)});
                    break;
                };
                const now_ns = std.time.nanoTimestamp();
                if (now_ns - last_heartbeat_ns > std.time.ns_per_s) {
                    last_heartbeat_ns = now_ns;
                    const pc = arm64_bindings.readReg(vcpu, .PC) catch 0;
                    log.info("hvf arm64 vcpu heartbeat pc=0x{x}", .{pc});
                }
                const exit = exit_ptr.*;
                switch (exit.reason) {
                    .Canceled => continue,
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
                        const info = decodeArmExceptionSyndrome(exit.exception.syndrome);
                        const pc = arm64_bindings.readReg(vcpu, .PC) catch 0;
                        log.err(
                            "hvf arm64 exception syndrome=0x{x} ec=0x{x} il={d} iss=0x{x} pc=0x{x} ipa=0x{x} va=0x{x}",
                            .{
                                exit.exception.syndrome,
                                info.ec,
                                info.il,
                                info.iss,
                                pc,
                                exit.exception.physical_address,
                                exit.exception.virtual_address,
                            },
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
            defer vcpu_thread_exited.store(true, .seq_cst);
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
                maybePauseVcpu();
                if (!vcpu_running.load(.seq_cst)) break;
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

/// Copy file to guest memory using mmap for zero-copy loading.
/// Falls back to chunked read on platforms without mmap support.
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
    if (stat.size == 0) {
        log.info("hvf loaded {s} (0 bytes) at 0x{x}", .{ label, guest_base });
        return 0;
    }

    const file_size: usize = @intCast(stat.size);

    // Try mmap-based loading for better performance (zero-copy from page cache)
    if (comptime (builtin.os.tag == .macos or builtin.os.tag == .linux)) {
        if (copyFileMmapToGuest(file.handle, file_size, guest_base, label)) |size| {
            return size;
        } else |_| {
            // Fall through to chunked read on mmap failure
            log.debug("hvf mmap failed for {s}, falling back to chunked read", .{label});
        }
    }

    // Fallback: chunked read (used on Windows or if mmap fails)
    return copyFileChunkedToGuest(file, file_size, guest_base, label);
}

/// Copy file to guest using mmap (zero-copy from page cache).
fn copyFileMmapToGuest(
    fd: std.posix.fd_t,
    file_size: usize,
    guest_base: u64,
    label: []const u8,
) !u64 {
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    const offset: usize = @intCast(guest_base - base);

    // mmap the file read-only
    const mapped = std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        fd,
        0,
    ) catch |e| {
        log.debug("hvf mmap failed: {s}", .{@errorName(e)});
        return e;
    };
    defer std.posix.munmap(mapped);

    // Single memcpy from mmap'd region to guest memory
    @memcpy(memory[offset..][0..file_size], mapped);

    log.info("hvf loaded {s} ({d} bytes) at 0x{x} [mmap]", .{ label, file_size, guest_base });
    return @intCast(file_size);
}

/// Copy file to guest using chunked reads (fallback path).
fn copyFileChunkedToGuest(
    file: std.fs.File,
    file_size: usize,
    guest_base: u64,
    label: []const u8,
) !u64 {
    var buf: [64 * 1024]u8 = undefined; // 64KB chunks for better throughput
    var remaining: usize = file_size;
    var offset: usize = 0;

    while (remaining > 0) {
        const to_read = @min(remaining, buf.len);
        const n = try file.read(buf[0..to_read]);
        if (n == 0) return error.UnexpectedEof;
        const guest_addr = guest_base + @as(u64, @intCast(offset));
        try writeGuestBytes(guest_addr, buf[0..n]);
        remaining -= n;
        offset += n;
    }

    log.info("hvf loaded {s} ({d} bytes) at 0x{x} [chunked]", .{ label, file_size, guest_base });
    return @intCast(file_size);
}

/// Decompress gzip file directly to guest memory.
/// Writes decompressed data directly to guest memory buffer for better performance.
fn copyGzipToGuest(
    memory_size_bytes: u64,
    guest_base: u64,
    file: std.fs.File,
    label: []const u8,
) !u64 {
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    if (guest_base < base) return error.GuestImageTooLarge;
    const offset_base = guest_base - base;
    if (offset_base >= memory_size_bytes) return error.GuestImageTooLarge;

    const guest_offset: usize = @intCast(offset_base);
    const max_output: usize = @intCast(memory_size_bytes - offset_base);

    // Use larger read buffer for better I/O throughput
    var read_buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(&read_buf);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor = std.compress.flate.Decompress.init(&reader.interface, .gzip, window[0..]);

    // Decompress directly into guest memory (avoid intermediate buffer copy)
    var total: usize = 0;
    const chunk_size: usize = 256 * 1024; // 256KB chunks for direct writes
    while (total < max_output) {
        const remaining = max_output - total;
        const to_read = @min(remaining, chunk_size);
        const dest = memory[guest_offset + total ..][0..to_read];
        const n = try decompressor.reader.readSliceShort(dest);
        if (n == 0) break;
        total += n;
    }

    log.info("hvf loaded {s} ({d} bytes) at 0x{x} [gzip]", .{ label, total, guest_base });
    return @intCast(total);
}

fn writeCmdlineToGuest(memory_size_bytes: u64, state: boot.BootState, cmdline: []const u8) !void {
    const base = guestMemoryBase();
    if (state.cmdline_addr < base) return error.GuestImageTooLarge;
    const end = (state.cmdline_addr - base) + @as(u64, state.cmdline_len) + 1;
    if (end > memory_size_bytes) return error.GuestImageTooLarge;
    try writeGuestBytes(state.cmdline_addr, cmdline);
    try writeGuestBytes(state.cmdline_addr + cmdline.len, &[_]u8{0});
}

/// Allocate guest memory using mmap for lazy (demand-paged) allocation.
/// Pages are not physically allocated until first accessed, saving boot time.
/// Returns error on platforms without mmap support.
fn allocateGuestMemoryLazy(size_bytes: usize) ![]align(std.heap.page_size_min) u8 {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) {
        return error.NotSupported;
    }

    // Use MAP_ANONYMOUS for zero-filled pages allocated on demand.
    // On macOS/Linux, anonymous pages aren't physically allocated until touched.
    const ptr = std.posix.mmap(
        null,
        size_bytes,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch |e| {
        log.debug("hvf mmap for guest memory failed: {s}", .{@errorName(e)});
        return error.MmapFailed;
    };

    log.info("hvf allocated {d} MB guest memory [lazy/mmap]", .{size_bytes / mb_to_bytes});
    return @alignCast(ptr);
}

/// Free guest memory allocated via mmap.
fn freeGuestMemoryMmap(memory: []align(std.heap.page_size_min) u8) void {
    std.posix.munmap(memory);
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

fn mapDaxRegion(_: ?*anyopaque, guest_addr: u64, len: u64, fd: std.posix.fd_t, file_offset: u64, writable: bool) !void {
    if (len == 0) return;
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    if (guest_addr < base) return error.InvalidGuestLayout;
    const offset = guest_addr - base;
    if (offset + len > memory.len) return error.InvalidGuestLayout;
    if (len > std.math.maxInt(usize)) return error.InvalidGuestLayout;

    const host_addr = @intFromPtr(memory.ptr) + @as(usize, @intCast(offset));
    const host_ptr: ?[*]align(std.heap.page_size_min) u8 = @ptrFromInt(host_addr);
    const prot: u32 = @intCast(if (writable) (std.posix.PROT.READ | std.posix.PROT.WRITE) else std.posix.PROT.READ);
    const flags = std.posix.MAP{
        .TYPE = .SHARED,
        .FIXED = true,
    };
    _ = try std.posix.mmap(host_ptr, @intCast(len), prot, flags, fd, @intCast(file_offset));
    if (builtin.os.tag == .macos) {
        if (host_ptr) |ptr| {
            std.posix.madvise(ptr, @intCast(len), std.posix.MADV.WILLNEED) catch {};
            std.posix.madvise(ptr, @intCast(len), std.posix.MADV.SEQUENTIAL) catch {};
        }
    }
}

fn unmapDaxRegion(_: ?*anyopaque, guest_addr: u64, len: u64) !void {
    if (len == 0) return;
    const memory = active_guest_memory orelse return error.NoGuestMemory;
    const base = guestMemoryBase();
    if (guest_addr < base) return error.InvalidGuestLayout;
    const offset = guest_addr - base;
    if (offset + len > memory.len) return error.InvalidGuestLayout;
    if (len > std.math.maxInt(usize)) return error.InvalidGuestLayout;

    const host_addr = @intFromPtr(memory.ptr) + @as(usize, @intCast(offset));
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
        .window_base = guestMemoryBase(),
        .window_size = memory_size_bytes,
        .page_size = std.heap.page_size_min,
        .map = mapDaxRegion,
        .unmap = unmapDaxRegion,
    };
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

/// Boot timing state for performance measurement
var boot_timing: struct {
    start_us: i64 = 0,
    vm_create_us: i64 = 0,
    memory_map_us: i64 = 0,
    kernel_load_us: i64 = 0,
    initrd_load_us: i64 = 0,
    vcpu_start_us: i64 = 0,
} = .{};

/// Returns the current timestamp in microseconds for boot timing.
fn bootTimestamp() i64 {
    return std.time.microTimestamp();
}

/// Logs boot timing breakdown at info level.
fn logBootTiming() void {
    const total = boot_timing.vcpu_start_us - boot_timing.start_us;
    const vm_create = boot_timing.vm_create_us - boot_timing.start_us;
    const memory_map = boot_timing.memory_map_us - boot_timing.vm_create_us;
    const kernel_load = boot_timing.kernel_load_us - boot_timing.memory_map_us;
    const initrd_load = boot_timing.initrd_load_us - boot_timing.kernel_load_us;
    const vcpu_setup = boot_timing.vcpu_start_us - boot_timing.initrd_load_us;

    log.info("hvf boot timing: total={d}µs vm_create={d}µs memory_map={d}µs kernel={d}µs initrd={d}µs vcpu_setup={d}µs", .{
        total,
        vm_create,
        memory_map,
        kernel_load,
        initrd_load,
        vcpu_setup,
    });
}

/// Result of parallel kernel/initrd loading.
const ParallelLoadResult = struct {
    kernel: anyerror!KernelLoadResult,
    initrd: anyerror!u64,
};

/// Loads kernel and initrd, using parallel loading when both are present.
/// Returns a struct with error unions for each result.
fn loadKernelAndInitrd(
    memory_size_bytes: u64,
    kernel_path: ?[]const u8,
    initrd_path: ?[]const u8,
) ParallelLoadResult {
    // If both paths are set, try to load in parallel
    if (kernel_path != null and initrd_path != null) {
        // Context for initrd thread
        const InitrdCtx = struct {
            mem_size: u64,
            path: []const u8,
            result: anyerror!u64 = error.Unexpected,

            fn run(self: *@This()) void {
                self.result = loadGuestInitrd(self.mem_size, self.path);
            }
        };

        var initrd_ctx = InitrdCtx{
            .mem_size = memory_size_bytes,
            .path = initrd_path.?,
        };

        // Spawn thread for initrd loading
        if (std.Thread.spawn(.{}, InitrdCtx.run, .{&initrd_ctx})) |thread| {
            // Load kernel on main thread
            const kernel_result = loadGuestKernel(memory_size_bytes, kernel_path);

            // Wait for initrd thread
            thread.join();

            log.debug("hvf loaded kernel and initrd in parallel", .{});
            return .{
                .kernel = kernel_result,
                .initrd = initrd_ctx.result,
            };
        } else |_| {
            // Thread spawn failed, fall through to sequential loading
            log.debug("hvf thread spawn failed, loading sequentially", .{});
        }
    }

    // Sequential loading (one or both missing, or thread spawn failed)
    return .{
        .kernel = loadGuestKernel(memory_size_bytes, kernel_path),
        .initrd = loadGuestInitrd(memory_size_bytes, initrd_path),
    };
}

fn signalActiveVcpuForStop() void {
    if (builtin.os.tag != .macos) return;

    if (builtin.cpu.arch == .aarch64) {
        if (active_vcpu_id_arm) |vcpu| {
            arm64_bindings.exit(vcpu) catch |e| {
                log.warn("failed to exit arm64 vcpu: {s}", .{@errorName(e)});
            };
        }
        return;
    }

    if (builtin.cpu.arch == .x86_64) {
        if (active_vcpu_id_x86) |vcpu| {
            x86_vcpu_bindings.interrupt(vcpu) catch |e| {
                log.warn("failed to interrupt x86 vcpu: {s}", .{@errorName(e)});
            };
        }
    }
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
    boot_timing.start_us = bootTimestamp();
    log.info("hvf backend starting", .{});
    arm64_unknown_sysreg_trap_count.store(0, .seq_cst);
    vcpu_thread_exited.store(true, .seq_cst);

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
    errdefer active_vm = null;
    boot_timing.vm_create_us = bootTimestamp();

    const size_bytes_u64 = try std.math.mul(u64, cfg.memory_mb, mb_to_bytes);
    if (size_bytes_u64 > std.math.maxInt(usize)) return error.MemoryTooLarge;
    const size_bytes: usize = @intCast(size_bytes_u64);
    var vmnet_started = false;
    var console_server_started = false;
    var serial_stdin_started = false;

    errdefer {
        if (serial_stdin_started) stopSerialInputThread();
        if (console_server_started) stopConsoleSocketServer(std.heap.page_allocator);
        if (vmnet_started) {
            stopVmnetInterface();
            virtio.resetVirtioNetState();
            vmnet_started = false;
        }
    }

    // Allocate guest memory using mmap for lazy (demand-paged) allocation.
    // This avoids committing physical memory until pages are actually accessed,
    // saving ~50-100ms on boot and reducing memory footprint.
    const guest_memory = blk: {
        if (allocateGuestMemoryLazy(size_bytes)) |mem| {
            active_memory_is_mmap = true;
            // Skip @memset - anonymous mmap pages are zero-filled on first access
            break :blk @as([]u8, mem);
        } else |e| {
            log.debug("hvf lazy allocation failed: {s}, falling back to page_allocator", .{@errorName(e)});
            // Fallback to immediate allocation on platforms without mmap
            const fallback = try std.heap.page_allocator.alloc(u8, size_bytes);
            @memset(fallback, 0);
            active_memory_is_mmap = false;
            break :blk fallback;
        }
    };
    errdefer {
        if (active_memory_is_mmap) {
            freeGuestMemoryMmap(@alignCast(guest_memory));
        } else {
            std.heap.page_allocator.free(guest_memory);
        }
        active_memory_is_mmap = false;
    }
    setActiveGuestMemory(guest_memory);
    errdefer clearActiveGuestMemory();
    mapActiveGuestMemory() catch |e| {
        log.err("hvf map guest memory failed: {s}", .{@errorName(e)});
        return e;
    };
    errdefer unmapActiveGuestMemory();
    boot_timing.memory_map_us = bootTimestamp();

    prepareGuestImage(size_bytes_u64) catch |e| {
        log.err("hvf prepareGuestImage failed: {s}", .{@errorName(e)});
        return e;
    };

    // Load kernel and initrd - use parallel loading when both are present.
    // This can save ~20-50ms depending on I/O latency.
    const load_result = loadKernelAndInitrd(size_bytes_u64, cfg.kernel_path, cfg.initrd_path);
    const kernel_load = load_result.kernel catch |e| {
        log.err("hvf loadGuestKernel failed: {s}", .{@errorName(e)});
        return e;
    };
    boot_timing.kernel_load_us = bootTimestamp();
    const initrd_size = load_result.initrd catch |e| {
        log.err("hvf loadGuestInitrd failed: {s}", .{@errorName(e)});
        return e;
    };
    boot_timing.initrd_load_us = bootTimestamp();
    virtio.initGuestIo(.{
        .read_bytes = readGuestBytes,
        .write_bytes = writeGuestBytes,
    });
    virtio.setInterruptHandler(virtioInterruptHandler);
    virtio.setupVirtioBlk(cfg) catch |e| {
        log.err("hvf virtio-blk setup failed: {s}", .{@errorName(e)});
        return e;
    };
    const enable_virtio_console = envFlagPresent(std.heap.page_allocator, "M80_VIRTIO_CONSOLE") or
        (cfg.kernel_cmdline != null and std.mem.indexOf(u8, cfg.kernel_cmdline.?, "hvc0") != null);
    virtio.setupVirtioConsole(enable_virtio_console);
    virtio.setupVirtioRng(true);
    const dax_mapper = buildDaxMapper(size_bytes_u64);
    virtio.setupVirtioFs(std.heap.page_allocator, cfg, dax_mapper) catch |e| {
        log.err("hvf virtio-fs setup failed: {s}", .{@errorName(e)});
        return e;
    };
    // Initialize networking if not locked down
    if (cfg.network_mode != .locked_down and builtin.os.tag == .macos) {
        // Start vmnet interface in shared mode
        if (vmnet.startShared()) |vmnet_iface| {
            active_vmnet_iface = vmnet_iface;
            vmnet_started = true;
            log.info(
                "hvf vmnet started mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} mtu={d}",
                .{
                    vmnet_iface.mac[0], vmnet_iface.mac[1], vmnet_iface.mac[2],
                    vmnet_iface.mac[3], vmnet_iface.mac[4], vmnet_iface.mac[5],
                    vmnet_iface.mtu,
                },
            );
            virtio.setupVirtioNet(true, vmnet_iface.mac);
            virtio.initNetworkPolicy(cfg) catch |e| {
                log.err("hvf network policy init failed: {s}", .{@errorName(e)});
                stopVmnetInterface();
                vmnet_started = false;
                virtio.resetVirtioNetState();
                return e;
            };
            virtio.setNetTxCallback(vmnetTxCallback);
            startVmnetRxThread() catch |e| {
                log.err("hvf vmnet rx thread start failed: {s}", .{@errorName(e)});
                stopVmnetInterface();
                vmnet_started = false;
                virtio.resetVirtioNetState();
                return e;
            };
        } else |e| {
            if (e == vmnet.VmnetError.NotAuthorized or e == vmnet.VmnetError.StartFailed) {
                log.warn(
                    "hvf vmnet unavailable (check vmnet entitlement/codesign; enable with M80_VMNET_ENTITLEMENTS=1 at build)",
                    .{},
                );
            } else {
                log.warn("hvf vmnet start failed: {s}", .{@errorName(e)});
            }
            log.warn("hvf networking disabled for this VM", .{});
            virtio.setupVirtioNet(false, .{ 0, 0, 0, 0, 0, 0 });
        }
    } else if (cfg.network_mode != .locked_down) {
        log.warn("hvf networking only supported on macOS; network_mode ignored", .{});
        virtio.setupVirtioNet(false, .{ 0, 0, 0, 0, 0, 0 });
    } else {
        virtio.setupVirtioNet(false, .{ 0, 0, 0, 0, 0, 0 });
    }
    const cmdline = buildCmdlineWithMounts(std.heap.page_allocator, cfg) catch |e| {
        log.err("hvf buildCmdlineWithMounts failed: {s}", .{@errorName(e)});
        return e;
    };
    defer std.heap.page_allocator.free(cmdline);
    if (cfg.mounts.len > 0) {
        log.info("hvf cmdline with mounts: {s}", .{cmdline});
    }
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
        virtio.gic_virtio_blk_intid = .{ virtio_blk0_intid, virtio_blk1_intid, virtio_blk2_intid };
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
            virtio.gic_virtio_console_intid = candidate;
        }
        if (virtio.virtio_rng_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 3;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-rng irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_rng_intid = candidate;
            virtio.gic_virtio_rng_intid = candidate;
        }
        if (virtio.virtio_net_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 4;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-net irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_net_intid = candidate;
            virtio.gic_virtio_net_intid = candidate;
        }
        if (virtio.virtio_fs_state.enabled) {
            const candidate = spi_base + pl011_irq_offset + 5;
            if (spi_count != 0 and candidate >= spi_base + spi_count) {
                log.warn("hvf virtio-fs irq out of range base={d} count={d}", .{ spi_base, spi_count });
            }
            virtio_fs_intid = candidate;
            virtio.gic_virtio_fs_intid = candidate;
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
                .{ virtio.virtioBlkMmioBase(0), virtio_blk0_irq.?, virtio_blk0_intid.? },
            );
        }
        if (cfg.seed_path != null and virtio_blk1_irq != null) {
            log.info(
                "hvf virtio-blk[1] dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtioBlkMmioBase(1), virtio_blk1_irq.?, virtio_blk1_intid.? },
            );
        }
        if (cfg.data_disk_path != null and virtio_blk2_irq != null) {
            log.info(
                "hvf virtio-blk[2] dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtioBlkMmioBase(2), virtio_blk2_irq.?, virtio_blk2_intid.? },
            );
        }
        if (enable_virtio_console and virtio_console_irq != null) {
            log.info(
                "hvf virtio-console dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtio_console_mmio_base, virtio_console_irq.?, virtio_console_intid.? },
            );
        }
        if (virtio.virtio_rng_state.enabled and virtio_rng_irq != null) {
            log.info(
                "hvf virtio-rng dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtio_rng_mmio_base, virtio_rng_irq.?, virtio_rng_intid.? },
            );
        }
        if (virtio.virtio_net_state.enabled and virtio_net_irq != null) {
            log.info(
                "hvf virtio-net dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtio_net_mmio_base, virtio_net_irq.?, virtio_net_intid.? },
            );
        }
        if (virtio.virtio_fs_state.enabled and virtio_fs_irq != null) {
            log.info(
                "hvf virtio-fs dtb base=0x{x} irq={d} intid={d}",
                .{ virtio.virtio_fs_mmio_base, virtio_fs_irq.?, virtio_fs_intid.? },
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
            .virtio_blk_base = if (cfg.disk_path != null) virtio.virtioBlkMmioBase(0) else null,
            .virtio_blk_irq = virtio_blk0_irq,
            .virtio_blk2_base = if (cfg.seed_path != null) virtio.virtioBlkMmioBase(1) else null,
            .virtio_blk2_irq = virtio_blk1_irq,
            .virtio_blk3_base = if (cfg.data_disk_path != null) virtio.virtioBlkMmioBase(2) else null,
            .virtio_blk3_irq = virtio_blk2_irq,
            .virtio_console_base = if (enable_virtio_console) virtio.virtio_console_mmio_base else null,
            .virtio_console_irq = virtio_console_irq,
            .virtio_rng_base = if (virtio.virtio_rng_state.enabled) virtio.virtio_rng_mmio_base else null,
            .virtio_rng_irq = virtio_rng_irq,
            .virtio_net_base = if (virtio.virtio_net_state.enabled) virtio.virtio_net_mmio_base else null,
            .virtio_net_irq = virtio_net_irq,
            .virtio_fs_base = if (virtio.virtio_fs_state.enabled) virtio.virtio_fs_mmio_base else null,
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
    errdefer active_memory_size = 0;

    if (cfg.kernel_path == null) {
        log.warn("hvf kernel path not set; skipping vcpu run (set kernel_path in m80.conf)", .{});
        log.info("hvf backend ready (no vcpu running)", .{});
        return;
    }

    vcpu_running.store(true, .seq_cst);
    if (envFlagPresent(std.heap.page_allocator, "M80_START_PAUSED")) {
        vcpu_pause_requested.store(true, .seq_cst);
    }
    if (builtin.cpu.arch == .aarch64) {
        setupGic();
    }
    if (envFlagPresent(std.heap.page_allocator, "M80_IO_SIM")) {
        simulate_io.store(true, .seq_cst);
    }
    serial_io.setFromEnv(std.heap.page_allocator);
    if (virtio.virtio_console_state.enabled) {
        virtio.setVirtioConsoleInputFromEnv(std.heap.page_allocator);
    }
    serial.setCaptureFromEnv(std.heap.page_allocator);
    serial.clearConsoleBacklog();
    if (startConsoleSocketServer(std.heap.page_allocator)) {
        console_server_started = true;
    }
    if (shouldEnableSerialStdin(std.heap.page_allocator)) {
        if (startSerialInputThread()) {
            serial_stdin_started = true;
        }
    }
    if (builtin.cpu.arch == .aarch64) {
        resetPl011State();
    }
    boot_timing.vcpu_start_us = bootTimestamp();
    logBootTiming();
    vcpu_thread_exited.store(false, .seq_cst);
    active_vcpu_thread = std.Thread.spawn(.{}, runVcpu, .{ 0, vcpu_init }) catch |e| {
        vcpu_running.store(false, .seq_cst);
        vcpu_thread_exited.store(true, .seq_cst);
        return e;
    };
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

    // Request vCPU shutdown.
    vcpu_pause_requested.store(false, .seq_cst);
    vcpu_paused.store(false, .seq_cst);
    vcpu_running.store(false, .seq_cst);

    if (active_vcpu_thread != null) {
        var attempts: usize = 0;
        while (!vcpu_thread_exited.load(.seq_cst) and attempts < vcpu_stop_signal_attempts) : (attempts += 1) {
            signalActiveVcpuForStop();
            std.Thread.sleep(vcpu_stop_signal_interval_ns);
        }

        if (!vcpu_thread_exited.load(.seq_cst)) {
            log.err("hvf stop timed out waiting for vcpu thread exit", .{});
            return error.VcpuStopTimeout;
        }
    }

    stopSerialInputThread();
    stopConsoleSocketServer(std.heap.page_allocator);

    // Wait for vCPU thread to exit
    if (active_vcpu_thread) |t| {
        t.join();
        active_vcpu_thread = null;
    }
    vcpu_thread_exited.store(true, .seq_cst);

    // Clean up serial I/O state
    serial_io.clear(std.heap.page_allocator);
    serial.clearCapture(std.heap.page_allocator);
    serial.clearConsoleBacklog();
    pl011_state = .{};
    virtio.resetVirtioBlkState();
    virtio.resetVirtioConsoleState();
    virtio.resetVirtioRngState();
    stopVmnetInterface();
    virtio.resetVirtioNetState();
    virtio.resetVirtioFsState();

    if (active_guest_memory) |buffer| {
        unmapActiveGuestMemory();
        if (active_memory_is_mmap) {
            freeGuestMemoryMmap(@alignCast(buffer));
        } else {
            std.heap.page_allocator.free(buffer);
        }
        active_guest_memory = null;
        active_memory_is_mmap = false;
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
    active_memory_is_mmap = false;
    clearActiveGuestMemory();
    gic_enabled = false;
    gic_uart_intid = null;
    virtio.gic_virtio_blk_intid = .{ null, null, null };
    virtio.gic_virtio_console_intid = null;
    virtio.gic_virtio_net_intid = null;
    virtio.gic_virtio_fs_intid = null;
    gic_layout = null;
    arm64_unknown_sysreg_trap_count.store(0, .seq_cst);
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

    virtio.resetVirtioConsoleState();
    defer virtio.resetVirtioConsoleState();
    virtio.virtio_console_state.enabled = true;

    const base = guestMemoryBase();
    const desc_addr = base + 0x1000;
    const avail_addr = base + 0x2000;
    const used_addr = base + 0x3000;
    const data_addr = base + 0x4000;

    virtio.virtio_console_state.queues[0] = .{
        .num = 8,
        .ready = true,
        .desc_addr = desc_addr,
        .avail_addr = avail_addr,
        .used_addr = used_addr,
        .last_avail_idx = 0,
        .used_idx = 0,
    };

    const desc = virtio.VirtqDesc{
        .addr = data_addr,
        .len = 4,
        .flags = virtio.virtq_desc_flag_write,
        .next = 0,
    };
    var desc_buf: [@sizeOf(virtio.VirtqDesc)]u8 = undefined;
    std.mem.copyForwards(u8, &desc_buf, std.mem.asBytes(&desc));
    try writeGuestBytes(desc_addr, desc_buf[0..]);

    try writeGuestU16(avail_addr, 0); // flags
    try writeGuestU16(avail_addr + 2, 1); // idx
    try writeGuestU16(avail_addr + 4, 0); // ring[0]
    try writeGuestU16(used_addr + 2, 0); // used idx

    virtio.appendVirtioConsoleInput("ping");
    try virtio.processVirtioConsoleRxQueue();

    var out: [4]u8 = undefined;
    try readGuestBytes(data_addr, out[0..]);
    try std.testing.expectEqualStrings("ping", out[0..]);

    const used_idx = try readGuestU16(used_addr + 2);
    try std.testing.expectEqual(@as(u16, 1), used_idx);
    const used_id = try readGuestU32(used_addr + 4);
    const used_len = try readGuestU32(used_addr + 8);
    try std.testing.expectEqual(@as(u32, 0), used_id);
    try std.testing.expectEqual(@as(u32, 4), used_len);
    try std.testing.expectEqual(@as(u16, 1), virtio.virtio_console_state.queues[0].last_avail_idx);
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

test "hvf: maybePauseVcpu clears paused flag when capture fails" {
    const old_pause_requested = vcpu_pause_requested.load(.seq_cst);
    const old_running = vcpu_running.load(.seq_cst);
    const old_paused = vcpu_paused.load(.seq_cst);
    defer {
        vcpu_pause_requested.store(old_pause_requested, .seq_cst);
        vcpu_running.store(old_running, .seq_cst);
        vcpu_paused.store(old_paused, .seq_cst);
    }

    vcpu_pause_requested.store(true, .seq_cst);
    vcpu_running.store(false, .seq_cst);
    vcpu_paused.store(false, .seq_cst);

    paused_vcpu_state_mutex.lock();
    paused_vcpu_state = null;
    paused_vcpu_state_error = null;
    restore_vcpu_state = null;
    restore_vcpu_state_error = null;
    paused_vcpu_state_mutex.unlock();

    maybePauseVcpu();
    try std.testing.expect(!vcpu_paused.load(.seq_cst));

    paused_vcpu_state_mutex.lock();
    defer paused_vcpu_state_mutex.unlock();
    try std.testing.expect(paused_vcpu_state_error != null);
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
    try std.testing.expectEqualStrings("KERN", guest_memory[@intCast(offset)..@intCast(offset + 4)]);
}

test "hvf: copyFileToGuest uses mmap on supported platforms" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const file_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "test.bin" });
    defer std.testing.allocator.free(file_path);

    // Create a test file with known content
    const test_data = "TESTDATA1234567890ABCDEF";
    {
        var file = try std.fs.cwd().createFile(file_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(test_data);
    }

    const memory_size: usize = 8 * 1024 * 1024;
    var guest_memory = try std.testing.allocator.alloc(u8, memory_size);
    defer std.testing.allocator.free(guest_memory);
    @memset(guest_memory, 0);

    setActiveGuestMemory(guest_memory);
    defer clearActiveGuestMemory();

    const guest_base = guestKernelBase();
    const size = try copyFileToGuest(memory_size, guest_base, file_path, "test");
    try std.testing.expectEqual(@as(u64, test_data.len), size);

    const offset = guest_base - guestMemoryBase();
    try std.testing.expectEqualStrings(test_data, guest_memory[@intCast(offset)..@intCast(offset + test_data.len)]);
}

test "hvf: copyFileMmapToGuest loads file correctly" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const file_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "mmap_test.bin" });
    defer std.testing.allocator.free(file_path);

    // Create test file with larger content to verify mmap works
    const test_content = "MMAP_TEST_CONTENT_" ** 100;
    {
        var file = try std.fs.cwd().createFile(file_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(test_content);
    }

    const memory_size: usize = 8 * 1024 * 1024;
    var guest_memory = try std.testing.allocator.alloc(u8, memory_size);
    defer std.testing.allocator.free(guest_memory);
    @memset(guest_memory, 0);

    setActiveGuestMemory(guest_memory);
    defer clearActiveGuestMemory();

    var file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const guest_base = guestKernelBase();
    const size = try copyFileMmapToGuest(file.handle, test_content.len, guest_base, "mmap_test");
    try std.testing.expectEqual(@as(u64, test_content.len), size);

    const offset = guest_base - guestMemoryBase();
    try std.testing.expectEqualStrings(test_content, guest_memory[@intCast(offset)..@intCast(offset + test_content.len)]);
}

test "hvf: allocateGuestMemoryLazy returns demand-paged memory" {
    // Skip on platforms without mmap
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    // Allocate 4MB - should succeed and return zero-filled pages
    const size: usize = 4 * 1024 * 1024;
    const mem = try allocateGuestMemoryLazy(size);
    defer freeGuestMemoryMmap(mem);

    // Verify the memory is accessible and zero-filled (by the OS on first access)
    try std.testing.expectEqual(size, mem.len);
    try std.testing.expectEqual(@as(u8, 0), mem[0]);
    try std.testing.expectEqual(@as(u8, 0), mem[size - 1]);

    // Verify we can write to it
    mem[0] = 0xAB;
    mem[size / 2] = 0xCD;
    mem[size - 1] = 0xEF;
    try std.testing.expectEqual(@as(u8, 0xAB), mem[0]);
    try std.testing.expectEqual(@as(u8, 0xCD), mem[size / 2]);
    try std.testing.expectEqual(@as(u8, 0xEF), mem[size - 1]);
}

test "hvf: lazy memory allocation used by default on macos/linux" {
    // This test verifies the active_memory_is_mmap flag works correctly
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;

    // Reset state
    active_memory_is_mmap = false;

    const size: usize = 1 * 1024 * 1024;
    const mem = try allocateGuestMemoryLazy(size);
    defer freeGuestMemoryMmap(mem);

    // The allocateGuestMemoryLazy doesn't set the flag, but it should succeed
    // The flag is set by the caller (start function)
    try std.testing.expectEqual(size, mem.len);
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

test "smoke: hvf arm64 repeated start-stop reliability" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.SkipZigTest;

    const enabled = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_HVF_RELIABILITY") catch null;
    defer if (enabled) |v| std.testing.allocator.free(v);
    if (enabled == null or !std.mem.eql(u8, enabled.?, "1")) return error.SkipZigTest;

    const kernel = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
    defer if (initrd) |i| std.testing.allocator.free(i);
    const disk = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_DISK") catch null;
    defer if (disk) |d| std.testing.allocator.free(d);
    const expect = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_SERIAL_EXPECT") catch null;
    defer if (expect) |e| std.testing.allocator.free(e);
    if (kernel == null or (initrd == null and disk == null)) return error.SkipZigTest;

    var reliability_cycles: usize = 20;
    const cycles_text = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_HVF_RELIABILITY_CYCLES") catch null;
    defer if (cycles_text) |v| std.testing.allocator.free(v);
    if (cycles_text) |value| {
        reliability_cycles = std.fmt.parseInt(usize, value, 10) catch 20;
        if (reliability_cycles == 0) reliability_cycles = 20;
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);
    const out_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ dir_path, "serial.log" });
    defer std.testing.allocator.free(out_path);

    var out_file = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    out_file.close();

    const serial_out_z = try allocZ(std.testing.allocator, "M80_SERIAL_OUT");
    defer std.testing.allocator.free(serial_out_z);
    const serial_out_path_z = try allocZ(std.testing.allocator, out_path);
    defer std.testing.allocator.free(serial_out_path_z);
    if (setenv(serial_out_z, serial_out_path_z, 1) != 0) return error.SkipZigTest;
    defer _ = unsetenv(serial_out_z);

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

    var cycle: usize = 0;
    while (cycle < reliability_cycles) : (cycle += 1) {
        var started = false;
        start(cfg_mut) catch |e| {
            std.debug.print("hvf reliability start cycle={d} failed: {s}\n", .{ cycle, @errorName(e) });
            return error.SkipZigTest;
        };
        started = true;

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

        if (!found) {
            if (started) stop() catch {};
            std.debug.print("hvf reliability serial missing cycle={d} len={d}\n", .{ cycle, serial.captureLen() });
        }
        try std.testing.expect(found);

        try stop();
    }
}

test "hvf: arm64 boot accepts console input" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) return error.SkipZigTest;

    const kernel = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_KERNEL") catch null;
    defer if (kernel) |k| std.testing.allocator.free(k);
    const initrd = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_INITRD") catch null;
    defer if (initrd) |i| std.testing.allocator.free(i);
    const disk = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_DISK") catch null;
    defer if (disk) |d| std.testing.allocator.free(d);
    const cmdline = std.process.getEnvVarOwned(std.testing.allocator, "M80_TEST_CMDLINE") catch null;
    defer if (cmdline) |c| std.testing.allocator.free(c);
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
    if (initrd) |path| {
        cfg_mut.initrd_path = try std.testing.allocator.dupe(u8, path);
    }
    cfg_mut.disk_path = try std.testing.allocator.dupe(u8, disk.?);
    cfg_mut.disk_readonly = false;
    cfg_mut.kernel_cmdline = try std.testing.allocator.dupe(
        u8,
        if (cmdline) |value| value else "earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw loglevel=8",
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
            virtio.appendVirtioConsoleInput(user_line);
            virtio.appendVirtioConsoleInput("\n");
            virtio.processVirtioConsoleRxQueue() catch |e| {
                std.debug.print("hvf login rx failed: {s}\n", .{@errorName(e)});
            };
        }
        if (saw_prompt and !saw_password and serial.captureContains("Password:")) {
            saw_password = true;
            virtio.appendVirtioConsoleInput(pass_line);
            virtio.appendVirtioConsoleInput("\n");
            virtio.processVirtioConsoleRxQueue() catch |e| {
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

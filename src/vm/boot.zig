//! VM Boot State Configuration
//!
//! This module computes the initial CPU state for booting a Linux guest.
//! It follows the Linux x86-64 boot protocol for setting up registers
//! before jumping to the kernel entry point.
//!
//! ## Linux Boot Protocol (simplified)
//! When the kernel starts executing, it expects:
//! - RIP: Kernel entry point (typically 0x100000 for bzImage)
//! - RSP: Valid stack pointer (top of memory, 16-byte aligned)
//! - RSI: Pointer to command line string
//! - RFLAGS: Interrupts disabled (0x2)
//!
//! ## Memory Layout Validation
//! This module validates that:
//! - Kernel base is within guest memory
//! - Command line fits in memory
//! - Stack doesn't overlap with command line
//! - Minimum memory size requirements are met

const std = @import("std");

/// Computed boot state containing addresses and sizes.
/// Used by hypervisor backends to set up initial guest state.
pub const BootState = struct {
    /// Kernel entry point (where RIP should start)
    entry: u64,
    /// Stack top address (16-byte aligned, near top of memory)
    stack_top: u64,
    /// Guest physical address of the command line string
    cmdline_addr: u64,
    /// Length of command line (excluding null terminator)
    cmdline_len: u32,
};

/// Initial x86-64 register values for VM boot.
pub const BootRegs = struct {
    /// Instruction pointer - kernel entry point
    rip: u64,
    /// Stack pointer - top of stack
    rsp: u64,
    /// Flags register - 0x2 = interrupts disabled
    rflags: u64,
    /// RSI register - pointer to boot parameters/command line
    rsi: u64,
};

/// Computes the boot state given memory layout parameters.
///
/// Validates that all addresses fit within guest memory and
/// that the layout is valid (kernel base < initrd base, etc.).
///
/// Parameters:
///   - memory_size_bytes: Total guest RAM size
///   - guest_kernel_base: Where kernel is loaded
///   - guest_cmdline_base: Where command line is stored
///   - cmdline: Kernel command line string
///
/// Returns: BootState with computed addresses
///
/// Errors:
///   - error.InvalidGuestLayout: Addresses exceed memory or overlap
pub fn computeBootState(
    memory_size_bytes: u64,
    guest_kernel_base: u64,
    guest_cmdline_base: u64,
    cmdline: []const u8,
) !BootState {
    if (guest_kernel_base >= memory_size_bytes) return error.InvalidGuestLayout;
    if (guest_cmdline_base >= memory_size_bytes) return error.InvalidGuestLayout;

    const cmdline_len: u32 = @intCast(cmdline.len);
    const cmdline_end = guest_cmdline_base + @as(u64, cmdline_len) + 1;
    if (cmdline_end > memory_size_bytes) return error.InvalidGuestLayout;

    if (memory_size_bytes < 0x2000) return error.InvalidGuestLayout;
    const stack_top = (memory_size_bytes - 0x1000) & ~@as(u64, 0xF);

    if (stack_top <= guest_cmdline_base) return error.InvalidGuestLayout;

    return .{
        .entry = guest_kernel_base,
        .stack_top = stack_top,
        .cmdline_addr = guest_cmdline_base,
        .cmdline_len = cmdline_len,
    };
}

/// Computes boot state when guest RAM is mapped at a non-zero base.
///
/// Parameters:
///   - memory_base: Guest physical base address of RAM
///   - memory_size_bytes: Size of RAM region
///   - guest_kernel_offset: Kernel load offset within RAM
///   - guest_cmdline_offset: Cmdline offset within RAM
pub fn computeBootStateWithBase(
    memory_base: u64,
    memory_size_bytes: u64,
    guest_kernel_offset: u64,
    guest_cmdline_offset: u64,
    cmdline: []const u8,
) !BootState {
    const offset_state = try computeBootState(
        memory_size_bytes,
        guest_kernel_offset,
        guest_cmdline_offset,
        cmdline,
    );
    return .{
        .entry = memory_base + offset_state.entry,
        .stack_top = memory_base + offset_state.stack_top,
        .cmdline_addr = memory_base + offset_state.cmdline_addr,
        .cmdline_len = offset_state.cmdline_len,
    };
}

/// Converts a BootState into initial register values.
///
/// Maps boot state to x86-64 registers:
/// - RIP = entry (kernel entry point)
/// - RSP = stack_top (stack pointer)
/// - RFLAGS = 0x2 (reserved bit set, interrupts disabled)
/// - RSI = cmdline_addr (Linux boot protocol: RSI points to boot params)
///
/// Note: RFLAGS bit 1 is always set (reserved). Bit 9 (IF) is clear to
/// indicate interrupts are disabled at boot.
pub fn buildBootRegs(state: BootState) BootRegs {
    return .{
        .rip = state.entry,
        .rsp = state.stack_top,
        .rflags = 0x2, // Reserved bit set, interrupts disabled
        .rsi = state.cmdline_addr,
    };
}

// =============================================================================
// TESTS
// =============================================================================

test "boot: computeBootState validates layout and alignment" {
    const state = try computeBootState(64 * 1024 * 1024, 0x100000, 0x20000, "console=ttyS0");
    try std.testing.expectEqual(@as(u64, 0x100000), state.entry);
    try std.testing.expect(state.stack_top % 16 == 0);
    try std.testing.expectEqual(@as(u64, 0x20000), state.cmdline_addr);
    try std.testing.expect(state.cmdline_len > 0);
}

test "boot: computeBootState rejects oversized cmdline" {
    const cmd = "x" ** 4096;
    try std.testing.expectError(
        error.InvalidGuestLayout,
        computeBootState(0x3000, 0x1000, 0x2000, cmd),
    );
}

test "boot: buildBootRegs mirrors boot state" {
    const state = try computeBootState(32 * 1024 * 1024, 0x100000, 0x20000, "root=/dev/vda");
    const regs = buildBootRegs(state);
    try std.testing.expectEqual(state.entry, regs.rip);
    try std.testing.expectEqual(state.stack_top, regs.rsp);
    try std.testing.expectEqual(@as(u64, 0x2), regs.rflags);
    try std.testing.expectEqual(state.cmdline_addr, regs.rsi);
}

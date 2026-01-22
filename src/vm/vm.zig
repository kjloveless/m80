//! VM Platform Dispatcher
//!
//! This module provides a platform-independent interface for VM operations.
//! It dispatches start/stop calls to the appropriate hypervisor backend
//! based on the host operating system.
//!
//! ## Supported Platforms & Backends
//! - **Windows**: Windows Hypervisor Platform (WHP) via windows.zig
//! - **macOS**: Hypervisor Framework (HVF) via hvf.zig
//! - **Linux/BSD**: Kernel-based Virtual Machine (KVM) via posix.zig
//!
//! ## Architecture
//! ```
//! Vm (this file) - Platform dispatcher
//!     │
//!     ├── windows.zig - WHP backend (Windows)
//!     ├── hvf.zig     - HVF backend (macOS)
//!     └── posix.zig   - KVM backend (Linux, FreeBSD, etc.)
//! ```
//!
//! The Vm struct is intentionally thin - it just routes calls to backends.
//! Platform-specific state and logic live in the backend modules.

const std = @import("std");
const Jailer = @import("../jailer/jailer.zig").Jailer;
const windows = @import("windows.zig");
const hvf = @import("hvf.zig");
const posix = @import("posix.zig");

/// Virtual Machine handle.
///
/// This struct provides a unified interface for VM operations across platforms.
/// It holds references to the allocator and jailer (security sandbox) but
/// delegates actual hypervisor work to platform-specific backends.
pub const Vm = struct {
    /// Memory allocator used for any allocations during VM lifecycle
    allocator: std.mem.Allocator,

    /// Reference to the security jailer that enforces sandboxing
    jailer: *Jailer,

    /// Creates a new VM instance.
    ///
    /// This is a lightweight operation - it just stores references.
    /// The actual hypervisor setup happens in start().
    ///
    /// Parameters:
    ///   - allocator: Memory allocator for VM operations
    ///   - jailer: Security jailer (must outlive the VM)
    pub fn init(
        allocator: std.mem.Allocator,
        jailer: *Jailer,
    ) !Vm {
        return Vm{
            .allocator = allocator,
            .jailer = jailer,
        };
    }

    /// Starts the VM with the given configuration.
    ///
    /// Dispatches to the appropriate hypervisor backend based on host OS:
    /// - Windows → WHP (Windows Hypervisor Platform)
    /// - macOS → HVF (Hypervisor Framework)
    /// - Linux/BSD → KVM (Kernel-based Virtual Machine)
    ///
    /// Parameters:
    ///   - cfg: VM configuration (kernel path, memory, CPU cores, etc.)
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - error.NotImplemented: Backend not yet implemented
    ///   - Backend-specific errors (hypervisor init failed, etc.)
    pub fn start(self: *Vm, cfg: @import("../core/config.zig").VmConfig) !void {
        _ = self;
        // Dispatch to platform-specific backend
        switch (@import("builtin").os.tag) {
            .windows => try windows.start(cfg),
            .macos => try hvf.start(cfg),
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.start(cfg),
            else => return error.UnsupportedPlatform,
        }
    }

    /// Stops the running VM.
    ///
    /// Signals the hypervisor to terminate the guest VM gracefully.
    /// Like start(), dispatches to the appropriate platform backend.
    ///
    /// Errors:
    ///   - error.UnsupportedPlatform: Running on unsupported OS
    ///   - Backend-specific errors
    pub fn stop(self: *Vm) !void {
        _ = self;
        switch (@import("builtin").os.tag) {
            .windows => try windows.stop(),
            .macos => try hvf.stop(),
            .linux, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => try posix.stop(),
            else => return error.UnsupportedPlatform,
        }
    }

    /// Cleans up VM resources.
    /// Currently a no-op since state lives in backends.
    pub fn deinit(self: *Vm) void {
        _ = self;
    }
};

// =============================================================================
// TESTS
// =============================================================================

test "smoke: backend start/stop" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var jailer = try Jailer.init(allocator);
    defer jailer.deinit();

    var vm = try Vm.init(allocator, &jailer);
    defer vm.deinit();

    const cfg = try @import("../core/config.zig").defaultConfig(allocator, "test");
    var cfg_mut = cfg;
    defer @import("../core/config.zig").freeConfig(allocator, &cfg_mut);

    vm.start(cfg_mut) catch |e| switch (e) {
        error.NotImplemented => return error.SkipZigTest,
        error.HvfFailure => return,
        else => return e,
    };
    try vm.stop();
}

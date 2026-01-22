//! Core Module Aggregator
//!
//! This module re-exports all core submodules for convenient importing.
//! Instead of importing each submodule separately:
//! ```zig
//! const config = @import("core/config.zig");
//! const state = @import("core/state.zig");
//! const paths = @import("core/paths.zig");
//! ```
//!
//! You can import them all at once:
//! ```zig
//! const core = @import("core.zig");
//! const cfg = try core.config.readConfigFile(...);
//! try core.state.initVm(...);
//! ```
//!
//! ## Submodules
//! - **errors**: Common error types (M80Error) and fatal error handling (die)
//! - **paths**: Data directory paths and VM name validation
//! - **state**: VM lifecycle management (init, delete, status)
//! - **config**: Configuration file parsing and validation

const std = @import("std");

/// Error types and fatal error handling
pub const errors = @import("core/errors.zig");

/// Path construction and VM name validation
pub const paths = @import("core/paths.zig");

/// VM lifecycle management (create, delete, status)
pub const state = @import("core/state.zig");

/// Configuration file parsing and validation
pub const config = @import("core/config.zig");

// =============================================================================
// TESTS
// =============================================================================

// Verifies that all re-exports are accessible and working.
test "core: re-exports are reachable" {
    try std.testing.expect(paths.validateVmName("valid_name-1"));

    var cfg = try config.defaultConfig(std.testing.allocator, "test");
    defer config.freeConfig(std.testing.allocator, &cfg);
    try std.testing.expectEqual(config.default_memory_mb, cfg.memory_mb);
    try std.testing.expectEqual(config.default_cpu_cores, cfg.cpu_cores);
}

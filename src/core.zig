const std = @import("std");

// Convenience re-exports for core modules.
pub const errors = @import("core/errors.zig");
pub const paths = @import("core/paths.zig");
pub const state = @import("core/state.zig");
pub const config = @import("core/config.zig");

test "core: re-exports are reachable" {
    try std.testing.expect(paths.validateVmName("valid_name-1"));

    var cfg = try config.defaultConfig(std.testing.allocator, "test");
    defer config.freeConfig(std.testing.allocator, &cfg);
    try std.testing.expectEqual(config.default_memory_mb, cfg.memory_mb);
    try std.testing.expectEqual(config.default_cpu_cores, cfg.cpu_cores);
}

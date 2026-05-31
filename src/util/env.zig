const std = @import("std");
const builtin = @import("builtin");

const integration_env = "M80_TEST_INTEGRATION";

pub fn getVarOwned(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    if (builtin.os.tag == .windows) {
        const environ: std.process.Environ = .{ .block = .global };
        return environ.getAlloc(allocator, key);
    }

    if (comptime builtin.link_libc) {
        const key_z = try allocator.dupeZ(u8, key);
        defer allocator.free(key_z);
        const value = std.c.getenv(key_z.ptr) orelse return error.EnvironmentVariableMissing;
        return allocator.dupe(u8, std.mem.span(value));
    }

    if (builtin.is_test) {
        return std.testing.environ.getAlloc(allocator, key);
    }
    return error.EnvironmentVariableMissing;
}

pub fn getMap(allocator: std.mem.Allocator) !std.process.Environ.Map {
    if (builtin.os.tag == .windows) {
        const environ: std.process.Environ = .{ .block = .global };
        return environ.createMap(allocator);
    }

    if (comptime builtin.link_libc) {
        var map = std.process.Environ.Map.init(allocator);
        errdefer map.deinit();

        var index: usize = 0;
        while (std.c.environ[index]) |entry_ptr| : (index += 1) {
            const entry = std.mem.span(entry_ptr);
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            if (eq == 0) continue;
            try map.put(entry[0..eq], entry[eq + 1 ..]);
        }
        return map;
    }

    if (builtin.is_test) {
        return std.testing.environ.createMap(allocator);
    }
    return std.process.Environ.Map.init(allocator);
}

pub fn flagEnabledValue(value: []const u8) bool {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "false")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "off")) return false;
    return true;
}

pub fn integrationEnabledValue(value: []const u8, key: []const u8) bool {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (!flagEnabledValue(trimmed)) return false;
    if (std.mem.eql(u8, trimmed, "1")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "true")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "all")) return true;

    var it = std.mem.tokenizeAny(u8, trimmed, ",;: \t\r\n");
    while (it.next()) |token| {
        if (std.ascii.eqlIgnoreCase(token, key)) return true;
    }
    return false;
}

pub fn integrationEnabled(allocator: std.mem.Allocator, key: []const u8) bool {
    const raw = getVarOwned(allocator, integration_env) catch return false;
    defer allocator.free(raw);
    return integrationEnabledValue(raw, key);
}

test "env: flagEnabledValue handles common disabled values" {
    try std.testing.expect(!flagEnabledValue(""));
    try std.testing.expect(!flagEnabledValue("0"));
    try std.testing.expect(!flagEnabledValue(" false "));
    try std.testing.expect(!flagEnabledValue("off"));
    try std.testing.expect(flagEnabledValue("1"));
    try std.testing.expect(flagEnabledValue("yes"));
}

test "env: integrationEnabledValue accepts all selectors" {
    try std.testing.expect(integrationEnabledValue("1", "hvf-net"));
    try std.testing.expect(integrationEnabledValue("true", "hvf-net"));
    try std.testing.expect(integrationEnabledValue("all", "hvf-net"));
}

test "env: integrationEnabledValue matches tokenized selectors" {
    try std.testing.expect(integrationEnabledValue("jailer,hvf-net", "hvf-net"));
    try std.testing.expect(integrationEnabledValue("jailer hvf-reliability", "hvf-reliability"));
    try std.testing.expect(!integrationEnabledValue("jailer", "whp"));
}

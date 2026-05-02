const std = @import("std");

const integration_env = "M80_TEST_INTEGRATION";

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
    const raw = std.process.getEnvVarOwned(allocator, integration_env) catch return false;
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

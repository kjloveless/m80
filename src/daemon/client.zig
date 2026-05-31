const std = @import("std");
const core = @import("../core.zig");
const config = @import("../core/config.zig");
const protocol = @import("protocol.zig");

pub const VmRegistration = struct {
    name: []const u8,
    memory_mb: u32,
    cpu_cores: u16,
    network_mode: config.NetworkMode,
    network_services: []const config.Service,
    network_metadata_file: ?[]const u8,
    network_allowed_domains: []const []const u8,
    network_allowed_ips: []const []const u8,
    mounts: []const []const u8,
    started_at: i64,
};

pub const VmRegistrationResult = struct {
    guest_cid: u32,
    guest_socket_path: []u8,

    pub fn deinit(self: *VmRegistrationResult, allocator: std.mem.Allocator) void {
        allocator.free(self.guest_socket_path);
        self.guest_socket_path = "";
    }
};

fn parseResponseRoot(allocator: std.mem.Allocator, payload: []const u8) !std.json.Parsed(std.json.Value) {
    return try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
}

fn extractSuccessRoot(parsed: std.json.Parsed(std.json.Value)) !std.json.ObjectMap {
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidResponse,
    };

    const ok_value = root.get("ok") orelse return error.InvalidResponse;
    switch (ok_value) {
        .bool => |ok| if (ok) return root,
        else => {},
    }

    if (root.get("error")) |err_value| {
        return switch (err_value) {
            .string => error.DaemonRejected,
            else => error.InvalidResponse,
        };
    }
    return error.InvalidResponse;
}

fn serviceNames(allocator: std.mem.Allocator, services: []const config.Service) ![][]const u8 {
    const names = try allocator.alloc([]const u8, services.len);
    errdefer allocator.free(names);
    for (services, 0..) |service, i| {
        names[i] = service.toString();
    }
    return names;
}

pub fn registerVm(allocator: std.mem.Allocator, reg: VmRegistration) !VmRegistrationResult {
    const register_path = try core.paths.daemonRegisterSocketPath(allocator);
    defer allocator.free(register_path);

    const service_names = try serviceNames(allocator, reg.network_services);
    defer allocator.free(service_names);

    const request = try protocol.buildRequestPayload(allocator, 1, "vm.register", .{
        .name = reg.name,
        .memory_mb = reg.memory_mb,
        .cpu_cores = reg.cpu_cores,
        .network_mode = reg.network_mode.toString(),
        .network_services = service_names,
        .network_metadata_file = reg.network_metadata_file,
        .network_allowed_domains = reg.network_allowed_domains,
        .network_allowed_ips = reg.network_allowed_ips,
        .mounts = reg.mounts,
        .started_at = reg.started_at,
    });
    defer allocator.free(request);

    const response = try protocol.rpc(allocator, register_path, request);
    defer allocator.free(response);

    var parsed = try parseResponseRoot(allocator, response);
    defer parsed.deinit();
    const root = try extractSuccessRoot(parsed);
    const result = switch (root.get("result") orelse return error.InvalidResponse) {
        .object => |obj| obj,
        else => return error.InvalidResponse,
    };
    const guest_cid = switch (result.get("guest_cid") orelse return error.InvalidResponse) {
        .integer => |value| std.math.cast(u32, value) orelse return error.InvalidResponse,
        else => return error.InvalidResponse,
    };
    const guest_socket_path = switch (result.get("guest_socket_path") orelse return error.InvalidResponse) {
        .string => |value| try allocator.dupe(u8, value),
        else => return error.InvalidResponse,
    };
    errdefer allocator.free(guest_socket_path);
    return .{ .guest_cid = guest_cid, .guest_socket_path = guest_socket_path };
}

pub fn unregisterVm(allocator: std.mem.Allocator, name: []const u8) !void {
    const register_path = try core.paths.daemonRegisterSocketPath(allocator);
    defer allocator.free(register_path);

    const request = try protocol.buildRequestPayload(allocator, 1, "vm.unregister", .{
        .name = name,
    });
    defer allocator.free(request);

    const response = try protocol.rpc(allocator, register_path, request);
    defer allocator.free(response);

    var parsed = try parseResponseRoot(allocator, response);
    defer parsed.deinit();
    _ = try extractSuccessRoot(parsed);
}

pub fn requestVmShutdown(allocator: std.mem.Allocator, name: []const u8) !void {
    const register_path = try core.paths.daemonRegisterSocketPath(allocator);
    defer allocator.free(register_path);

    const request = try protocol.buildRequestPayload(allocator, 1, "vm.request_shutdown", .{
        .name = name,
    });
    defer allocator.free(request);

    const response = try protocol.rpc(allocator, register_path, request);
    defer allocator.free(response);

    var parsed = try parseResponseRoot(allocator, response);
    defer parsed.deinit();
    _ = try extractSuccessRoot(parsed);
}

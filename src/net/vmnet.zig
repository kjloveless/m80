const std = @import("std");

const c = @cImport({
    @cInclude("vmnet/vmnet.h");
    @cInclude("sys/uio.h");
    @cInclude("xpc/xpc.h");
    @cInclude("dispatch/dispatch.h");
});

extern fn m80_vmnet_start_sync(interface_desc: c.xpc_object_t, out_iface: ?*c.interface_ref, out_params: ?*c.xpc_object_t) c.vmnet_return_t;
extern fn m80_vmnet_stop_sync(iface: c.interface_ref) c.vmnet_return_t;
extern fn m80_vmnet_set_event_callback(
    iface: c.interface_ref,
    mask: c.interface_event_t,
    queue: c.dispatch_queue_t,
    cb: ?*const fn (c.interface_event_t, c.xpc_object_t, ?*anyopaque) callconv(.c) void,
    ctx: ?*anyopaque,
) c.vmnet_return_t;

pub const VmnetError = error{
    StartFailed,
    NotAuthorized,
    InvalidParams,
    NoMacAddress,
    InvalidMacAddress,
    Unsupported,
};

pub const VmnetInterface = struct {
    handle: c.interface_ref,
    mac: [6]u8,
    mtu: u32,
    max_packet_size: u32,
};

fn parseMacAddress(mac_str: []const u8) VmnetError![6]u8 {
    var out: [6]u8 = undefined;
    var i: usize = 0;
    var pos: usize = 0;
    while (i < out.len) : (i += 1) {
        if (pos + 2 > mac_str.len) return VmnetError.InvalidMacAddress;
        const hi = std.fmt.charToDigit(mac_str[pos], 16) catch return VmnetError.InvalidMacAddress;
        const lo = std.fmt.charToDigit(mac_str[pos + 1], 16) catch return VmnetError.InvalidMacAddress;
        out[i] = @intCast((hi << 4) | lo);
        pos += 2;
        if (i + 1 < out.len) {
            if (pos >= mac_str.len or mac_str[pos] != ':') return VmnetError.InvalidMacAddress;
            pos += 1;
        }
    }
    return out;
}

fn vmnetStatusToError(status: c.vmnet_return_t) VmnetError!void {
    switch (status) {
        c.VMNET_SUCCESS => return,
        c.VMNET_NOT_AUTHORIZED => return VmnetError.NotAuthorized,
        c.VMNET_INVALID_ARGUMENT => return VmnetError.InvalidParams,
        else => return VmnetError.StartFailed,
    }
}

pub fn startShared() VmnetError!VmnetInterface {
    const desc = c.xpc_dictionary_create(null, null, 0);
    if (desc == null) return VmnetError.StartFailed;
    defer c.xpc_release(desc);

    c.xpc_dictionary_set_uint64(desc, c.vmnet_operation_mode_key, c.VMNET_SHARED_MODE);
    c.xpc_dictionary_set_bool(desc, c.vmnet_allocate_mac_address_key, true);
    c.xpc_dictionary_set_bool(desc, c.vmnet_enable_isolation_key, true);

    var iface: c.interface_ref = undefined;
    var params: c.xpc_object_t = null;
    const status = m80_vmnet_start_sync(desc, &iface, &params);
    try vmnetStatusToError(status);
    if (iface == null) return VmnetError.StartFailed;
    defer if (params != null) c.xpc_release(params);

    var mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
    if (params != null) {
        const mac_c = c.xpc_dictionary_get_string(params, c.vmnet_mac_address_key);
        if (mac_c != null) {
            const mac_slice = std.mem.sliceTo(mac_c, 0);
            mac = try parseMacAddress(mac_slice);
        } else {
            return VmnetError.NoMacAddress;
        }
    }

    const mtu_val = if (params != null)
        c.xpc_dictionary_get_uint64(params, c.vmnet_mtu_key)
    else
        1500;
    const max_pkt = if (params != null)
        c.xpc_dictionary_get_uint64(params, c.vmnet_max_packet_size_key)
    else
        1514;

    return .{
        .handle = iface,
        .mac = mac,
        .mtu = @intCast(mtu_val),
        .max_packet_size = @intCast(max_pkt),
    };
}

pub fn stop(iface: VmnetInterface) VmnetError!void {
    const status = m80_vmnet_stop_sync(iface.handle);
    try vmnetStatusToError(status);
}

pub fn setEventCallback(
    iface: VmnetInterface,
    queue: c.dispatch_queue_t,
    cb: ?*const fn (c.interface_event_t, c.xpc_object_t, ?*anyopaque) callconv(.c) void,
    ctx: ?*anyopaque,
) VmnetError!void {
    const status = m80_vmnet_set_event_callback(
        iface.handle,
        c.VMNET_INTERFACE_PACKETS_AVAILABLE,
        queue,
        cb,
        ctx,
    );
    try vmnetStatusToError(status);
}

pub fn readPackets(
    iface: VmnetInterface,
    packets: [*]c.vmpktdesc,
    pktcnt: *c_int,
) VmnetError!void {
    const status = c.vmnet_read(iface.handle, packets, pktcnt);
    if (status == c.VMNET_SUCCESS) return;
    if (status == c.VMNET_FAILURE) return VmnetError.StartFailed;
    if (status == c.VMNET_PACKET_TOO_BIG) return VmnetError.InvalidParams;
    return VmnetError.StartFailed;
}

pub fn writePackets(
    iface: VmnetInterface,
    packets: [*]c.vmpktdesc,
    pktcnt: *c_int,
) VmnetError!void {
    const status = c.vmnet_write(iface.handle, packets, pktcnt);
    if (status == c.VMNET_SUCCESS) return;
    if (status == c.VMNET_PACKET_TOO_BIG) return VmnetError.InvalidParams;
    return VmnetError.StartFailed;
}

pub const c_types = c;

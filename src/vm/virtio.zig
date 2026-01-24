//! Virtio device models shared by the m80 HVF backend.

const std = @import("std");
const config = @import("../core/config.zig");
const dns = @import("../net/dns.zig");
const net_policy = @import("../net/policy.zig");
const virtio_fs = @import("../fs/virtio_fs.zig");
const mounts = @import("../fs/mounts.zig");
const log = @import("../util/log.zig");
const SerialIo = @import("serial.zig").SerialIo;

pub const GuestIo = struct {
    read_bytes: *const fn (u64, []u8) anyerror!void,
    write_bytes: *const fn (u64, []const u8) anyerror!void,
};

var guest_io: ?GuestIo = null;

pub fn initGuestIo(io: GuestIo) void {
    guest_io = io;
}

fn ensureGuestIo() !GuestIo {
    return guest_io orelse error.NoGuestIo;
}

fn readGuestBytes(guest_addr: u64, out: []u8) !void {
    const io = try ensureGuestIo();
    try io.read_bytes(guest_addr, out);
}

fn writeGuestBytes(guest_addr: u64, data: []const u8) !void {
    const io = try ensureGuestIo();
    try io.write_bytes(guest_addr, data);
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
    try writeGuestBytes(guest_addr, &[_]u8{value});
}

pub const InterruptHandler = *const fn (intid: u32, level: bool) void;
var interrupt_handler: ?InterruptHandler = null;

pub fn setInterruptHandler(handler: ?InterruptHandler) void {
    interrupt_handler = handler;
}

fn triggerInterrupt(intid: u32, level: bool) void {
    if (interrupt_handler) |handler| {
        handler(intid, level);
        return;
    }
    log.warn("virtio interrupt handler missing", .{});
}

pub const virtio_blk_device_count: usize = 3;
pub const virtio_blk_mmio_bases = [_]u64{ 0x0a000000, 0x0a002000, 0x0a004000 };
pub const virtio_blk_mmio_size: u64 = 0x1000;
pub const virtio_blk_queue_max: u16 = 128;
pub const virtio_console_mmio_base: u64 = 0x0a001000;
pub const virtio_console_mmio_size: u64 = 0x1000;
pub const virtio_console_queue_max: u16 = 128;
pub const virtio_rng_mmio_base: u64 = 0x0a003000;
pub const virtio_rng_mmio_size: u64 = 0x1000;
pub const virtio_rng_queue_max: u16 = 128;
pub const virtio_net_mmio_base: u64 = 0x0a004000;
pub const virtio_net_mmio_size: u64 = 0x1000;
pub const virtio_net_queue_max: u16 = 256;
pub const virtio_fs_mmio_base: u64 = 0x0a005000;
pub const virtio_fs_mmio_size: u64 = 0x1000;
pub const virtio_fs_queue_max: u16 = 256;

pub fn virtioBlkMmioBase(index: usize) u64 {
    return virtio_blk_mmio_bases[index];
}

pub fn virtioBlkIndexForAddr(addr: u64) ?usize {
    for (virtio_blk_mmio_bases, 0..) |base, index| {
        if (addr >= base and addr < base + virtio_blk_mmio_size) return index;
    }
    return null;
}
pub const VirtioConsoleInput = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    mutex: std.Thread.Mutex = .{},
};

pub var virtio_console_input = VirtioConsoleInput{};
pub var gic_virtio_blk_intid: [virtio_blk_device_count]?u32 = .{ null, null, null };
pub var gic_virtio_console_intid: ?u32 = null;
pub var gic_virtio_rng_intid: ?u32 = null;
pub var virtio_blk_irq_level: [virtio_blk_device_count]bool = .{ false, false, false };
pub var virtio_console_irq_level = false;
pub var virtio_rng_irq_level = false;

pub const VirtioBlkQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

pub const VirtioBlkDevice = struct {
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

pub var virtio_blk_devices: [virtio_blk_device_count]VirtioBlkDevice = .{ .{}, .{}, .{} };

pub const VirtioConsoleQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

pub const VirtioConsoleState = struct {
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

pub var virtio_console_state = VirtioConsoleState{};
pub var virtio_console_seen = std.atomic.Value(bool).init(false);

pub const VirtioRngQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

pub const VirtioRngState = struct {
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

pub var virtio_rng_state = VirtioRngState{};
pub var virtio_rng_seen = std.atomic.Value(bool).init(false);
pub const VirtioNetQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

pub const VirtioNetState = struct {
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

pub var virtio_net_state = VirtioNetState{};
pub var virtio_net_seen = std.atomic.Value(bool).init(false);
pub var gic_virtio_net_intid: ?u32 = null;
pub var virtio_net_irq_level = false;


pub var net_policy_state: ?net_policy.NetworkPolicy = null;
pub var net_policy_mutex = std.Thread.Mutex{};

pub const virtio_fs_tag_len: usize = 36;

pub const VirtioFsQueue = struct {
    num: u16 = 0,
    ready: bool = false,
    desc_addr: u64 = 0,
    avail_addr: u64 = 0,
    used_addr: u64 = 0,
    last_avail_idx: u16 = 0,
    used_idx: u16 = 0,
};

pub const VirtioFsState = struct {
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

pub var virtio_fs_state = VirtioFsState{};
pub var virtio_fs_seen = std.atomic.Value(bool).init(false);
pub var virtio_fs_config_logged = std.atomic.Value(bool).init(false);
pub var gic_virtio_fs_intid: ?u32 = null;
pub var virtio_fs_irq_level = false;
pub var virtio_fs_device: ?virtio_fs.VirtioFsDevice = null;
pub var virtio_fs_mount_manager: ?mounts.MountManager = null;
pub fn updateVirtioBlkInterrupt(index: usize) void {
    if (index >= virtio_blk_devices.len) return;
    const intid = gic_virtio_blk_intid[index] orelse return;
    const device = &virtio_blk_devices[index];
    const level = device.interrupt_status != 0;
    if (level != virtio_blk_irq_level[index]) {
        virtio_blk_irq_level[index] = level;
        log.debug("hvf virtio-blk irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    triggerInterrupt(intid, level);
}

pub fn updateVirtioConsoleInterrupt() void {
    const intid = gic_virtio_console_intid orelse return;
    const level = virtio_console_state.interrupt_status != 0;
    if (level != virtio_console_irq_level) {
        virtio_console_irq_level = level;
        log.debug("hvf virtio-console irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    triggerInterrupt(intid, level);
}

pub fn updateVirtioRngInterrupt() void {
    const intid = gic_virtio_rng_intid orelse return;
    const level = virtio_rng_state.interrupt_status != 0;
    if (level != virtio_rng_irq_level) {
        virtio_rng_irq_level = level;
        log.debug("hvf virtio-rng irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    triggerInterrupt(intid, level);
}

pub fn updateVirtioNetInterrupt() void {
    const intid = gic_virtio_net_intid orelse return;
    const level = virtio_net_state.interrupt_status != 0;
    if (level != virtio_net_irq_level) {
        virtio_net_irq_level = level;
        log.debug("hvf virtio-net irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    triggerInterrupt(intid, level);
}

pub fn updateVirtioFsInterrupt() void {
    const intid = gic_virtio_fs_intid orelse return;
    const level = virtio_fs_state.interrupt_status != 0;
    if (level != virtio_fs_irq_level) {
        virtio_fs_irq_level = level;
        log.debug("hvf virtio-fs irq level={s} intid={d}", .{ if (level) "high" else "low", intid });
    }
    triggerInterrupt(intid, level);
}
pub const virtio_mmio_magic: u32 = 0x74726976; // "virt"
pub const virtio_mmio_version: u32 = 2;
pub const virtio_mmio_device_id_blk: u32 = 2;
pub const virtio_mmio_device_id_net: u32 = 1;
pub const virtio_mmio_device_id_console: u32 = 3;
pub const virtio_mmio_device_id_rng: u32 = 4;
pub const virtio_mmio_device_id_fs: u32 = 26;
pub const virtio_mmio_vendor_id: u32 = 0x4d3830; // "M80"
pub const virtio_mmio_int_vring: u32 = 1 << 0;

pub const virtio_mmio_reg_magic: u64 = 0x000;
pub const virtio_mmio_reg_version: u64 = 0x004;
pub const virtio_mmio_reg_device_id: u64 = 0x008;
pub const virtio_mmio_reg_vendor_id: u64 = 0x00c;
pub const virtio_mmio_reg_device_features: u64 = 0x010;
pub const virtio_mmio_reg_device_features_sel: u64 = 0x014;
pub const virtio_mmio_reg_driver_features: u64 = 0x020;
pub const virtio_mmio_reg_driver_features_sel: u64 = 0x024;
pub const virtio_mmio_reg_queue_sel: u64 = 0x030;
pub const virtio_mmio_reg_queue_num_max: u64 = 0x034;
pub const virtio_mmio_reg_queue_num: u64 = 0x038;
pub const virtio_mmio_reg_queue_ready: u64 = 0x044;
pub const virtio_mmio_reg_queue_notify: u64 = 0x050;
pub const virtio_mmio_reg_interrupt_status: u64 = 0x060;
pub const virtio_mmio_reg_interrupt_ack: u64 = 0x064;
pub const virtio_mmio_reg_status: u64 = 0x070;
pub const virtio_mmio_reg_queue_desc_low: u64 = 0x080;
pub const virtio_mmio_reg_queue_desc_high: u64 = 0x084;
pub const virtio_mmio_reg_queue_driver_low: u64 = 0x090;
pub const virtio_mmio_reg_queue_driver_high: u64 = 0x094;
pub const virtio_mmio_reg_queue_device_low: u64 = 0x0a0;
pub const virtio_mmio_reg_queue_device_high: u64 = 0x0a4;
pub const virtio_mmio_reg_config_generation: u64 = 0x0fc;
pub const virtio_mmio_reg_config: u64 = 0x100;

pub const virtio_blk_f_ro: u32 = 1 << 5;
pub const virtio_f_version_1: u32 = 1 << 0;
pub const virtio_net_f_mac: u32 = 1 << 5;

pub const virtio_console_f_size: u32 = 1 << 0;
pub const virtio_console_f_multiport: u32 = 1 << 1;
pub const virtio_console_f_emerg_write: u32 = 1 << 2;

pub const virtio_blk_t_in: u32 = 0;
pub const virtio_blk_t_out: u32 = 1;
pub const virtio_blk_t_flush: u32 = 4;

pub const virtio_blk_s_ok: u8 = 0;
pub const virtio_blk_s_ioerr: u8 = 1;
pub const virtio_blk_s_unsupported: u8 = 2;

pub const VirtqDesc = packed struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

pub const virtq_desc_flag_next: u16 = 1;
pub const virtq_desc_flag_write: u16 = 2;
pub const virtq_desc_flag_indirect: u16 = 4;

pub const VirtioBlkReq = packed struct {
    @"type": u32,
    reserved: u32,
    sector: u64,
};

pub fn virtioBlkDeviceFeatures(device: *const VirtioBlkDevice, sel: u32) u32 {
    if (sel == 0) {
        return if (device.readonly) virtio_blk_f_ro else 0;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

pub fn virtioConsoleDeviceFeatures(sel: u32) u32 {
    if (sel == 0) {
        return 0;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

pub fn virtioRngDeviceFeatures(sel: u32) u32 {
    switch (sel) {
        0 => return 0,
        1 => return virtio_f_version_1,
        else => return 0,
    }
}

pub fn virtioNetDeviceFeatures(sel: u32) u32 {
    if (sel == 0) {
        return virtio_net_f_mac;
    }
    if (sel == 1) {
        return virtio_f_version_1;
    }
    return 0;
}

pub fn virtioFsDeviceFeatures(sel: u32) u32 {
    const device = virtio_fs_device orelse return 0;
    const features = device.features;
    return switch (sel) {
        0 => @intCast(features & 0xFFFF_FFFF),
        1 => @intCast((features >> 32) & 0xFFFF_FFFF),
        else => 0,
    };
}

pub fn resetVirtioBlkQueue(device: *VirtioBlkDevice) void {
    device.queue = .{};
    device.queue_sel = 0;
}

pub fn resetVirtioBlkDevice(index: usize) void {
    if (index >= virtio_blk_devices.len) return;
    if (virtio_blk_devices[index].file) |*file| file.close();
    virtio_blk_devices[index] = .{};
    gic_virtio_blk_intid[index] = null;
    virtio_blk_irq_level[index] = false;
}

pub fn resetVirtioBlkState() void {
    var i: usize = 0;
    while (i < virtio_blk_devices.len) : (i += 1) {
        resetVirtioBlkDevice(i);
    }
}

pub fn resetVirtioConsoleState() void {
    virtio_console_state = .{};
    gic_virtio_console_intid = null;
    virtio_console_irq_level = false;
    virtio_console_input.mutex.lock();
    virtio_console_input.buf.clearRetainingCapacity();
    virtio_console_input.mutex.unlock();
}

pub fn resetVirtioRngState() void {
    virtio_rng_state = .{};
    gic_virtio_rng_intid = null;
    virtio_rng_irq_level = false;
}

pub fn resetVirtioNetState() void {
    virtio_net_state = .{};
    gic_virtio_net_intid = null;
    virtio_net_irq_level = false;
    virtio_net_seen.store(false, .seq_cst);
}

pub fn resetVirtioFsState() void {
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

pub fn setupVirtioConsole(enabled: bool) void {
    resetVirtioConsoleState();
    if (!enabled) return;
    virtio_console_state.enabled = true;
    log.info("hvf virtio-console enabled", .{});
}

pub fn setupVirtioRng(enabled: bool) void {
    resetVirtioRngState();
    if (!enabled) return;
    virtio_rng_state.enabled = true;
    log.info("hvf virtio-rng enabled", .{});
}

pub fn setupVirtioNet(enabled: bool, mac: [6]u8) void {
    resetVirtioNetState();
    if (!enabled) return;
    virtio_net_state.enabled = true;
    virtio_net_state.mac = mac;
    log.info(
        "hvf virtio-net enabled mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    );
}

pub fn setupVirtioFs(allocator: std.mem.Allocator, cfg: config.VmConfig) !void {
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

pub fn initNetworkPolicy(cfg: config.VmConfig) !void {
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

pub const ether_type_ipv4: u16 = 0x0800;
pub const ether_type_arp: u16 = 0x0806;
pub const ip_proto_udp: u8 = 17;

pub fn maybeCacheDnsResponse(frame: []const u8) void {
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

pub fn isDhcpPort(port: u16) bool {
    return port == 67 or port == 68;
}

pub fn outboundFrameAllowed(frame: []const u8) bool {
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

pub fn virtioConsoleInputLen() usize {
    virtio_console_input.mutex.lock();
    defer virtio_console_input.mutex.unlock();
    return virtio_console_input.buf.items.len;
}

pub fn appendVirtioConsoleInput(bytes: []const u8) void {
    if (bytes.len == 0) return;
    virtio_console_input.mutex.lock();
    defer virtio_console_input.mutex.unlock();
    virtio_console_input.buf.appendSlice(std.heap.page_allocator, bytes) catch {};
}

pub fn takeVirtioConsoleInput(dst: []u8) usize {
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

pub fn setVirtioConsoleInputFromEnv(allocator: std.mem.Allocator) void {
    const env = std.process.getEnvVarOwned(allocator, "M80_SERIAL_IN") catch return;
    defer allocator.free(env);
    appendVirtioConsoleInput(env);
}

pub fn setupVirtioBlk(cfg: config.VmConfig) !void {
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

pub fn setupVirtioBlkDevice(index: usize, path: []const u8, readonly: bool) !void {
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

pub fn writeVirtioBlkStatus(status_addr: u64, status: u8) !void {
    writeGuestByte(status_addr, status) catch |e| {
        log.warn("hvf virtio-blk failed to write status: {s}", .{@errorName(e)});
        return e;
    };
}

pub fn readVirtqDesc(desc_addr: u64) !VirtqDesc {
    var buf: [@sizeOf(VirtqDesc)]u8 = undefined;
    try readGuestBytes(desc_addr, &buf);
    return std.mem.bytesToValue(VirtqDesc, &buf);
}

pub fn readVirtioBlkReq(req_addr: u64) !VirtioBlkReq {
    var buf: [@sizeOf(VirtioBlkReq)]u8 = undefined;
    try readGuestBytes(req_addr, &buf);
    return std.mem.bytesToValue(VirtioBlkReq, &buf);
}

pub fn processVirtioBlkRequest(device: *VirtioBlkDevice, head: u16) !u32 {
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

pub fn processVirtioBlkQueue(index: usize) !void {
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

pub fn handleVirtioBlkMmio(index: usize, offset: u64, is_write: bool, size: usize, value: u64) u64 {
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

pub fn processVirtioConsoleQueue(queue_index: u16) !void {
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

pub const virtio_net_hdr_len: usize = 10;

pub fn virtioNetRxPacket(frame: []const u8) !void {
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

pub fn processVirtioNetTxQueue() !void {
    if (!virtio_net_state.enabled) return;
    const queue = &virtio_net_state.queues[1];
    if (!queue.ready or queue.num == 0) return;

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
            // vmnet disabled; drop outbound frames for now.
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

pub fn processVirtioFsQueue(queue_index: usize) !void {
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

pub fn processVirtioConsoleRxQueue() !void {
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

pub fn processVirtioRngQueue() !void {
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

pub fn handleVirtioConsoleMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
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

pub fn handleVirtioNetMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
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

pub fn handleVirtioFsMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
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

pub fn handleVirtioRngMmio(offset: u64, is_write: bool, size: usize, value: u64) u64 {
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

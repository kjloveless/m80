const std = @import("std");

pub fn allocZ(allocator: std.mem.Allocator, value: []const u8) ![:0]u8 {
    var buf = try allocator.alloc(u8, value.len + 1);
    @memcpy(buf[0..value.len], value);
    buf[value.len] = 0;
    return buf[0..value.len :0];
}

pub fn encodeDnsName(out: []u8, domain: []const u8) !usize {
    if (domain.len == 0) return error.InvalidDnsName;
    var out_idx: usize = 0;
    var label_start: usize = 0;
    while (label_start < domain.len) {
        const dot = std.mem.indexOfScalarPos(u8, domain, label_start, '.') orelse domain.len;
        const label_len = dot - label_start;
        if (label_len == 0 or label_len > 63) return error.InvalidDnsName;
        if (out_idx + 1 + label_len > out.len) return error.NoSpaceLeft;
        out[out_idx] = @intCast(label_len);
        out_idx += 1;
        @memcpy(out[out_idx .. out_idx + label_len], domain[label_start..dot]);
        out_idx += label_len;
        label_start = if (dot < domain.len) dot + 1 else dot;
    }
    if (out_idx >= out.len) return error.NoSpaceLeft;
    out[out_idx] = 0;
    return out_idx + 1;
}

pub fn buildDnsQueryFrame(frame: []u8, domain: []const u8, dst_ip: [4]u8) ![]const u8 {
    if (frame.len < 64) return error.NoSpaceLeft;
    @memset(frame, 0);

    frame[0..6].* = .{ 0x10, 0x22, 0x33, 0x44, 0x55, 0x66 };
    frame[6..12].* = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    frame[12] = 0x08;
    frame[13] = 0x00;

    const ip_offset: usize = 14;
    const udp_offset: usize = ip_offset + 20;
    const dns_offset: usize = udp_offset + 8;
    const qname_len = try encodeDnsName(frame[dns_offset + 12 ..], domain);
    const question_offset = dns_offset + 12 + qname_len;
    if (question_offset + 4 > frame.len) return error.NoSpaceLeft;

    frame[dns_offset + 0] = 0x12;
    frame[dns_offset + 1] = 0x34;
    frame[dns_offset + 2] = 0x01;
    frame[dns_offset + 3] = 0x00;
    frame[dns_offset + 4] = 0x00;
    frame[dns_offset + 5] = 0x01;
    frame[question_offset + 0] = 0x00;
    frame[question_offset + 1] = 0x01;
    frame[question_offset + 2] = 0x00;
    frame[question_offset + 3] = 0x01;

    const dns_len: usize = 12 + qname_len + 4;
    const udp_len: u16 = @intCast(8 + dns_len);
    const ip_len: u16 = @intCast(20 + udp_len);
    const frame_len = dns_offset + dns_len;

    frame[ip_offset + 0] = 0x45;
    frame[ip_offset + 8] = 64;
    frame[ip_offset + 9] = 17;
    std.mem.writeInt(u16, frame[ip_offset + 2 ..][0..2], ip_len, .big);
    frame[ip_offset + 12 .. ip_offset + 16].* = .{ 10, 0, 2, 15 };
    @memcpy(frame[ip_offset + 16 .. ip_offset + 20], &dst_ip);

    std.mem.writeInt(u16, frame[udp_offset..][0..2], 12345, .big);
    std.mem.writeInt(u16, frame[udp_offset + 2 ..][0..2], 53, .big);
    std.mem.writeInt(u16, frame[udp_offset + 4 ..][0..2], udp_len, .big);

    return frame[0..frame_len];
}

const std = @import("std");
const serial = @import("../serial.zig");

const IoExit = serial.IoExit;

pub const ArmExceptionInfo = struct {
    ec: u8,
    il: u1,
    iss: u32,
};

pub fn decodeArmExceptionSyndrome(syndrome: u64) ArmExceptionInfo {
    return .{
        .ec = @intCast((syndrome >> 26) & 0x3F),
        .il = @intCast((syndrome >> 25) & 0x1),
        .iss = @intCast(syndrome & 0x1FFFFFF),
    };
}

pub fn decodeVmxIoExit(qualification: u64, rax: u64) IoExit {
    const size_field: u3 = @intCast(qualification & 0x7);
    const size: usize = switch (size_field) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => 1,
    };
    const is_write = ((qualification >> 3) & 0x1) == 0;
    const is_string = ((qualification >> 4) & 0x1) == 1;
    const has_rep = ((qualification >> 5) & 0x1) == 1;
    const port: u16 = @intCast(qualification & 0xFFFF);
    return .{
        .port = port,
        .is_write = is_write,
        .size = size,
        .rax = rax,
        .is_string = is_string,
        .has_rep = has_rep,
    };
}

pub fn stopTimeoutWindowNs(signal_attempts: usize, signal_interval_ns: u64) u64 {
    return @as(u64, @intCast(signal_attempts)) * signal_interval_ns;
}

pub fn forceStopTimeoutTestDelayNs(signal_attempts: usize, signal_interval_ns: u64, extra_delay_ns: u64) u64 {
    return stopTimeoutWindowNs(signal_attempts, signal_interval_ns) + extra_delay_ns;
}

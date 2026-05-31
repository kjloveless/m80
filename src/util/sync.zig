const std = @import("std");
const fs = @import("fs.zig");

pub const Mutex = struct {
    inner: std.Io.Mutex = .init,

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(fs.io());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(fs.io());
    }
};

pub fn sleep(nanoseconds: u64) void {
    std.Io.sleep(
        fs.io(),
        .{ .nanoseconds = @intCast(nanoseconds) },
        .awake,
    ) catch {};
}

pub fn nanoTimestamp() i128 {
    return std.Io.Clock.real.now(fs.io()).nanoseconds;
}

pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_ms));
}

pub fn timestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_s));
}

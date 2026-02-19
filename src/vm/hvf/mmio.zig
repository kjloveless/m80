const std = @import("std");

pub const GicLayout = struct {
    dist_base: u64,
    redist_base: u64,
    dist_size: u64,
    redist_size: u64,
    dist_alignment: usize,
    redist_alignment: usize,
};

pub const GicProbe = struct {
    dist_alignment: usize,
    redist_alignment: usize,
    dist_size: usize,
    redist_size: usize,
};

pub fn alignUp(value: u64, alignment: usize) u64 {
    if (alignment <= 1) return value;
    const mask = @as(u64, alignment) - 1;
    return (value + mask) & ~mask;
}

pub fn computeGicLayout(
    dist_base_default: u64,
    redist_base_default: u64,
    dist_size_default: u64,
    redist_size_default: u64,
    probe: GicProbe,
) GicLayout {
    var dist_base = dist_base_default;
    if (probe.dist_alignment > 1) {
        dist_base = alignUp(dist_base, probe.dist_alignment);
    }

    var redist_base = redist_base_default;
    const min_redist = dist_base + @as(u64, @intCast(probe.dist_size));
    if (redist_base < min_redist) {
        redist_base = min_redist;
    }
    if (probe.redist_alignment > 1) {
        redist_base = alignUp(redist_base, probe.redist_alignment);
    }
    if (redist_base == dist_base) {
        redist_base = alignUp(dist_base + @as(u64, @intCast(probe.dist_size)), probe.redist_alignment);
    }

    return .{
        .dist_base = dist_base,
        .redist_base = redist_base,
        .dist_size = @intCast(if (probe.dist_size == 0) dist_size_default else probe.dist_size),
        .redist_size = @intCast(if (probe.redist_size == 0) redist_size_default else probe.redist_size),
        .dist_alignment = probe.dist_alignment,
        .redist_alignment = probe.redist_alignment,
    };
}

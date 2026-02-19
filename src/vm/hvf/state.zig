const snapshot = @import("../snapshot.zig");

pub const Pl011State = struct {
    cr: u32 = 0,
    lcrh: u32 = 0,
    ibrd: u32 = 0,
    fbrd: u32 = 0,
    imsc: u32 = 0,
    pending: u32 = 0,
};

pub fn capturePl011State(state: Pl011State) snapshot.Pl011SnapshotState {
    return .{
        .cr = state.cr,
        .lcrh = state.lcrh,
        .ibrd = state.ibrd,
        .fbrd = state.fbrd,
        .imsc = state.imsc,
        .pending = state.pending,
    };
}

pub fn restorePl011State(state: snapshot.Pl011SnapshotState) Pl011State {
    return .{
        .cr = state.cr,
        .lcrh = state.lcrh,
        .ibrd = state.ibrd,
        .fbrd = state.fbrd,
        .imsc = state.imsc,
        .pending = state.pending,
    };
}

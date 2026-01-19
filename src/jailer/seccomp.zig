const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");

pub const SeccompError = error{
    SetNoNewPrivsFailed,
    SeccompFailed,
    InvalidFilter,
    OutOfMemory,
};

/// Seccomp filter action
pub const SeccompAction = enum(u32) {
    kill_process = 0x80000000,
    kill_thread = 0x00000000,
    trap = 0x00030000,
    errno_eperm = 0x00050001,
    log_action = 0x7ffc0000,
    allow = 0x7fff0000,
};

/// BPF instruction structure for seccomp filters
pub const BpfInstruction = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    pub fn loadSyscallNr() BpfInstruction {
        return .{
            .code = BPF_LD | BPF_W | BPF_ABS,
            .jt = 0,
            .jf = 0,
            .k = 0,
        };
    }

    pub fn jumpIfEq(syscall: u32, jt: u8, jf: u8) BpfInstruction {
        return .{
            .code = BPF_JMP | BPF_JEQ | BPF_K,
            .jt = jt,
            .jf = jf,
            .k = syscall,
        };
    }

    pub fn ret(action: SeccompAction) BpfInstruction {
        return .{
            .code = BPF_RET | BPF_K,
            .jt = 0,
            .jf = 0,
            .k = @intFromEnum(action),
        };
    }
};

/// Linux x86_64 syscall numbers for VMM allowlist
pub const Syscall = struct {
    pub const read: u32 = 0;
    pub const write: u32 = 1;
    pub const close: u32 = 3;
    pub const mmap: u32 = 9;
    pub const mprotect: u32 = 10;
    pub const munmap: u32 = 11;
    pub const brk: u32 = 12;
    pub const ioctl: u32 = 16;
    pub const nanosleep: u32 = 35;
    pub const exit: u32 = 60;
    pub const futex: u32 = 202;
    pub const clock_gettime: u32 = 228;
    pub const exit_group: u32 = 231;
    pub const epoll_create1: u32 = 291;
    pub const epoll_ctl: u32 = 233;
    pub const epoll_pwait: u32 = 281;
    pub const eventfd2: u32 = 290;
    pub const timerfd_create: u32 = 283;
    pub const timerfd_settime: u32 = 286;
    pub const getpid: u32 = 39;
    pub const gettid: u32 = 186;
    pub const rt_sigaction: u32 = 13;
    pub const rt_sigprocmask: u32 = 14;
    pub const rt_sigreturn: u32 = 15;
};

/// Minimal syscall allowlist for VMM operation
pub const vmm_allowlist = [_]u32{
    Syscall.read,
    Syscall.write,
    Syscall.close,
    Syscall.mmap,
    Syscall.munmap,
    Syscall.mprotect,
    Syscall.brk,
    Syscall.ioctl,
    Syscall.exit,
    Syscall.exit_group,
    Syscall.futex,
    Syscall.clock_gettime,
    Syscall.nanosleep,
    Syscall.epoll_create1,
    Syscall.epoll_ctl,
    Syscall.epoll_pwait,
    Syscall.eventfd2,
    Syscall.timerfd_create,
    Syscall.timerfd_settime,
    Syscall.getpid,
    Syscall.gettid,
    Syscall.rt_sigaction,
    Syscall.rt_sigprocmask,
    Syscall.rt_sigreturn,
};

/// Seccomp filter builder
pub const SeccompFilter = struct {
    allocator: std.mem.Allocator,
    instructions: std.ArrayList(BpfInstruction),
    default_action: SeccompAction,

    pub fn init(allocator: std.mem.Allocator, default_action: SeccompAction) SeccompFilter {
        return .{
            .allocator = allocator,
            .instructions = .empty,
            .default_action = default_action,
        };
    }

    pub fn deinit(self: *SeccompFilter) void {
        self.instructions.deinit(self.allocator);
    }

    pub fn buildAllowlist(self: *SeccompFilter, allowed: []const u32) !void {
        self.instructions.clearRetainingCapacity();

        try self.instructions.append(self.allocator, BpfInstruction.loadSyscallNr());

        for (allowed, 0..) |syscall, i| {
            const remaining: u8 = @intCast(allowed.len - i - 1);
            const jump_to_allow: u8 = remaining + 1;
            try self.instructions.append(self.allocator, BpfInstruction.jumpIfEq(syscall, jump_to_allow, 0));
        }

        try self.instructions.append(self.allocator, BpfInstruction.ret(self.default_action));
        try self.instructions.append(self.allocator, BpfInstruction.ret(.allow));
    }

    pub fn apply(self: *SeccompFilter) SeccompError!void {
        if (builtin.os.tag != .linux) return;

        const PR_SET_NO_NEW_PRIVS = 38;
        const prctl_result = std.os.linux.prctl(@enumFromInt(PR_SET_NO_NEW_PRIVS), .{ 1, 0, 0, 0 });
        if (prctl_result != 0) {
            log.err("prctl SET_NO_NEW_PRIVS failed", .{});
            return SeccompError.SetNoNewPrivsFailed;
        }

        const prog = std.os.linux.sock_fprog{
            .len = @intCast(self.instructions.items.len),
            .filter = @ptrCast(self.instructions.items.ptr),
        };

        const seccomp_result = std.os.linux.seccomp(.SET_MODE_FILTER, 0, @ptrCast(&prog));
        if (seccomp_result != 0) {
            log.err("seccomp SET_MODE_FILTER failed", .{});
            return SeccompError.SeccompFailed;
        }

        log.info("seccomp filter applied ({} instructions)", .{self.instructions.items.len});
    }
};

pub fn applyVmmSeccompFilter(allocator: std.mem.Allocator) SeccompError!void {
    if (builtin.os.tag != .linux) return;

    var filter = SeccompFilter.init(allocator, .errno_eperm);
    defer filter.deinit();

    filter.buildAllowlist(&vmm_allowlist) catch return SeccompError.OutOfMemory;
    try filter.apply();
}

pub fn isSeccompAvailable() bool {
    if (builtin.os.tag != .linux) return false;
    const PR_GET_SECCOMP = 21;
    const result = std.os.linux.prctl(@enumFromInt(PR_GET_SECCOMP), .{ 0, 0, 0, 0 });
    return @as(isize, @bitCast(result)) >= 0;
}

test "seccomp: BpfInstruction creation" {
    const load = BpfInstruction.loadSyscallNr();
    try std.testing.expectEqual(@as(u32, 0), load.k);

    const jump = BpfInstruction.jumpIfEq(Syscall.read, 5, 0);
    try std.testing.expectEqual(Syscall.read, jump.k);
    try std.testing.expectEqual(@as(u8, 5), jump.jt);

    const ret_allow = BpfInstruction.ret(.allow);
    try std.testing.expectEqual(@intFromEnum(SeccompAction.allow), ret_allow.k);
}

test "seccomp: SeccompFilter buildAllowlist" {
    const allocator = std.testing.allocator;

    var filter = SeccompFilter.init(allocator, .errno_eperm);
    defer filter.deinit();

    const allowed = [_]u32{ Syscall.read, Syscall.write, Syscall.close };
    try filter.buildAllowlist(&allowed);

    try std.testing.expectEqual(@as(usize, 6), filter.instructions.items.len);
}

test "seccomp: vmm_allowlist is valid" {
    try std.testing.expect(vmm_allowlist.len > 0);
    try std.testing.expect(vmm_allowlist.len < 100);
}

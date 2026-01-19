const std = @import("std");
const builtin = @import("builtin");
const log = @import("../util/log.zig");

pub const SandboxError = error{
    JobObjectCreationFailed,
    JobObjectConfigFailed,
    ProcessAssignmentFailed,
    InvalidConfiguration,
    OutOfMemory,
};

pub const JobLimits = struct {
    active_process_limit: ?u32 = 1,
    job_memory_limit: ?u64 = null,
    process_memory_limit: ?u64 = null,
    kill_on_job_close: bool = true,
    die_on_unhandled_exception: bool = true,
};

pub const UiRestrictions = struct {
    restrict_desktop: bool = true,
    restrict_clipboard: bool = true,
    restrict_global_atoms: bool = true,
    restrict_handles: bool = true,
};

const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x00000008;
const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x00000200;
const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x00000100;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x00000400;

const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x00000040;
const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x00000002;
const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x00000004;
const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x00000020;
const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x00000001;

const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64 = 0,
    PerJobUserTimeLimit: i64 = 0,
    LimitFlags: u32 = 0,
    MinimumWorkingSetSize: u64 = 0,
    MaximumWorkingSetSize: u64 = 0,
    ActiveProcessLimit: u32 = 0,
    Affinity: u64 = 0,
    PriorityClass: u32 = 0,
    SchedulingClass: u32 = 0,
};

const IO_COUNTERS = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION = .{},
    IoInfo: IO_COUNTERS = .{},
    ProcessMemoryLimit: u64 = 0,
    JobMemoryLimit: u64 = 0,
    PeakProcessMemoryUsed: u64 = 0,
    PeakJobMemoryUsed: u64 = 0,
};

const JOBOBJECT_BASIC_UI_RESTRICTIONS = extern struct {
    UIRestrictionsClass: u32 = 0,
};

pub const JobObjectSandbox = struct {
    allocator: std.mem.Allocator,
    job_handle: ?*anyopaque = null,
    limits: JobLimits,
    ui_restrictions: UiRestrictions,

    pub fn init(allocator: std.mem.Allocator) JobObjectSandbox {
        return .{
            .allocator = allocator,
            .limits = .{},
            .ui_restrictions = .{},
        };
    }

    pub fn deinit(self: *JobObjectSandbox) void {
        if (builtin.os.tag != .windows) return;

        if (self.job_handle) |handle| {
            const close_handle = @extern(?*const fn (*anyopaque) callconv(.winapi) c_int, .{
                .name = "CloseHandle",
            });
            if (close_handle) |f| {
                _ = f(handle);
            }
            self.job_handle = null;
        }
    }

    pub fn create(self: *JobObjectSandbox) SandboxError!void {
        if (builtin.os.tag != .windows) return;

        const create_job = @extern(?*const fn (?*anyopaque, ?[*:0]const u16) callconv(.winapi) ?*anyopaque, .{
            .name = "CreateJobObjectW",
        });

        if (create_job == null) {
            return SandboxError.JobObjectCreationFailed;
        }

        self.job_handle = create_job.?(null, null);
        if (self.job_handle == null) {
            log.err("CreateJobObject failed", .{});
            return SandboxError.JobObjectCreationFailed;
        }

        // Apply hard limits before the process joins the job.
        try self.applyLimits();
        try self.applyUiRestrictions();

        log.info("Windows job object created", .{});
    }

    fn applyLimits(self: *JobObjectSandbox) SandboxError!void {
        if (builtin.os.tag != .windows) return;
        if (self.job_handle == null) return SandboxError.InvalidConfiguration;

        // Job object limits are best-effort; any failure aborts setup.
        const set_info = @extern(?*const fn (*anyopaque, u32, *anyopaque, u32) callconv(.winapi) c_int, .{
            .name = "SetInformationJobObject",
        });

        if (set_info == null) return SandboxError.JobObjectConfigFailed;

        const JobObjectExtendedLimitInformation: u32 = 9;

        var ext_limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = .{};
        var limit_flags: u32 = 0;

        if (self.limits.active_process_limit) |limit| {
            ext_limit.BasicLimitInformation.ActiveProcessLimit = limit;
            limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }

        if (self.limits.process_memory_limit) |limit| {
            ext_limit.ProcessMemoryLimit = limit;
            limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }

        if (self.limits.job_memory_limit) |limit| {
            ext_limit.JobMemoryLimit = limit;
            limit_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }

        if (self.limits.kill_on_job_close) {
            limit_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }

        if (self.limits.die_on_unhandled_exception) {
            limit_flags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        }

        ext_limit.BasicLimitInformation.LimitFlags = limit_flags;

        const result = set_info.?(
            self.job_handle.?,
            JobObjectExtendedLimitInformation,
            @ptrCast(&ext_limit),
            @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
        );

        if (result == 0) {
            return SandboxError.JobObjectConfigFailed;
        }
    }

    fn applyUiRestrictions(self: *JobObjectSandbox) SandboxError!void {
        if (builtin.os.tag != .windows) return;
        if (self.job_handle == null) return SandboxError.InvalidConfiguration;

        // UI restrictions prevent desktop/clipboard/handle leakage.
        const set_info = @extern(?*const fn (*anyopaque, u32, *anyopaque, u32) callconv(.winapi) c_int, .{
            .name = "SetInformationJobObject",
        });

        if (set_info == null) return SandboxError.JobObjectConfigFailed;

        const JobObjectBasicUIRestrictions: u32 = 4;

        var ui_flags: u32 = 0;

        if (self.ui_restrictions.restrict_desktop) {
            ui_flags |= JOB_OBJECT_UILIMIT_DESKTOP;
        }
        if (self.ui_restrictions.restrict_clipboard) {
            ui_flags |= JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        }
        if (self.ui_restrictions.restrict_global_atoms) {
            ui_flags |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
        }
        if (self.ui_restrictions.restrict_handles) {
            ui_flags |= JOB_OBJECT_UILIMIT_HANDLES;
        }

        var ui_info = JOBOBJECT_BASIC_UI_RESTRICTIONS{ .UIRestrictionsClass = ui_flags };

        const result = set_info.?(
            self.job_handle.?,
            JobObjectBasicUIRestrictions,
            @ptrCast(&ui_info),
            @sizeOf(JOBOBJECT_BASIC_UI_RESTRICTIONS),
        );

        if (result == 0) {
            return SandboxError.JobObjectConfigFailed;
        }
    }

    pub fn assignCurrentProcess(self: *JobObjectSandbox) SandboxError!void {
        if (builtin.os.tag != .windows) return;
        if (self.job_handle == null) return SandboxError.InvalidConfiguration;

        // Attach the current process so limits apply to this runner.
        const get_current = @extern(?*const fn () callconv(.winapi) *anyopaque, .{
            .name = "GetCurrentProcess",
        });
        const assign = @extern(?*const fn (*anyopaque, *anyopaque) callconv(.winapi) c_int, .{
            .name = "AssignProcessToJobObject",
        });

        if (get_current == null or assign == null) {
            return SandboxError.ProcessAssignmentFailed;
        }

        const current = get_current.?();
        const result = assign.?(self.job_handle.?, current);

        if (result == 0) {
            log.err("AssignProcessToJobObject failed", .{});
            return SandboxError.ProcessAssignmentFailed;
        }

        log.info("Process assigned to job object", .{});
    }
};

pub const VmmSandboxOptions = struct {
    memory_limit: ?u64 = null,
    allow_clipboard: bool = false,
};

pub fn applyVmmSandbox(allocator: std.mem.Allocator, options: VmmSandboxOptions) SandboxError!void {
    if (builtin.os.tag != .windows) return;

    var sandbox = JobObjectSandbox.init(allocator);
    defer sandbox.deinit();

    sandbox.limits = .{
        .active_process_limit = 1,
        .process_memory_limit = options.memory_limit,
        .kill_on_job_close = true,
        .die_on_unhandled_exception = true,
    };

    sandbox.ui_restrictions = .{
        .restrict_desktop = true,
        .restrict_clipboard = !options.allow_clipboard,
        .restrict_global_atoms = true,
        .restrict_handles = true,
    };

    try sandbox.create();
    try sandbox.assignCurrentProcess();
}

pub fn isJobObjectAvailable() bool {
    if (builtin.os.tag != .windows) return false;
    return true;
}

test "sandbox_windows: JobLimits defaults" {
    const limits = JobLimits{};
    try std.testing.expectEqual(@as(?u32, 1), limits.active_process_limit);
    try std.testing.expect(limits.kill_on_job_close);
    try std.testing.expect(limits.die_on_unhandled_exception);
}

test "sandbox_windows: UiRestrictions defaults" {
    const ui = UiRestrictions{};
    try std.testing.expect(ui.restrict_desktop);
    try std.testing.expect(ui.restrict_clipboard);
    try std.testing.expect(ui.restrict_global_atoms);
    try std.testing.expect(ui.restrict_handles);
}

test "sandbox_windows: JobObjectSandbox init" {
    const allocator = std.testing.allocator;

    var sandbox = JobObjectSandbox.init(allocator);
    defer sandbox.deinit();

    try std.testing.expect(sandbox.job_handle == null);
    try std.testing.expectEqual(@as(?u32, 1), sandbox.limits.active_process_limit);
}

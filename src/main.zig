//! m80 CLI Entry Point

const std = @import("std");
const core = @import("core.zig");
const errors = core.errors;
const log = @import("util/log.zig");

const cli_dispatch = @import("cli/dispatch.zig");
const cli_help = @import("cli/help.zig");
const daemon_cmd = @import("cli/commands/daemon.zig");
const lifecycle = @import("cli/commands/lifecycle.zig");
const console_cmd = @import("cli/commands/console.zig");
const snapshot_restore = @import("cli/commands/snapshot_restore.zig");
const vm_admin = @import("cli/commands/vm_admin.zig");

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.initFromEnv(allocator);

    var args_arena = std.heap.ArenaAllocator.init(allocator);
    defer args_arena.deinit();
    const args = try init.minimal.args.toSlice(args_arena.allocator());

    const command = cli_dispatch.parseArgs(args) catch |e| switch (e) {
        error.MissingName => errors.die("missing <name>", .{}),
        error.MissingPath => {
            if (args.len >= 2 and std.mem.eql(u8, args[1], "snapshot")) {
                errors.die("usage: m80 snapshot <name> <path>", .{});
            }
            errors.die("usage: m80 restore <name> <path>", .{});
        },
        error.MissingCloneName => errors.die("usage: m80 clone <name> <new-name>", .{}),
        error.MissingDaemonCommand => errors.die("usage: m80 daemon <run|start|stop|status>", .{}),
        error.InvalidVmName => {
            if (args.len >= 3) {
                errors.die("invalid vm name: {s}", .{args[2]});
            }
            errors.die("invalid vm name", .{});
        },
        error.InvalidCloneName => {
            if (args.len >= 4) {
                errors.die("invalid vm name: {s}", .{args[3]});
            }
            errors.die("invalid vm name", .{});
        },
        error.UnknownCommand => {
            if (args.len >= 2) {
                errors.die("unknown command: {s}", .{args[1]});
            }
            errors.die("unknown command", .{});
        },
        error.UnknownDaemonCommand => {
            if (args.len >= 3) {
                errors.die("unknown daemon command: {s}", .{args[2]});
            }
            errors.die("unknown daemon command", .{});
        },
    };

    switch (command) {
        .help => cli_help.printHelp(),
        .ps => try vm_admin.runPs(allocator),
        .daemon => |cmd| try daemon_cmd.run(allocator, cmd),
        .init => |name| try vm_admin.runInit(allocator, name),
        .delete => |name| try vm_admin.runDelete(allocator, name),
        .start => |name| try lifecycle.runStart(allocator, name),
        .run => |name| try lifecycle.runRun(allocator, name),
        .console => |name| try console_cmd.runConsole(allocator, name),
        .stop => |name| try lifecycle.runStop(allocator, name),
        .inspect => |name| try vm_admin.runInspect(allocator, name),
        .snapshot => |arg| try snapshot_restore.runSnapshot(allocator, arg.name, arg.path),
        .restore => |arg| try snapshot_restore.runRestore(allocator, arg.name, arg.path),
        .clone => |arg| try vm_admin.runClone(allocator, arg.name, arg.other),
    }
}

const std = @import("std");
const core = @import("../core.zig");

pub const Command = union(enum) {
    help,
    ps,
    init: []const u8,
    delete: []const u8,
    start: []const u8,
    run: []const u8,
    console: []const u8,
    stop: []const u8,
    inspect: []const u8,
    snapshot: NamePath,
    restore: NamePath,
    clone: NamePair,
};

pub const NamePath = struct {
    name: []const u8,
    path: []const u8,
};

pub const NamePair = struct {
    name: []const u8,
    other: []const u8,
};

pub const ParseError = error{
    MissingName,
    MissingPath,
    MissingCloneName,
    UnknownCommand,
    InvalidVmName,
    InvalidCloneName,
};

pub fn parseArgs(args: []const []const u8) ParseError!Command {
    if (args.len < 2) return .help;
    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        return .help;
    }
    if (std.mem.eql(u8, cmd, "ps")) return .ps;

    if (args.len < 3) return error.MissingName;
    const name = args[2];
    if (!core.paths.validateVmName(name)) return error.InvalidVmName;

    if (std.mem.eql(u8, cmd, "init")) return .{ .init = name };
    if (std.mem.eql(u8, cmd, "delete")) return .{ .delete = name };
    if (std.mem.eql(u8, cmd, "start")) return .{ .start = name };
    if (std.mem.eql(u8, cmd, "run")) return .{ .run = name };
    if (std.mem.eql(u8, cmd, "console")) return .{ .console = name };
    if (std.mem.eql(u8, cmd, "stop")) return .{ .stop = name };
    if (std.mem.eql(u8, cmd, "inspect")) return .{ .inspect = name };

    if (std.mem.eql(u8, cmd, "snapshot")) {
        if (args.len < 4) return error.MissingPath;
        return .{ .snapshot = .{ .name = name, .path = args[3] } };
    }
    if (std.mem.eql(u8, cmd, "restore")) {
        if (args.len < 4) return error.MissingPath;
        return .{ .restore = .{ .name = name, .path = args[3] } };
    }
    if (std.mem.eql(u8, cmd, "clone")) {
        if (args.len < 4) return error.MissingCloneName;
        const other = args[3];
        if (!core.paths.validateVmName(other)) return error.InvalidCloneName;
        return .{ .clone = .{ .name = name, .other = other } };
    }

    return error.UnknownCommand;
}

test "dispatch: help aliases parse to help" {
    const cases = [_][]const []const u8{
        &[_][]const u8{"m80"},
        &[_][]const u8{ "m80", "help" },
        &[_][]const u8{ "m80", "--help" },
        &[_][]const u8{ "m80", "-h" },
    };

    for (cases) |args| {
        const cmd = try parseArgs(args);
        try std.testing.expectEqual(Command.help, cmd);
    }
}

test "dispatch: command requiring name returns MissingName" {
    try std.testing.expectError(error.MissingName, parseArgs(&[_][]const u8{ "m80", "start" }));
}

test "dispatch: invalid vm name is rejected" {
    try std.testing.expectError(error.InvalidVmName, parseArgs(&[_][]const u8{ "m80", "start", ".." }));
}

test "dispatch: snapshot missing path is rejected" {
    try std.testing.expectError(error.MissingPath, parseArgs(&[_][]const u8{ "m80", "snapshot", "vm1" }));
}

test "dispatch: clone validates destination name" {
    try std.testing.expectError(error.InvalidCloneName, parseArgs(&[_][]const u8{ "m80", "clone", "vm1", ".." }));
}

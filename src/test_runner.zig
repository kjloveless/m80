//! ╔═══════════════════════════════════════════════════════════════════════════╗
//! ║                        M80 CUSTOM TEST RUNNER                             ║
//! ╚═══════════════════════════════════════════════════════════════════════════╝
//!
//! A visually stunning test runner with:
//! - Animated progress bar with color gradients
//! - Real-time test execution with timing
//! - Module-based test grouping and statistics
//! - Memory leak detection per test
//! - Slowest tests report
//! - Beautiful summary dashboard
//!

const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

// ═══════════════════════════════════════════════════════════════════════════════
// ANSI ESCAPE CODES
// ═══════════════════════════════════════════════════════════════════════════════

const Ansi = struct {
    // Reset
    const reset = "\x1b[0m";

    // Styles
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const italic = "\x1b[3m";
    const underline = "\x1b[4m";

    // Foreground colors
    const black = "\x1b[30m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const magenta = "\x1b[35m";
    const cyan = "\x1b[36m";
    const white = "\x1b[37m";

    // Bright foreground
    const bright_black = "\x1b[90m";
    const bright_red = "\x1b[91m";
    const bright_green = "\x1b[92m";
    const bright_yellow = "\x1b[93m";
    const bright_blue = "\x1b[94m";
    const bright_magenta = "\x1b[95m";
    const bright_cyan = "\x1b[96m";
    const bright_white = "\x1b[97m";

    // Background colors
    const bg_red = "\x1b[41m";
    const bg_green = "\x1b[42m";
    const bg_yellow = "\x1b[43m";
    const bg_blue = "\x1b[44m";
    const bg_magenta = "\x1b[45m";
    const bg_cyan = "\x1b[46m";

    // Cursor control
    const hide_cursor = "\x1b[?25l";
    const show_cursor = "\x1b[?25h";
    const clear_line = "\x1b[2K";
    const move_up = "\x1b[1A";
    const save_cursor = "\x1b[s";
    const restore_cursor = "\x1b[u";
};

const AnsiPalette = struct {
    reset: []const u8,
    bold: []const u8,
    dim: []const u8,
    italic: []const u8,
    underline: []const u8,
    black: []const u8,
    red: []const u8,
    green: []const u8,
    yellow: []const u8,
    blue: []const u8,
    magenta: []const u8,
    cyan: []const u8,
    white: []const u8,
    bright_black: []const u8,
    bright_red: []const u8,
    bright_green: []const u8,
    bright_yellow: []const u8,
    bright_blue: []const u8,
    bright_magenta: []const u8,
    bright_cyan: []const u8,
    bright_white: []const u8,
    bg_red: []const u8,
    bg_green: []const u8,
    bg_yellow: []const u8,
    bg_blue: []const u8,
    bg_magenta: []const u8,
    bg_cyan: []const u8,
    hide_cursor: []const u8,
    show_cursor: []const u8,
    clear_line: []const u8,
    move_up: []const u8,
    save_cursor: []const u8,
    restore_cursor: []const u8,
};

fn palette(use_ansi: bool) AnsiPalette {
    if (use_ansi) {
        return .{
            .reset = Ansi.reset,
            .bold = Ansi.bold,
            .dim = Ansi.dim,
            .italic = Ansi.italic,
            .underline = Ansi.underline,
            .black = Ansi.black,
            .red = Ansi.red,
            .green = Ansi.green,
            .yellow = Ansi.yellow,
            .blue = Ansi.blue,
            .magenta = Ansi.magenta,
            .cyan = Ansi.cyan,
            .white = Ansi.white,
            .bright_black = Ansi.bright_black,
            .bright_red = Ansi.bright_red,
            .bright_green = Ansi.bright_green,
            .bright_yellow = Ansi.bright_yellow,
            .bright_blue = Ansi.bright_blue,
            .bright_magenta = Ansi.bright_magenta,
            .bright_cyan = Ansi.bright_cyan,
            .bright_white = Ansi.bright_white,
            .bg_red = Ansi.bg_red,
            .bg_green = Ansi.bg_green,
            .bg_yellow = Ansi.bg_yellow,
            .bg_blue = Ansi.bg_blue,
            .bg_magenta = Ansi.bg_magenta,
            .bg_cyan = Ansi.bg_cyan,
            .hide_cursor = Ansi.hide_cursor,
            .show_cursor = Ansi.show_cursor,
            .clear_line = Ansi.clear_line,
            .move_up = Ansi.move_up,
            .save_cursor = Ansi.save_cursor,
            .restore_cursor = Ansi.restore_cursor,
        };
    }
    return .{
        .reset = "",
        .bold = "",
        .dim = "",
        .italic = "",
        .underline = "",
        .black = "",
        .red = "",
        .green = "",
        .yellow = "",
        .blue = "",
        .magenta = "",
        .cyan = "",
        .white = "",
        .bright_black = "",
        .bright_red = "",
        .bright_green = "",
        .bright_yellow = "",
        .bright_blue = "",
        .bright_magenta = "",
        .bright_cyan = "",
        .bright_white = "",
        .bg_red = "",
        .bg_green = "",
        .bg_yellow = "",
        .bg_blue = "",
        .bg_magenta = "",
        .bg_cyan = "",
        .hide_cursor = "",
        .show_cursor = "",
        .clear_line = "",
        .move_up = "",
        .save_cursor = "",
        .restore_cursor = "",
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// VISUAL ELEMENTS
// ═══════════════════════════════════════════════════════════════════════════════

const Visual = struct {
    // Box drawing
    const top_left = "╔";
    const top_right = "╗";
    const bottom_left = "╚";
    const bottom_right = "╝";
    const horizontal = "═";
    const vertical = "║";
    const t_down = "╦";
    const t_up = "╩";
    const t_right = "╠";
    const t_left = "╣";
    const cross = "╬";

    // Light box drawing
    const l_top_left = "┌";
    const l_top_right = "┐";
    const l_bottom_left = "└";
    const l_bottom_right = "┘";
    const l_horizontal = "─";
    const l_vertical = "│";

    // Progress bar elements
    const bar_full = "█";
    const bar_seven_eighths = "▉";
    const bar_three_quarters = "▊";
    const bar_five_eighths = "▋";
    const bar_half = "▌";
    const bar_three_eighths = "▍";
    const bar_quarter = "▎";
    const bar_eighth = "▏";
    const bar_empty = "░";

    // Status icons
    const check = "✓";
    const cross_mark = "✗";
    const skip = "⊘";
    const leak = "💧";
    const clock = "⏱";
    const rocket = "🚀";
    const fire = "🔥";
    const warning = "⚠";
    const sparkles = "✨";
    const trophy = "🏆";
    const chart = "📊";
    const gear = "⚙";
    const bolt = "⚡";

    // Spinner frames
    const spinner = [_][]const u8{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
};

// ═══════════════════════════════════════════════════════════════════════════════
// TEST RESULT TRACKING
// ═══════════════════════════════════════════════════════════════════════════════

const TestResult = struct {
    name: []const u8,
    module: []const u8,
    status: Status,
    duration_ns: u64,
    leaked: bool,

    const Status = enum {
        passed,
        failed,
        skipped,
    };
};

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

const ModuleStats = struct {
    name: []const u8,
    passed: usize,
    failed: usize,
    skipped: usize,
    total_time_ns: u64,
};

// ═══════════════════════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════════════════════

pub const std_options: std.Options = .{
    .logFn = log,
};

var log_err_count: usize = 0;

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    @disableInstrumentation();
    if (@intFromEnum(message_level) <= @intFromEnum(std.log.Level.err)) {
        log_err_count +|= 1;
    }
    if (@intFromEnum(message_level) <= @intFromEnum(testing.log_level)) {
        std.debug.print(
            Ansi.dim ++ "[" ++ @tagName(scope) ++ "] (" ++ @tagName(message_level) ++ "): " ++ format ++ Ansi.reset ++ "\n",
            args,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

pub fn main() !void {
    @disableInstrumentation();

    if (builtin.cpu.arch.isSpirV()) {
        return;
    }

    const test_fns = builtin.test_functions;
    const TestFn = @TypeOf(test_fns[0]);

    // Detect if we're in a TTY for fancy output
    const use_ansi = blk: {
        // Check stderr (fd 2) for TTY
        if (@hasDecl(std.posix, "isatty")) {
            break :blk std.posix.isatty(std.posix.STDERR_FILENO);
        }
        // Fallback: assume TTY on most systems
        break :blk true;
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_filter = parseTestFilter(allocator);
    defer if (test_filter) |value| allocator.free(value);

    var selected_tests = std.ArrayList(TestFn).empty;
    defer selected_tests.deinit(allocator);

    for (test_fns) |test_fn| {
        if (test_filter) |filter| {
            if (std.mem.indexOf(u8, test_fn.name, filter) == null) continue;
        }
        try selected_tests.append(allocator, test_fn);
    }

    var results = try allocator.alloc(TestResult, selected_tests.items.len);
    defer allocator.free(results);

    // Print header
    printHeader(use_ansi, selected_tests.items.len);

    // Hide cursor during test execution
    if (use_ansi) std.debug.print("{s}", .{Ansi.hide_cursor});
    defer if (use_ansi) std.debug.print("{s}", .{Ansi.show_cursor});

    var ok_count: usize = 0;
    var skip_count: usize = 0;
    var fail_count: usize = 0;
    var leak_count: usize = 0;
    var total_time: u64 = 0;

    const start_time = std.time.nanoTimestamp();

    // Run all tests
    for (selected_tests.items, 0..) |test_fn, i| {
        // Fresh allocator per test for leak detection
        testing.allocator_instance = .{};

        testing.log_level = .warn;

        // Extract module name from test name (before the colon)
        const module_name = extractModule(test_fn.name);

        // Print progress
        if (use_ansi) {
            printProgress(i, selected_tests.items.len, test_fn.name, ok_count, fail_count, skip_count);
        }

        // Time the test
        const test_start = std.time.nanoTimestamp();
        const test_result = test_fn.func();
        const test_end = std.time.nanoTimestamp();
        const duration: u64 = @intCast(@max(0, test_end - test_start));

        // Check for leaks
        const leaked = testing.allocator_instance.deinit() == .leak;
        if (leaked) leak_count += 1;

        // Record result
        if (test_result) |_| {
            ok_count += 1;
            results[i] = .{
                .name = test_fn.name,
                .module = module_name,
                .status = .passed,
                .duration_ns = duration,
                .leaked = leaked,
            };
        } else |err| switch (err) {
            error.SkipZigTest => {
                skip_count += 1;
                results[i] = .{
                    .name = test_fn.name,
                    .module = module_name,
                    .status = .skipped,
                    .duration_ns = duration,
                    .leaked = leaked,
                };
            },
            else => {
                fail_count += 1;
                results[i] = .{
                    .name = test_fn.name,
                    .module = module_name,
                    .status = .failed,
                    .duration_ns = duration,
                    .leaked = leaked,
                };

                // Print failure details immediately
                if (use_ansi) {
                    std.debug.print("{s}\r{s}", .{ Ansi.clear_line, Ansi.reset });
                }
                std.debug.print("{s}{s} FAIL {s} {s}{s} ({s})\n", .{
                    if (use_ansi) Ansi.bold ++ Ansi.red else "",
                    Visual.cross_mark,
                    if (use_ansi) Ansi.reset ++ Ansi.white else "",
                    test_fn.name,
                    if (use_ansi) Ansi.dim else "",
                    @errorName(err),
                });
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
            },
        }

        total_time += duration;
    }

    const end_time = std.time.nanoTimestamp();
    const wall_time: u64 = @intCast(@max(0, end_time - start_time));

    // Clear progress line
    if (use_ansi) {
        std.debug.print("{s}\r", .{Ansi.clear_line});
    }

    // Print results
    std.debug.print("\n", .{});
    printModuleBreakdown(results, use_ansi, allocator) catch {};
    std.debug.print("\n", .{});
    printSlowestTests(results, use_ansi);
    std.debug.print("\n", .{});
    printSummary(ok_count, fail_count, skip_count, leak_count, log_err_count, wall_time, total_time, selected_tests.items.len, use_ansi);

    // Exit with appropriate code
    if (fail_count != 0 or leak_count != 0 or log_err_count != 0) {
        std.process.exit(1);
    }
}

fn parseTestFilter(allocator: std.mem.Allocator) ?[]u8 {
    const args = std.process.argsAlloc(allocator) catch return null;
    defer std.process.argsFree(allocator, args);

    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--test-filter")) {
            if (idx + 1 < args.len) {
                return allocator.dupe(u8, args[idx + 1]) catch null;
            }
            return null;
        }
        const prefix = "--test-filter=";
        if (std.mem.startsWith(u8, arg, prefix)) {
            return allocator.dupe(u8, arg[prefix.len..]) catch null;
        }
    }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISPLAY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn printHeader(use_ansi: bool, total_tests: usize) void {
    const a = palette(use_ansi);

    std.debug.print("\n", .{});
    std.debug.print("{s}", .{a.bright_cyan});
    std.debug.print("    ╔══════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("    ║{s}                                                              {s}║\n", .{ a.reset, a.bright_cyan });
    std.debug.print("    ║{s}   ███╗   ███╗ █████╗  ██████╗     {s}{s}TEST SUITE{s}                 {s}║\n", .{ a.magenta, a.white, a.bold, a.reset, a.bright_cyan });
    std.debug.print("    ║{s}   ████╗ ████║██╔══██╗██╔═══██╗    {s}─────────────────────────  {s}║\n", .{ a.magenta, a.dim, a.bright_cyan });
    std.debug.print("    ║{s}   ██╔████╔██║╚█████╔╝██║   ██║    {s}{d:>4} tests loaded {s}         {s}║\n", .{ a.magenta, a.white, total_tests, Visual.rocket, a.bright_cyan });
    std.debug.print("    ║{s}   ██║╚██╔╝██║██╔══██╗██║   ██║                                {s}║\n", .{ a.magenta, a.bright_cyan });
    std.debug.print("    ║{s}   ██║ ╚═╝ ██║╚█████╔╝╚██████╔╝    {s}microvm runtime{s}            {s}║\n", .{ a.magenta, a.dim, a.reset, a.bright_cyan });
    std.debug.print("    ║{s}   ╚═╝     ╚═╝ ╚════╝  ╚═════╝                                 {s}║\n", .{ a.magenta, a.bright_cyan });
    std.debug.print("    ║{s}                                                              {s}║\n", .{ a.reset, a.bright_cyan });
    std.debug.print("    ╚══════════════════════════════════════════════════════════════╝{s}\n", .{a.reset});
    std.debug.print("\n", .{});
}

fn printProgress(current: usize, total: usize, test_name: []const u8, passed: usize, failed: usize, skipped: usize) void {
    const percent: usize = if (total == 0) 0 else (current * 100) / total;
    const bar_width: usize = 30;
    const filled: usize = if (total == 0) 0 else (current * bar_width) / total;

    // Spinner animation
    const spinner_idx = current % Visual.spinner.len;

    std.debug.print("{s}\r", .{Ansi.clear_line});

    // Spinner and progress
    std.debug.print("  {s}{s}{s} ", .{ Ansi.cyan, Visual.spinner[spinner_idx], Ansi.reset });

    // Progress bar with gradient
    std.debug.print("{s}[", .{Ansi.dim});
    for (0..bar_width) |i| {
        if (i < filled) {
            // Color gradient from cyan to green
            if (i < bar_width / 3) {
                std.debug.print("{s}{s}", .{ Ansi.cyan, Visual.bar_full });
            } else if (i < (bar_width * 2) / 3) {
                std.debug.print("{s}{s}", .{ Ansi.bright_cyan, Visual.bar_full });
            } else {
                std.debug.print("{s}{s}", .{ Ansi.green, Visual.bar_full });
            }
        } else {
            std.debug.print("{s}{s}", .{ Ansi.bright_black, Visual.bar_empty });
        }
    }
    std.debug.print("{s}] {s}{d:>3}%{s}", .{ Ansi.dim, Ansi.bold ++ Ansi.white, percent, Ansi.reset });

    // Stats
    std.debug.print("  {s}{s}{d}{s}", .{ Ansi.green, Visual.check, passed, Ansi.reset });
    if (failed > 0) {
        std.debug.print(" {s}{s}{d}{s}", .{ Ansi.red, Visual.cross_mark, failed, Ansi.reset });
    }
    if (skipped > 0) {
        std.debug.print(" {s}{s}{d}{s}", .{ Ansi.yellow, Visual.skip, skipped, Ansi.reset });
    }

    // Current test name (truncated)
    const max_name_len: usize = 35;
    const display_name = if (test_name.len > max_name_len)
        test_name[0..max_name_len]
    else
        test_name;
    std.debug.print("  {s}{s}{s}", .{ Ansi.dim, display_name, Ansi.reset });
}

fn extractModule(test_name: []const u8) []const u8 {
    // Find the colon separator (e.g., "config: test name" -> "config")
    for (test_name, 0..) |c, i| {
        if (c == ':') {
            return test_name[0..i];
        }
    }
    // Check for "test." prefix pattern
    if (std.mem.startsWith(u8, test_name, "test.")) {
        const rest = test_name[5..];
        for (rest, 0..) |c, i| {
            if (c == '.') {
                return rest[0..i];
            }
        }
    }
    return "misc";
}

fn printModuleBreakdown(results: []const TestResult, use_ansi: bool, allocator: std.mem.Allocator) !void {
    const a = palette(use_ansi);

    // Collect unique modules and their stats
    var module_map = std.StringHashMap(ModuleStats).init(allocator);
    defer module_map.deinit();

    for (results) |result| {
        const gop = try module_map.getOrPut(result.module);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .name = result.module,
                .passed = 0,
                .failed = 0,
                .skipped = 0,
                .total_time_ns = 0,
            };
        }
        switch (result.status) {
            .passed => gop.value_ptr.passed += 1,
            .failed => gop.value_ptr.failed += 1,
            .skipped => gop.value_ptr.skipped += 1,
        }
        gop.value_ptr.total_time_ns += result.duration_ns;
    }

    std.debug.print("  {s}{s}{s} MODULE BREAKDOWN{s}\n", .{ a.bold, a.cyan, Visual.chart, a.reset });
    std.debug.print("  {s}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{s}\n", .{ a.dim, a.reset });

    // Sort modules by name for consistent output
    var modules = try allocator.alloc(ModuleStats, module_map.count());
    defer allocator.free(modules);

    var i: usize = 0;
    var iter = module_map.valueIterator();
    while (iter.next()) |stats| {
        modules[i] = stats.*;
        i += 1;
    }

    // Simple bubble sort by name
    for (0..modules.len) |j| {
        for (j + 1..modules.len) |k| {
            if (std.mem.order(u8, modules[j].name, modules[k].name) == .gt) {
                const tmp = modules[j];
                modules[j] = modules[k];
                modules[k] = tmp;
            }
        }
    }

    for (modules) |mod| {
        const total = mod.passed + mod.failed + mod.skipped;
        const pass_pct: usize = if (total == 0) 0 else (mod.passed * 100) / total;
        const time_ms = mod.total_time_ns / 1_000_000;

        // Module name (padded)
        std.debug.print("  {s}{s:<15}{s}", .{ a.white, mod.name, a.reset });

        // Mini progress bar
        const bar_len: usize = 20;
        const filled_len: usize = if (total == 0) 0 else (mod.passed * bar_len) / total;
        const failed_len: usize = if (total == 0) 0 else (mod.failed * bar_len) / total;

        for (0..bar_len) |bi| {
            if (bi < filled_len) {
                std.debug.print("{s}█{s}", .{ a.green, a.reset });
            } else if (bi < filled_len + failed_len) {
                std.debug.print("{s}█{s}", .{ a.red, a.reset });
            } else {
                std.debug.print("{s}░{s}", .{ a.dim, a.reset });
            }
        }

        // Stats
        std.debug.print(" {s}{d:>3}%{s}", .{ if (pass_pct == 100) a.green else a.white, pass_pct, a.reset });
        std.debug.print("  {s}{s}{d}{s}", .{ a.green, Visual.check, mod.passed, a.reset });
        if (mod.failed > 0) {
            std.debug.print(" {s}{s}{d}{s}", .{ a.red, Visual.cross_mark, mod.failed, a.reset });
        }
        if (mod.skipped > 0) {
            std.debug.print(" {s}{s}{d}{s}", .{ a.yellow, Visual.skip, mod.skipped, a.reset });
        }
        std.debug.print("  {s}{d}ms{s}\n", .{ a.dim, time_ms, a.reset });
    }
}

fn printSlowestTests(results: []const TestResult, use_ansi: bool) void {
    const a = palette(use_ansi);

    // Find top 5 slowest tests
    var slowest: [5]struct { idx: usize, time: u64 } = .{
        .{ .idx = 0, .time = 0 },
        .{ .idx = 0, .time = 0 },
        .{ .idx = 0, .time = 0 },
        .{ .idx = 0, .time = 0 },
        .{ .idx = 0, .time = 0 },
    };

    for (results, 0..) |result, i| {
        // Find where this result fits in the top 5
        for (&slowest) |*s| {
            if (result.duration_ns > s.time) {
                // Shift everything down
                var j: usize = slowest.len - 1;
                while (j > (@intFromPtr(s) - @intFromPtr(&slowest[0])) / @sizeOf(@TypeOf(slowest[0]))) : (j -= 1) {
                    slowest[j] = slowest[j - 1];
                    if (j == 0) break;
                }
                s.* = .{ .idx = i, .time = result.duration_ns };
                break;
            }
        }
    }

    std.debug.print("  {s}{s}{s} SLOWEST TESTS{s}\n", .{ a.bold, a.yellow, Visual.clock, a.reset });
    std.debug.print("  {s}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{s}\n", .{ a.dim, a.reset });

    for (slowest, 0..) |s, rank| {
        if (s.time == 0) continue;
        const result = results[s.idx];
        const time_us = s.time / 1_000;
        const time_ms = s.time / 1_000_000;

        std.debug.print("  {s}#{d}{s} ", .{ a.bright_yellow, rank + 1, a.reset });

        if (time_ms > 0) {
            std.debug.print("{s}{d:>6}ms{s}  ", .{ a.yellow, time_ms, a.reset });
        } else {
            std.debug.print("{s}{d:>6}μs{s}  ", .{ a.dim, time_us, a.reset });
        }

        // Truncate name if too long
        const max_len: usize = 50;
        const name = if (result.name.len > max_len) result.name[0..max_len] else result.name;
        std.debug.print("{s}{s}{s}\n", .{ a.white, name, a.reset });
    }
}

fn printSummary(
    passed: usize,
    failed: usize,
    skipped: usize,
    leaks: usize,
    errors: usize,
    wall_time_ns: u64,
    cpu_time_ns: u64,
    total: usize,
    use_ansi: bool,
) void {
    const a = palette(use_ansi);

    const all_passed = failed == 0 and leaks == 0 and errors == 0;
    const pass_rate: usize = if (total == 0) 0 else (passed * 100) / total;

    const wall_ms = wall_time_ns / 1_000_000;
    const cpu_ms = cpu_time_ns / 1_000_000;

    std.debug.print("\n", .{});

    if (all_passed) {
        // Celebration banner!
        std.debug.print("  {s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ a.bright_green, a.reset });
        std.debug.print("  {s}║{s}                                                              {s}║{s}\n", .{ a.bright_green, a.reset, a.bright_green, a.reset });
        std.debug.print("  {s}║{s}     {s}{s}{s}  ALL TESTS PASSED!  {s}{s}                            {s}║{s}\n", .{
            a.bright_green,
            a.reset,
            Visual.sparkles,
            a.bold,
            a.bright_green,
            Visual.sparkles,
            a.reset,
            a.bright_green,
            a.reset,
        });
        std.debug.print("  {s}║{s}                                                              {s}║{s}\n", .{ a.bright_green, a.reset, a.bright_green, a.reset });
        std.debug.print("  {s}║{s}        {s}     {s}{s}{d} tests {s}{s}  •  {s} {d}ms wall  {s}{s}  •  {s} {d}ms cpu         {s}║{s}\n", .{
            a.bright_green,
            a.reset,
            Visual.trophy,
            a.bold,
            a.white,
            total,
            a.reset,
            a.dim,
            Visual.bolt,
            wall_ms,
            a.reset,
            a.dim,
            Visual.gear,
            cpu_ms,
            a.bright_green,
            a.reset,
        });
        std.debug.print("  {s}║{s}                                                              {s}║{s}\n", .{ a.bright_green, a.reset, a.bright_green, a.reset });
        std.debug.print("  {s}╚══════════════════════════════════════════════════════════════╝{s}\n", .{ a.bright_green, a.reset });
    } else {
        // Failure summary
        std.debug.print("  {s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ a.bright_red, a.reset });
        std.debug.print("  {s}║{s}                                                              {s}║{s}\n", .{ a.bright_red, a.reset, a.bright_red, a.reset });
        std.debug.print("  {s}║{s}     {s}{s}{s}  TEST SUITE FAILED  {s}{s}                             {s}║{s}\n", .{
            a.bright_red,
            a.reset,
            Visual.warning,
            a.bold,
            a.bright_red,
            Visual.warning,
            a.reset,
            a.bright_red,
            a.reset,
        });
        std.debug.print("  {s}║{s}                                                              {s}║{s}\n", .{ a.bright_red, a.reset, a.bright_red, a.reset });
        std.debug.print("  {s}╚══════════════════════════════════════════════════════════════╝{s}\n", .{ a.bright_red, a.reset });
    }

    std.debug.print("\n", .{});

    // Detailed stats
    std.debug.print("  {s}{s}{s} SUMMARY{s}\n", .{ a.bold, a.cyan, Visual.chart, a.reset });
    std.debug.print("  {s}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{s}\n", .{ a.dim, a.reset });

    // Pass rate bar
    const bar_width: usize = 40;
    const passed_width: usize = if (total == 0) 0 else (passed * bar_width) / total;
    const failed_width: usize = if (total == 0) 0 else (failed * bar_width) / total;
    const skipped_width: usize = if (total == 0) 0 else (skipped * bar_width) / total;

    std.debug.print("  Pass Rate    ", .{});
    for (0..bar_width) |i| {
        if (i < passed_width) {
            std.debug.print("{s}█{s}", .{ a.green, a.reset });
        } else if (i < passed_width + failed_width) {
            std.debug.print("{s}█{s}", .{ a.red, a.reset });
        } else if (i < passed_width + failed_width + skipped_width) {
            std.debug.print("{s}█{s}", .{ a.yellow, a.reset });
        } else {
            std.debug.print("{s}░{s}", .{ a.dim, a.reset });
        }
    }
    std.debug.print(" {s}{d}%{s}\n", .{ if (pass_rate == 100) a.bright_green else a.white, pass_rate, a.reset });

    std.debug.print("\n", .{});

    // Stats grid
    std.debug.print("  {s}{s} Passed:  {s}{d:>5}{s}     ", .{ a.green, Visual.check, a.bold, passed, a.reset });
    std.debug.print("{s}{s} Failed:  {s}{d:>5}{s}\n", .{ a.red, Visual.cross_mark, a.bold, failed, a.reset });
    std.debug.print("  {s}{s} Skipped: {s}{d:>5}{s}     ", .{ a.yellow, Visual.skip, a.bold, skipped, a.reset });
    std.debug.print("{s}{s} Leaks:   {s}{d:>5}{s}\n", .{ a.magenta, Visual.leak, a.bold, leaks, a.reset });

    if (errors > 0) {
        std.debug.print("  {s}{s} Errors:  {s}{d:>5}{s}\n", .{ a.red, Visual.warning, a.bold, errors, a.reset });
    }

    std.debug.print("\n", .{});
    std.debug.print("  {s}Timing:{s}  {s}{d}ms{s} wall  •  {s}{d}ms{s} cpu\n", .{ a.dim, a.reset, a.cyan, wall_ms, a.reset, a.cyan, cpu_ms, a.reset });
    std.debug.print("\n", .{});
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "test_runner: log counts errors" {
    const saved = log_err_count;
    defer log_err_count = saved;

    log_err_count = 0;
    log(.err, .default, "test error {d}", .{1});
    try std.testing.expectEqual(@as(usize, 1), log_err_count);
}

test "test_runner: extract module from test name" {
    try std.testing.expectEqualStrings("config", extractModule("config: parses valid file"));
    try std.testing.expectEqualStrings("state", extractModule("state: initializes vm"));
    try std.testing.expectEqualStrings("misc", extractModule("no colon here"));
}

//! m80 Build Configuration
//!
//! This build script configures the m80 CLI executable and test suite.
//!
//! ## Build Commands
//! - `zig build` - Build the m80 executable
//! - `zig build run -- <args>` - Build and run with arguments
//! - `zig build test` - Run all tests via custom runner
//!
//! ## Platform-Specific Setup
//! - POSIX hosts: Links libc for host filesystem, process, and socket helpers
//! - macOS: Links the Hypervisor.framework for HVF backend
//! - Windows: Uses WHP (no extra linking required)
//! - Linux: Uses KVM
//!
//! ## Test Infrastructure
//! Tests use a custom runner (src/test_runner.zig) that:
//! - Reports progress per test
//! - Detects memory leaks per test
//! - Counts logged errors
//! - All tests are aggregated in src/all_tests.zig

const std = @import("std");

const CodesignConfig = struct {
    identity: ?[]const u8 = null,
    keychain: ?[]const u8 = null,
    provisioning_profile: ?[]const u8 = null,

    fn deinit(self: *CodesignConfig, allocator: std.mem.Allocator) void {
        if (self.identity) |v| allocator.free(v);
        if (self.keychain) |v| allocator.free(v);
        if (self.provisioning_profile) |v| allocator.free(v);
    }
};

fn readBuildRootFileAlloc(b: *std.Build, path: []const u8, max_bytes: usize) ![]u8 {
    const graph_type = @TypeOf(b.graph.*);
    if (comptime @hasField(graph_type, "io")) {
        return b.build_root.handle.readFileAlloc(
            b.graph.io,
            path,
            b.allocator,
            .limited(max_bytes),
        );
    }
    return b.build_root.handle.readFileAlloc(b.allocator, path, max_bytes);
}

fn buildRootFileExists(b: *std.Build, path: []const u8) bool {
    const graph_type = @TypeOf(b.graph.*);
    if (comptime @hasField(graph_type, "io")) {
        b.build_root.handle.access(b.graph.io, path, .{}) catch return false;
        return true;
    }
    b.build_root.handle.access(path, .{}) catch return false;
    return true;
}

fn readCodesignConfig(b: *std.Build, path: []const u8) !CodesignConfig {
    var cfg = CodesignConfig{};
    const data = readBuildRootFileAlloc(b, path, 64 * 1024) catch |e| switch (e) {
        error.FileNotFound => return cfg,
        else => return e,
    };
    defer b.allocator.free(data);

    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t\r");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (key.len == 0) continue;
        if (std.mem.eql(u8, key, "identity")) {
            if (cfg.identity) |v| b.allocator.free(v);
            cfg.identity = try b.allocator.dupe(u8, value);
            continue;
        }
        if (std.mem.eql(u8, key, "keychain")) {
            if (cfg.keychain) |v| b.allocator.free(v);
            cfg.keychain = try b.allocator.dupe(u8, value);
            continue;
        }
        if (std.mem.eql(u8, key, "provisioning_profile")) {
            if (cfg.provisioning_profile) |v| b.allocator.free(v);
            cfg.provisioning_profile = try b.allocator.dupe(u8, value);
            continue;
        }
    }
    return cfg;
}

fn buildEnv(b: *std.Build, key: []const u8) ?[]const u8 {
    const graph_type = @TypeOf(b.graph.*);
    if (comptime @hasField(graph_type, "environ_map")) {
        return b.graph.environ_map.get(key);
    }
    if (comptime @hasField(graph_type, "env_map")) {
        return b.graph.env_map.get(key);
    }
    return null;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "m80",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const needs_libc = target.result.os.tag != .windows;
    exe.root_module.link_libc = needs_libc;

    if (target.result.os.tag == .macos) {
        exe.root_module.linkFramework("Hypervisor", .{});
    }

    const install_exe = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install_exe.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "run m80");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "run tests");
    const test_runner: std.Build.Step.Compile.TestRunner = .{
        .path = b.path("src/test_runner.zig"),
        .mode = .simple,
    };
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/all_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .test_runner = test_runner,
    });
    unit_tests.root_module.link_libc = needs_libc;
    if (target.result.os.tag == .macos) {
        unit_tests.root_module.linkFramework("Hypervisor", .{});
    }
    unit_tests.root_module.addAnonymousImport("build_script", .{
        .root_source_file = b.path("build.zig"),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    if (b.args) |args| {
        run_unit_tests.addArgs(args);
    }
    test_step.dependOn(&run_unit_tests.step);

    if (target.result.os.tag == .macos) {
        var cfg = readCodesignConfig(b, buildEnv(b, "M80_CODESIGN_CONFIG") orelse "codesign.conf") catch CodesignConfig{};
        defer cfg.deinit(b.allocator);

        const entitlements_main_name: []const u8 = "entitlements/hvf-entitlements.xml";
        const entitlements_test_name: []const u8 = "entitlements/hvf-entitlements-test.xml";
        const have_entitlements =
            buildRootFileExists(b, entitlements_main_name) and
            buildRootFileExists(b, entitlements_test_name);
        if (!have_entitlements) return;

        var codesign_identity: []const u8 = cfg.identity orelse "-";
        if (buildEnv(b, "M80_CODESIGN_IDENTITY")) |value| {
            if (value.len != 0) {
                codesign_identity = value;
            }
        }
        var codesign_keychain: ?[]const u8 = cfg.keychain;
        if (buildEnv(b, "M80_CODESIGN_KEYCHAIN")) |value| {
            if (value.len != 0) {
                codesign_keychain = value;
            }
        }
        const entitlements = b.path(entitlements_main_name);
        const entitlements_test = b.path(entitlements_test_name);

        const sign_exe = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            codesign_identity,
        });
        if (codesign_keychain) |kc| {
            sign_exe.addArgs(&[_][]const u8{ "--keychain", kc });
        }
        sign_exe.addArg("--entitlements");
        sign_exe.addFileArg(entitlements);
        sign_exe.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime" });
        if (!std.mem.eql(u8, codesign_identity, "-")) {
            sign_exe.addArg("--timestamp");
        }
        sign_exe.addFileArg(exe.getEmittedBin());
        sign_exe.step.dependOn(&exe.step);
        run_cmd.step.dependOn(&sign_exe.step);

        const sign_installed = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            codesign_identity,
        });
        if (codesign_keychain) |kc| {
            sign_installed.addArgs(&[_][]const u8{ "--keychain", kc });
        }
        sign_installed.addArg("--entitlements");
        sign_installed.addFileArg(entitlements);
        sign_installed.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime" });
        if (!std.mem.eql(u8, codesign_identity, "-")) {
            sign_installed.addArg("--timestamp");
        }
        sign_installed.addArg(b.getInstallPath(.bin, exe.name));
        sign_installed.step.dependOn(&install_exe.step);
        b.getInstallStep().dependOn(&sign_installed.step);

        const sign_tests = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            codesign_identity,
        });
        if (codesign_keychain) |kc| {
            sign_tests.addArgs(&[_][]const u8{ "--keychain", kc });
        }
        sign_tests.addArg("--entitlements");
        sign_tests.addFileArg(entitlements_test);
        sign_tests.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime" });
        if (!std.mem.eql(u8, codesign_identity, "-")) {
            sign_tests.addArg("--timestamp");
        }
        sign_tests.addFileArg(unit_tests.getEmittedBin());
        sign_tests.step.dependOn(&unit_tests.step);
        run_unit_tests.step.dependOn(&sign_tests.step);
    }
}

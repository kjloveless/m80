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
//! - macOS: Links the Hypervisor.framework for HVF backend
//! - Windows: Uses WHP (no extra linking required)
//! - Linux: Uses KVM (no extra linking required)
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

    fn deinit(self: *CodesignConfig, allocator: std.mem.Allocator) void {
        if (self.identity) |v| allocator.free(v);
        if (self.keychain) |v| allocator.free(v);
    }
};

fn readCodesignConfig(allocator: std.mem.Allocator, path: []const u8) !CodesignConfig {
    var cfg = CodesignConfig{};
    var file = std.fs.cwd().openFile(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return cfg,
        else => return e,
    };
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 64 * 1024);
    defer allocator.free(data);

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
            if (cfg.identity) |v| allocator.free(v);
            cfg.identity = try allocator.dupe(u8, value);
            continue;
        }
        if (std.mem.eql(u8, key, "keychain")) {
            if (cfg.keychain) |v| allocator.free(v);
            cfg.keychain = try allocator.dupe(u8, value);
            continue;
        }
    }
    return cfg;
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

    if (target.result.os.tag == .macos) {
        exe.linkFramework("Hypervisor");
    }

    b.installArtifact(exe);

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
    if (target.result.os.tag == .macos) {
        unit_tests.linkFramework("Hypervisor");
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
        const config_path = std.process.getEnvVarOwned(b.allocator, "M80_CODESIGN_CONFIG") catch null;
        defer if (config_path) |p| b.allocator.free(p);
        var cfg = readCodesignConfig(
            b.allocator,
            config_path orelse "codesign.conf",
        ) catch CodesignConfig{};
        defer cfg.deinit(b.allocator);

        const entitlements_name: []const u8 = "entitlements/hvf-entitlements.xml";
        var codesign_identity: []const u8 = cfg.identity orelse "-";
        var codesign_identity_buf: ?[]u8 = null;
        if (std.process.getEnvVarOwned(b.allocator, "M80_CODESIGN_IDENTITY") catch null) |value| {
            if (value.len != 0) {
                codesign_identity = value;
                codesign_identity_buf = value;
            } else {
                b.allocator.free(value);
            }
        }
        var codesign_keychain: ?[]const u8 = cfg.keychain;
        var codesign_keychain_buf: ?[]u8 = null;
        if (std.process.getEnvVarOwned(b.allocator, "M80_CODESIGN_KEYCHAIN") catch null) |value| {
            if (value.len != 0) {
                codesign_keychain = value;
                codesign_keychain_buf = value;
            } else {
                b.allocator.free(value);
            }
        }
        const entitlements = b.path(entitlements_name);

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
        sign_exe.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime", "--timestamp" });
        sign_exe.addFileArg(exe.getEmittedBin());
        sign_exe.step.dependOn(&exe.step);

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
        sign_installed.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime", "--timestamp" });
        sign_installed.addArg(b.getInstallPath(.bin, exe.name));
        sign_installed.step.dependOn(b.getInstallStep());

        const sign_tests = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            codesign_identity,
        });
        if (codesign_keychain) |kc| {
            sign_tests.addArgs(&[_][]const u8{ "--keychain", kc });
        }
        sign_tests.addArg("--entitlements");
        sign_tests.addFileArg(entitlements);
        sign_tests.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime", "--timestamp" });
        sign_tests.addFileArg(unit_tests.getEmittedBin());
        sign_tests.step.dependOn(&unit_tests.step);
        run_unit_tests.step.dependOn(&sign_tests.step);

        run_cmd.step.dependOn(&sign_installed.step);

        if (codesign_identity_buf) |buf| b.allocator.free(buf);
        if (codesign_keychain_buf) |buf| b.allocator.free(buf);
    }
}

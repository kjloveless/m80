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
    vmnet_entitlements: bool = false,
    provisioning_profile: ?[]const u8 = null,

    fn deinit(self: *CodesignConfig, allocator: std.mem.Allocator) void {
        if (self.identity) |v| allocator.free(v);
        if (self.keychain) |v| allocator.free(v);
        if (self.provisioning_profile) |v| allocator.free(v);
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
        if (std.mem.eql(u8, key, "vmnet_entitlements")) {
            cfg.vmnet_entitlements = std.mem.eql(u8, value, "true");
            continue;
        }
        if (std.mem.eql(u8, key, "provisioning_profile")) {
            if (cfg.provisioning_profile) |v| allocator.free(v);
            cfg.provisioning_profile = try allocator.dupe(u8, value);
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
        exe.linkFramework("vmnet");
        exe.addCSourceFile(.{
            .file = b.path("src/net/vmnet_bridge.c"),
            .flags = &.{"-fno-sanitize=undefined"},
        });
        exe.linkLibC();
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
        unit_tests.linkFramework("vmnet");
        unit_tests.addCSourceFile(.{
            .file = b.path("src/net/vmnet_bridge.c"),
            .flags = &.{"-fno-sanitize=undefined"},
        });
        unit_tests.linkLibC();
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
        const entitlements_test_name: []const u8 = "entitlements/hvf-entitlements-test.xml";
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
        sign_tests.addFileArg(entitlements_test); // Use test entitlements without vmnet
        sign_tests.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime", "--timestamp" });
        sign_tests.addFileArg(unit_tests.getEmittedBin());
        sign_tests.step.dependOn(&unit_tests.step);
        run_unit_tests.step.dependOn(&sign_tests.step);

        // Create app bundle with vmnet entitlements and provisioning profile
        if (cfg.vmnet_entitlements and cfg.provisioning_profile != null) {
            const app_bundle_step = b.step("bundle", "create m80.app bundle with vmnet support");
            const bundle_path = b.getInstallPath(.bin, "m80.app");

            // Create bundle directory structure (depends on signed exe, not install)
            const mkdir_contents = b.addSystemCommand(&[_][]const u8{
                "mkdir", "-p",
            });
            mkdir_contents.addArg(b.fmt("{s}/Contents/MacOS", .{bundle_path}));
            mkdir_contents.step.dependOn(&sign_exe.step);

            // Copy binary to bundle (use the build output, not installed)
            const copy_binary = b.addSystemCommand(&[_][]const u8{ "cp" });
            copy_binary.addFileArg(exe.getEmittedBin());
            copy_binary.addArg(b.fmt("{s}/Contents/MacOS/{s}", .{ bundle_path, exe.name }));
            copy_binary.step.dependOn(&mkdir_contents.step);

            // Write Info.plist using shell to avoid install step dependency
            const write_plist = b.addSystemCommand(&[_][]const u8{ "sh", "-c" });
            write_plist.addArg(b.fmt(
                \\cat > {s}/Contents/Info.plist << 'PLIST_EOF'
                \\<?xml version="1.0" encoding="UTF-8"?>
                \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                \\<plist version="1.0">
                \\<dict>
                \\    <key>CFBundleExecutable</key>
                \\    <string>m80</string>
                \\    <key>CFBundleIdentifier</key>
                \\    <string>co.themissile.m80</string>
                \\    <key>CFBundleName</key>
                \\    <string>m80</string>
                \\    <key>CFBundleVersion</key>
                \\    <string>1.0</string>
                \\    <key>CFBundleShortVersionString</key>
                \\    <string>1.0</string>
                \\    <key>LSMinimumSystemVersion</key>
                \\    <string>11.0</string>
                \\</dict>
                \\</plist>
                \\PLIST_EOF
            , .{bundle_path}));
            write_plist.step.dependOn(&copy_binary.step);

            // Copy provisioning profile (expand ~ in path)
            const profile_path = cfg.provisioning_profile.?;
            const copy_profile = b.addSystemCommand(&[_][]const u8{ "sh", "-c" });
            copy_profile.addArg(b.fmt("cp {s} {s}/Contents/embedded.provisionprofile", .{ profile_path, bundle_path }));
            copy_profile.step.dependOn(&write_plist.step);

            // Sign the bundle
            const sign_bundle = b.addSystemCommand(&[_][]const u8{
                "codesign",
                "--sign",
                codesign_identity,
            });
            if (codesign_keychain) |kc| {
                sign_bundle.addArgs(&[_][]const u8{ "--keychain", kc });
            }
            sign_bundle.addArg("--entitlements");
            sign_bundle.addFileArg(entitlements);
            sign_bundle.addArgs(&[_][]const u8{ "--deep", "--force", "--options", "runtime", "--timestamp" });
            sign_bundle.addArg(bundle_path);
            sign_bundle.step.dependOn(&copy_profile.step);

            app_bundle_step.dependOn(&sign_bundle.step);

            // Make bundle part of default install
            b.getInstallStep().dependOn(&sign_bundle.step);
            run_cmd.step.dependOn(&sign_bundle.step);
        } else {
            run_cmd.step.dependOn(&sign_installed.step);
        }

        if (codesign_identity_buf) |buf| b.allocator.free(buf);
        if (codesign_keychain_buf) |buf| b.allocator.free(buf);
    }
}

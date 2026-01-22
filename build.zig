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
        const entitlements = b.path("entitlements/hvf-entitlements.xml");

        const sign_exe = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            "-",
            "--entitlements",
        });
        sign_exe.addFileArg(entitlements);
        sign_exe.addArgs(&[_][]const u8{ "--deep", "--force" });
        sign_exe.addFileArg(exe.getEmittedBin());
        sign_exe.step.dependOn(&exe.step);

        const sign_installed = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            "-",
            "--entitlements",
        });
        sign_installed.addFileArg(entitlements);
        sign_installed.addArgs(&[_][]const u8{ "--deep", "--force" });
        sign_installed.addArg(b.getInstallPath(.bin, exe.name));
        sign_installed.step.dependOn(b.getInstallStep());

        const sign_tests = b.addSystemCommand(&[_][]const u8{
            "codesign",
            "--sign",
            "-",
            "--entitlements",
        });
        sign_tests.addFileArg(entitlements);
        sign_tests.addArgs(&[_][]const u8{ "--deep", "--force" });
        sign_tests.addFileArg(unit_tests.getEmittedBin());
        sign_tests.step.dependOn(&unit_tests.step);
        run_unit_tests.step.dependOn(&sign_tests.step);

        run_cmd.step.dependOn(&sign_installed.step);
    }
}

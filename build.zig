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
  const run_unit_tests = b.addRunArtifact(unit_tests);
  test_step.dependOn(&run_unit_tests.step);
}

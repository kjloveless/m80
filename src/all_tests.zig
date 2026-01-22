//! Test Aggregator
//!
//! This file imports all modules so that Zig's test discovery finds all tests.
//! The custom test runner (test_runner.zig) executes tests from this root.
//!
//! ## Why This Pattern?
//! Zig only runs tests from files that are transitively imported from the
//! test root. By importing every module here, we ensure all tests run when
//! executing `zig build test`.
//!
//! ## Adding New Modules
//! When adding a new module with tests, add an import line below to include
//! it in the test suite.

test "import: all modules" {
    // Importing modules here ensures tests are discovered by the runner.
    _ = @import("core.zig");
    _ = @import("core/config.zig");
    _ = @import("core/errors.zig");
    _ = @import("core/paths.zig");
    _ = @import("core/state.zig");
    _ = @import("fs/mounts.zig");
    _ = @import("fs/virtio_fs.zig");
    _ = @import("jailer/acl.zig");
    _ = @import("jailer/jailer.zig");
    _ = @import("jailer/sandbox_darwin.zig");
    _ = @import("jailer/sandbox_windows.zig");
    _ = @import("jailer/seccomp.zig");
    _ = @import("main.zig");
    _ = @import("net/dns.zig");
    _ = @import("net/policy.zig");
    _ = @import("util/log.zig");
    _ = @import("util/path.zig");
    _ = @import("vm/hvf.zig");
    _ = @import("vm/dtb.zig");
    _ = @import("vm/boot.zig");
    _ = @import("vm/posix.zig");
    _ = @import("vm/serial.zig");
    _ = @import("vm/vm.zig");
    _ = @import("vm/windows.zig");
}

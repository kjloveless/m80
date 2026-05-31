const std = @import("std");

pub const help_text =
    \\m80 - cross-platform microvm runtime
    \\
    \\usage:
    \\  m80 daemon run              run the system daemon in the foreground
    \\  m80 daemon start            start the system daemon
    \\  m80 daemon stop             stop the system daemon
    \\  m80 daemon status           show daemon status
    \\  m80 init <name>              create a new VM
    \\  m80 start <name>             start a VM in the background
    \\  m80 console <name>           attach to a running VM console
    \\  m80 stop <name>              stop a running VM
    \\  m80 delete <name>            remove a VM and its files
    \\  m80 ps                       list all VMs and their status
    \\  m80 inspect <name>           show VM details
    \\  m80 snapshot <name> <path>   save filesystem-image snapshot to directory
    \\  m80 restore <name> <path>    restore filesystem images from snapshot directory
    \\  m80 clone <name> <new-name>  clone a VM (copy config)
    \\  m80 help                     show this help message
    \\
    \\networking:
    \\  use network_mode=locked_down|allowlist|open and network_services=dns,metadata
    \\  HVF guests with allowlist/open get TCP/UDP egress at socks5h://127.0.0.1:1080
    \\  network_mode=open requires M80_ALLOW_OPEN_NETWORK=1
    \\
;

pub fn writeHelp(writer: anytype) !void {
    try writer.writeAll(help_text);
}

pub fn printHelp() void {
    std.debug.print("{s}", .{help_text});
}

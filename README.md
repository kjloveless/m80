# m80

Zig microVM runtime with a small CLI, platform-specific hypervisor backends, explicit VM config, and deny-by-default policy controls.

See [docs/PROJECT.md](docs/PROJECT.md) for the canonical project status, roadmap, QA snapshot, integration test commands, and macOS signing notes.

## Status

- CLI control plane is implemented; there is no daemon or REST API yet.
- macOS HVF is the most complete backend path.
- Windows WHP and Linux/POSIX KVM paths exist but still need real-host lifecycle validation.
- Jailer, mount, networking-policy, virtio device, and snapshot building blocks are implemented with platform-gated integration work still pending.
- Latest local validation from 2026-04-29: `zig build test` loaded 340 tests; 322 passed, 18 skipped, 0 failed.

## Build

```bash
zig build
zig build run -- help
zig build test
```

## CLI

```text
m80 init <name>              create a new VM
m80 start <name>             start a VM in the background
m80 run <name>               run a VM in the foreground; normally used internally
m80 console <name>           attach to a running VM console
m80 stop <name>              stop a running VM
m80 delete <name>            remove a VM and its files
m80 ps                       list all VMs and their status
m80 inspect <name>           show VM details
m80 snapshot <name> <path>   copy configured VM disk images into a snapshot directory
m80 restore <name> <path>    restore configured VM disk images from a snapshot directory
m80 clone <name> <new-name>  clone a VM config
m80 help                     show help
```

VM names must be 1-64 characters and only use letters, numbers, `-`, and `_`.

## VM Config

VMs use `m80.conf` in each VM directory. Paths can be absolute, `~`-relative, or relative to the VM directory.

```text
name=deb
memory_mb=2048
cpu_cores=2
kernel_path=images/linux
initrd_path=images/m80-initramfs.cpio.gz
disk_path=images/rootfs.ext4
seed_path=images/nocloud-seed.iso
kernel_cmdline=console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw
network_mode=locked_down
```

Useful optional keys:

```text
disk_readonly=false
data_disk_path=images/data.ext4
data_disk_readonly=false
mount_roots=/Users/you/projects
mounts=code:/Users/you/projects/m80:/mnt/code:rw:virtiofs
virtio_fs_queues=1
virtio_fs_cache=auto
network_mode=allowlist
allowed_domains=deb.debian.org,security.debian.org,repo.example.com:443
allowed_ips=10.0.0.0/8
```

`kernel_path` is required to start. Either `initrd_path` or `disk_path` is required. `network_mode=open` requires `M80_ALLOW_OPEN_NETWORK=1`.

## Logging

Logs default to `info` and print to stderr with millisecond timestamps.

```bash
M80_LOG_LEVEL=debug zig build run -- help
```

Supported levels: `debug`, `info`, `warn`, `error`.

## Data Directories

- Windows: `%LOCALAPPDATA%\m80`
- POSIX: `$XDG_DATA_HOME/m80` or `~/.local/share/m80`

Each VM lives under `{data}/vms/{name}/`.

## Integration Helpers

```bash
make initramfs
make hvf-smoke KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz EXPECT="m80 initramfs: boot ok"
make hvf-reliability KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz CYCLES=20
```

Most integration tests are gated by environment variables and local boot images. Full commands are in [docs/PROJECT.md](docs/PROJECT.md).

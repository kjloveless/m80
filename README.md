# m80

Zig microVM runtime with a small CLI, platform-specific hypervisor backends, and an HVF-first vsock control plane for guest-local services.

See [docs/PROJECT.md](docs/PROJECT.md) for the canonical project status, roadmap, QA snapshot, integration test commands, and macOS signing notes.

## Status

- `m80 daemon` now provides the local control-plane daemon used by `m80 start` and `m80 run`.
- macOS HVF is the active backend for the `network_*` guest networking model and virtio-vsock.
- Windows WHP and Linux/POSIX KVM paths still need real-host lifecycle validation and fail fast when `network_*` guest networking is enabled.
- Guest-local DNS, metadata, external DNS forwarding, TCP CONNECT, SOCKS5 UDP ASSOCIATE, and daemon-side ICMP echo run over an authenticated per-VM vsock session. TCP and UDP egress are exposed through a guest-local SOCKS5 endpoint on `127.0.0.1:1080`; transparent TUN remains pending.
- Latest local validation from 2026-05-31: `zig build test` with Zig 0.16.0 loaded 333 tests; 312 passed, 21 skipped, 0 failed.

## Build

m80 currently targets Zig 0.16.0. The Makefile uses `~/.local/opt/zig-v0.16.0/zig` when present.

```bash
zig build
zig build run -- help
zig build test
```

## CLI

```text
m80 init <name>              create a new VM
m80 daemon run               run the local control-plane daemon in the foreground
m80 daemon start             start the local control-plane daemon
m80 daemon stop              stop the local control-plane daemon
m80 daemon status            show daemon status
m80 start <name>             start a VM in the background
m80 run <name>               run a VM in the foreground; normally used internally
m80 console <name>           attach to a running VM console
m80 stop <name>              stop a running VM
m80 delete <name>            remove a VM and its files
m80 ps                       list all VMs and their status
m80 inspect <name>           show VM details
m80 snapshot <name> <path>   copy configured VM disk images into a filesystem-image snapshot directory
m80 restore <name> <path>    restore configured VM disk images from a filesystem-image snapshot directory
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
kernel_cmdline=console=ttyAMA0 root=/dev/vda rootwait rw
network_mode=locked_down
network_services=dns,metadata
network_metadata_file=images/metadata.json
network_allowed_domains=example.com,*.example.org:443
network_allowed_ips=192.0.2.10,198.51.100.0/24,2001:db8::10,2001:db8:abcd::/48
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
```

`kernel_path` is required to start. Either `initrd_path` or `disk_path` is required. `network_*` guest networking is currently implemented on the macOS HVF path only. `network_mode=open` requires `M80_ALLOW_OPEN_NETWORK=1`; `services=`, `metadata_file=`, `allowed_domains=`, and `allowed_ips=` are rejected with migration guidance. For `allowlist` and gated `open` modes, guest TCP and UDP egress are available through `socks5h://127.0.0.1:1080` when using the m80 initramfs, and ICMP echo uses the m80 TUN/vsock path with IPv4 and IPv6 allowlist enforcement.

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
make hvf-smoke
make boot-hvf-login
make hvf-reliability CYCLES=20
make hvf-vsock-smoke
```

Most integration tests are gated by environment variables and local boot images. Full commands are in [docs/PROJECT.md](docs/PROJECT.md).

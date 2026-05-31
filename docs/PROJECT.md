# m80 Project Guide

Last reviewed: 2026-05-31

This is the canonical project document for m80. Keep active status, roadmap, QA notes, architecture notes, and operational runbooks here. Avoid adding new phase plans, TODO files, or dated session logs unless they replace a section in this file.

## Product Direction

m80 is a Zig microVM runtime with a small CLI and platform-specific hypervisor backends:

- macOS: Hypervisor Framework (HVF), currently the most complete path.
- Windows: Windows Hypervisor Platform (WHP), implemented with dynamic loading and backend tests, but still needs real-host validation.
- Linux and other POSIX-like hosts: KVM-oriented backend path exists, but real KVM lifecycle validation remains a priority.

The project is still pre-production. The useful target is a small, scriptable runtime for Linux microVMs with explicit storage, filesystem sharing, guest-local control-plane services, and jailer hardening. It is not trying to become a general-purpose desktop VM manager.

## Current State

### CLI

The CLI remains the primary UX, but it now auto-manages a local daemon for the control plane. There is still no REST API or Firecracker-compatible socket API.

Supported commands:

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

`m80 start` spawns a detached `m80 run <name>` process, ensures the daemon is running, sets up a console socket, and writes runtime control files in the VM directory. `m80 stop` first asks the daemon to request guest shutdown over the authenticated guest session; if the VM does not exit, it falls back to the host stop request and then POSIX signals.

### VM Config

Each VM has an `m80.conf` file under its VM data directory. Paths may be absolute, `~`-relative, or relative to the VM directory.

Common keys:

```text
name=<vm-name>
ephemeral=false
memory_mb=2048
cpu_cores=2
kernel_path=images/linux
initrd_path=images/m80-initramfs.cpio.gz
disk_path=images/rootfs.ext4
seed_path=images/nocloud-seed.iso
disk_readonly=false
data_disk_path=images/data.ext4
data_disk_readonly=false
kernel_cmdline=console=ttyAMA0 root=/dev/vda rootwait rw
mount_roots=/Users/you/projects
mounts=code:/Users/you/projects/m80:/mnt/code:rw:virtiofs
virtio_fs_queues=1
virtio_fs_cache=auto
network_mode=locked_down
network_services=dns,metadata
network_metadata_file=images/metadata.json
network_allowed_domains=example.com,*.example.org:443
network_allowed_ips=192.0.2.10,198.51.100.0/24,2001:db8::10,2001:db8:abcd::/48
```

Important behavior:

- VM names are 1-64 characters and may contain only letters, numbers, `-`, and `_`.
- `kernel_path` is required to start a VM.
- Either `initrd_path` or `disk_path` is required.
- `seed_path` requires `disk_path`.
- `network_mode` accepts `locked_down`, `allowlist`, and `open`; `open` requires `M80_ALLOW_OPEN_NETWORK=1`.
- `network_services` accepts `dns` and `metadata`. These guest-local services can run with `network_mode=locked_down`.
- `network_metadata_file` is the only host file path served back through the metadata service at `/v1/user`.
- `network_allowed_domains` and IPv4/IPv6 `network_allowed_ips` apply when `network_mode=allowlist`.
- For `allowlist` and gated `open` modes on HVF, TCP/UDP use the guest SOCKS endpoint and ICMP echo uses the m80 TUN/vsock path.
- Legacy keys `services`, `metadata_file`, `allowed_domains`, and `allowed_ips` are rejected with migration guidance.
- `network_*` guest networking is currently implemented on macOS HVF only; non-HVF backends fail fast when it is enabled.
- `mounts` currently supports one virtio-fs mount in the start path.
- `ephemeral` is parsed and written, but disposable overlay lifecycle semantics are not implemented yet.

### Devices And Storage

Implemented or partially implemented device paths:

- Kernel/initrd loading with relative path resolution and file validation.
- Virtio-blk for root, seed, and data disks.
- Virtio-console and serial console plumbing.
- Virtio-rng.
- Virtio-fs with FUSE request handling and read-only/read-write checks.
- Virtio-vsock control-plane transport on HVF, including guest CID assignment and per-VM guest session sockets.
- ARM PSCI is exposed on HVF through DTB `method=smc`; guest `SYSTEM_OFF`/`SYSTEM_RESET` stops the vCPU so `m80 run` can exit cleanly.

Snapshot commands operate on configured filesystem images. They copy disk slots (`disk_path`, `seed_path`, `data_disk_path`) into a directory with a `manifest.txt`, then restore those images later. Full memory/vCPU snapshot code exists in `src/vm/snapshot.zig` and HVF paths, but it is not wired into the regular CLI snapshot contract.

The m80 initramfs runs `e2fsck -p` before mounting ext roots. If automatic repair fails, it refuses to mount the dirty root read-write and drops to the recovery shell. Use `fsck-root` from that shell for explicit `e2fsck -fy` repair, or boot once with `m80.fsck_repair=1` when unattended repair is intentional.

### Control-Plane Services

The runtime uses a guest-local control plane over virtio-vsock. The host daemon owns guest CID allocation and exposes separate owner-only sockets under `{data_dir}/daemon/`: `control.sock` for CLI/admin control, `register.sock` for VM lifecycle registration, and `guests/<cid>.sock` for the CID-bound guest session.

- `network_services=dns` enables guest-local DNS for `*.m80.internal` and blocks disallowed external names with synthetic NXDOMAIN.
- `network_services=metadata` enables guest-local metadata discovery through the per-VM guest session socket.
- `network_mode=allowlist` and gated `network_mode=open` enable the m80 initramfs proxy path, including `m80tun0`, direct guest TCP/UDP/ICMP forwarding, and a guest-local SOCKS5 listener at `127.0.0.1:1080`.
- Guest frames do not carry VM identity; daemon ACLs bind authorization to the registered CID/session socket.
- Host-only methods are not reachable from guest sockets.
- Daemon-side DNS, TCP, UDP, and ICMP echo handlers enforce policy before host socket use.
- Guest shutdown requests are exposed to the guest agent through CID-bound heartbeat responses; guests cannot request or spoof VM lifecycle methods.
- `src/net/dns.zig` provides the DNS wire-codec and synthetic internal-name responses used by the daemon path.

### Jailer And Hardening

The jailer prepares VM directories, resource limits, and platform hardening hooks:

- Linux: seccomp path.
- macOS: Sandbox.framework profile path.
- Windows: Job Object path.
- POSIX: privilege drop and resource limit helpers.

Runtime hardening mode is controlled by:

```text
M80_JAILER_ENFORCEMENT=observe|strict|off
```

`observe` is the default and logs hardening failures while continuing. `strict` fails VM startup when platform hardening fails. `off` skips platform hardening hooks.

## Build And Test

m80 currently targets Zig 0.16.0. The Makefile uses `~/.local/opt/zig-v0.16.0/zig` when present, otherwise it falls back to `zig`.

```bash
zig build
zig build run -- help
zig build test
```

Tests are aggregated through `src/all_tests.zig` and run with `src/test_runner.zig`.

Current local QA snapshot from 2026-05-31:

```text
zig build test
339 tests loaded
318 passed
21 skipped
0 failed
0 leaks
```

The skipped tests are expected on hosts that do not provide the relevant OS, hypervisor, entitlement, or integration environment variables.
Platform integration tests are enabled with `M80_TEST_INTEGRATION=<selector>`, where selectors include `hvf-reliability`, `jailer`, `whp`, and `all`.

## Integration Tests

HVF smoke test with a small initramfs:

```bash
make initramfs

make hvf-smoke
```

Equivalent direct command:

```bash
M80_TEST_KERNEL=images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64 \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
M80_TEST_SERIAL_EXPECT="m80 initramfs: boot ok" \
zig build test -- --test-filter "smoke: hvf arm64 boot emits serial output"
```

HVF login test:

```bash
make boot-hvf-login
```

Equivalent direct command:

```bash
M80_TEST_KERNEL=images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64 \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
M80_TEST_DISK=images/debian-fresh.raw \
M80_TEST_CMDLINE="earlycon=pl011,0x09000000 keep_bootcon console=ttyAMA0 root=/dev/vda1 rootwait rootfstype=ext4 rw devtmpfs.mount=1 systemd.mask=boot-efi.mount systemd.mask=systemd-boot-update.service quiet loglevel=3 systemd.show_status=false systemd.log_level=warning systemd.log_color=no fsck.mode=skip fsck.repair=no" \
M80_TEST_LOGIN_INPUT="" \
M80_TEST_LOGIN_EXPECT="login:" \
zig build test -- --test-filter "hvf: arm64 boot accepts console input"
```

HVF reliability loop:

```bash
make hvf-reliability CYCLES=20
```

Nightly-depth reliability loop:

```bash
make hvf-reliability-nightly
```

HVF vsock control-plane smoke:

```bash
make hvf-vsock-smoke
```

Equivalent direct command:

```bash
M80_TEST_KERNEL=images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64 \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
zig build test -- --test-filter "smoke: hvf arm64 services resolve metadata over vsock"
```

Deterministic timeout-path test:

```bash
M80_TEST_KERNEL=images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64 \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
zig build test -- --test-filter "hvf: stop returns VcpuStopTimeout when forced vcpu-exit delay is enabled"
```

## macOS Code Signing

The HVF build now uses the hypervisor entitlement only. The build reads optional signing config from `codesign.conf` or `M80_CODESIGN_CONFIG`:

```text
identity=<codesign identity or SHA>
keychain=<optional keychain>
provisioning_profile=/path/to/profile.provisionprofile
```

`provisioning_profile` may be present for local signing context, but the canonical artifact remains the single `zig-out/bin/m80` executable.

Environment overrides:

```text
M80_CODESIGN_IDENTITY
M80_CODESIGN_KEYCHAIN
M80_CODESIGN_CONFIG
```

Useful checks:

```bash
sysctl kern.hv_support
codesign -d --entitlements - ./zig-out/bin/m80
codesign -d --verbose=4 ./zig-out/bin/m80
/usr/bin/log show --predicate 'eventMessage CONTAINS "m80" AND eventMessage CONTAINS "Unsatisfied"' --last 30s
security find-identity -v -p codesigning
```

## Architecture Map

Primary source layout:

```text
src/main.zig                         CLI entry and top-level dispatch
src/cli/dispatch.zig                 argument parsing
src/cli/help.zig                     help text
src/cli/runtime.zig                  detached runner control files, pid, sockets
src/cli/commands/                    command implementations
src/core/                            config, state, paths, errors
src/vm/vm.zig                        platform dispatcher
src/vm/hvf.zig and src/vm/hvf/       macOS HVF backend
src/vm/windows.zig                   Windows WHP backend
src/vm/posix.zig                     POSIX/KVM backend
src/vm/virtio.zig                    virtio device orchestration
src/vm/snapshot.zig                  VM snapshot format and helpers
src/fs/                              mount policy and virtio-fs
src/net/                             DNS wire-codec and synthetic responses
src/jailer/                          jailer, ACL, seccomp, platform sandbox hooks
src/util/                            logging and path safety helpers
```

Data directories:

```text
Windows: %LOCALAPPDATA%\m80
POSIX:   $XDG_DATA_HOME/m80 or ~/.local/share/m80
```

Each VM lives under `{data}/vms/{name}/` and contains `m80.conf`, runtime status/control files, and logs such as `run.log`.

## Active Roadmap

Use this list instead of resurrecting old phase files.

1. Real-host backend validation
   - Validate WHP lifecycle on Windows with real kernel/initrd payloads.
   - Validate Linux KVM start/stop/restart loops with real payloads.
   - Keep HVF macOS arm64 smoke, login, and reliability tests reproducible.

2. Snapshot contract cleanup
   - Keep `m80 snapshot` and `m80 restore` scoped to filesystem-image snapshots.
   - Keep disk-image snapshot/restore tests separate from memory/vCPU snapshot tests.
   - Document backend support per snapshot type before exposing full VM-state snapshots.

3. Control-plane service validation
   - Boot a guest with `network_services=dns,metadata` and validate daemon registration.
   - Prove guest-local DNS resolution for `metadata.m80.internal`.
   - Prove metadata fetches succeed through the per-VM vsock session and reconnect after restore.
   - Finish transparent TUN routing before claiming full direct-connect outbound networking parity.

4. Jailer strict-mode validation
   - Run `M80_JAILER_ENFORCEMENT=strict` on each supported platform.
   - Verify seccomp, Sandbox.framework, and Windows Job Object paths in platform-gated integration tests.

5. Maintainability refactors
   - Continue splitting large backend/device files by ownership boundary.
   - Keep `src/main.zig` limited to parse, dispatch, and top-level error mapping.
   - Split config parse, validation, and serialization when the next config feature lands.

6. CI guardrails
   - Add CI for `zig fmt --check`, `zig build`, and `zig build test`.
   - Keep integration tests gated by explicit environment variables.

7. Deferred product features
   - REST API control plane.
   - Inbound guest port publishing, multicast/broadcast discovery, and raw socket parity.
   - Rate limiting.
   - Balloon device.
   - Firecracker-compatible workflows where they are useful, without requiring exact implementation parity.

## Documentation Policy

Only these markdown files should be needed:

- `README.md`: quickstart and user-facing entry point.
- `AGENTS.md`: coding-agent and contributor guidance.
- `CLAUDE.md`: short compatibility pointer for Claude Code users.
- `docs/PROJECT.md`: this canonical project guide.

When facts change, update this file and the README pointer if needed. Do not add a new dated plan file for temporary work.

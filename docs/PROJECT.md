# m80 Project Guide

Last reviewed: 2026-04-29

This is the canonical project document for m80. Keep active status, roadmap, QA notes, architecture notes, and operational runbooks here. Avoid adding new phase plans, TODO files, or dated session logs unless they replace a section in this file.

## Product Direction

m80 is a Zig microVM runtime with a small CLI and platform-specific hypervisor backends:

- macOS: Hypervisor Framework (HVF), currently the most complete path.
- Windows: Windows Hypervisor Platform (WHP), implemented with dynamic loading and backend tests, but still needs real-host validation.
- Linux and other POSIX-like hosts: KVM-oriented backend path exists, but real KVM lifecycle validation remains a priority.

The project is still pre-production. The useful target is a small, scriptable runtime for Linux microVMs with explicit storage, filesystem sharing, network policy, and jailer hardening. It is not trying to become a general-purpose desktop VM manager.

## Current State

### CLI

The CLI is the only supported control plane right now. There is no daemon, REST API, or Firecracker-compatible socket API yet.

Supported commands:

```text
m80 init <name>              create a new VM
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

`m80 start` spawns a detached `m80 run <name>` process, sets up a console socket, and writes runtime control files in the VM directory. `m80 stop` first writes a graceful stop request, then falls back to signals on POSIX hosts.

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
allowed_domains=example.com,*.example.org,repo.example.com:443
allowed_ips=10.0.0.0/8,192.168.1.20
```

Important behavior:

- VM names are 1-64 characters and may contain only letters, numbers, `-`, and `_`.
- `kernel_path` is required to start a VM.
- Either `initrd_path` or `disk_path` is required.
- `seed_path` requires `disk_path`.
- `network_mode=open` requires `M80_ALLOW_OPEN_NETWORK=1` or `true`.
- `mounts` currently supports one virtio-fs mount in the start path.
- `ephemeral` is parsed and written, but disposable overlay lifecycle semantics are not implemented yet.

### Devices And Storage

Implemented or partially implemented device paths:

- Kernel/initrd loading with relative path resolution and file validation.
- Virtio-blk for root, seed, and data disks.
- Virtio-console and serial console plumbing.
- Virtio-rng.
- Virtio-fs with FUSE request handling and read-only/read-write checks.
- Virtio-net policy code and vmnet bridge scaffolding on macOS.

Snapshot commands operate on configured filesystem images. They copy disk slots (`disk_path`, `seed_path`, `data_disk_path`) into a directory with a `manifest.txt`, then restore those images later. Full memory/vCPU snapshot code exists in `src/vm/snapshot.zig` and HVF paths, but it is not wired into the regular CLI snapshot contract.

### Networking

Networking is deny-by-default:

- `locked_down`: no guest network access.
- `allowlist`: DNS/IP rules are enforced through the policy layer.
- `open`: full access, but only with explicit environment opt-in.

`allowed_domains` accepts exact domains, wildcard subdomains such as `*.example.com`, and optional single-port rules such as `example.com:443`. `allowed_ips` accepts IPv4 and CIDR entries.

On macOS, vmnet requires `com.apple.developer.networking.vmnet`. If vmnet cannot initialize because of signing or entitlement state, m80 logs the issue and leaves networking disabled for that VM.

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

```bash
zig build
zig build run -- help
zig build test
```

Tests are aggregated through `src/all_tests.zig` and run with `src/test_runner.zig`.

Current local QA snapshot from 2026-04-29:

```text
zig build test
348 tests loaded
328 passed
20 skipped
0 failed
0 leaks
```

The skipped tests are expected on hosts that do not provide the relevant OS, hypervisor, entitlement, or integration environment variables.

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
M80_TEST_KERNEL=images/fc-aarch64-vmlinux.bin \
M80_TEST_DISK=images/fc-aarch64-rootfs.ext4 \
M80_TEST_LOGIN_INPUT=$'root\nroot\n' \
M80_TEST_LOGIN_EXPECT="root@" \
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

Platform-gated network policy path:

```bash
make hvf-vmnet-policy
```

Deterministic timeout-path test:

```bash
M80_TEST_HVF_FORCE_STOP_TIMEOUT=1 \
M80_TEST_KERNEL=images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64 \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
zig build test -- --test-filter "hvf: stop returns VcpuStopTimeout when forced vcpu-exit delay is enabled"
```

## macOS Code Signing

Normal HVF-only builds use a hypervisor-only entitlement. When `vmnet_entitlements=true`, the installed single binary uses the vmnet entitlement set.

vmnet requires a restricted Apple entitlement. The build reads optional signing config from `codesign.conf` or `M80_CODESIGN_CONFIG`:

```text
identity=<codesign identity or SHA>
keychain=<optional keychain>
vmnet_entitlements=true
provisioning_profile=/path/to/profile.provisionprofile
```

`provisioning_profile` may be present for local signing context, but the canonical artifact remains the single `zig-out/bin/m80` executable.

Environment overrides:

```text
M80_CODESIGN_IDENTITY
M80_CODESIGN_KEYCHAIN
M80_CODESIGN_CONFIG
M80_TEST_VMNET_ENTITLEMENTS
```

When vmnet support is enabled in `codesign.conf`, the normal `zig-out/bin/m80` executable is signed directly with hypervisor and vmnet entitlements.
`M80_TEST_VMNET_ENTITLEMENTS=1` signs the Zig test binary with vmnet entitlements so the vmnet policy integration test can fail or pass instead of skipping on entitled hosts.

Useful checks:

```bash
sysctl kern.hv_support
codesign -d --entitlements - ./zig-out/bin/m80
codesign -d --verbose=4 ./zig-out/bin/m80
/usr/bin/log show --predicate 'eventMessage CONTAINS "m80" AND eventMessage CONTAINS "Unsatisfied"' --last 30s
security find-identity -v -p codesigning
```

The vmnet entitlement key is:

```text
com.apple.developer.networking.vmnet
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
src/net/                             DNS, vmnet bridge, network policy
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

3. Networking hardening
   - Finish vmnet-backed virtio-net validation on entitled macOS hosts.
   - Keep locked-down mode as the default.
   - Add real guest tests proving allowlist failures are visible and deterministic.

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
   - REST or socket API control plane.
   - vsock and metadata service.
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

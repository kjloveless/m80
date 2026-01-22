# m80

Windows-native microVM runtime (Zig) with a minimal CLI scaffold.

## Status

Phase 0: repository layout, core stubs, and CLI scaffolding.
Phase 1: WHP backend brings up vCPU loop + guest memory loading (Windows), with shared IO/serial scaffolding across backends.
Phase 2–6: jailer, mounts, and networking are present as scaffolds/stubs and still evolving (see `PHASES.md` for detail).

## QA Snapshot (2026-01-19)

- `zig build test`: **200 passed, 8 skipped, 0 failed** (re-verified)
- Skips are OS-gated/integration-gated (HVF/POSIX/WHP integration paths).

## In Progress / Next

- **Security hardening:** Windows ACL hardening implementation.
- **VM backend validation:** cross-backend start/stop parity checks.

## Supported Platforms

- Windows (primary target)
- POSIX hosts (macOS/Linux) for scaffolding and CLI development

## VM Name Rules

Names must be 1-64 characters and only use letters, numbers, `-`, and `_`.

## CLI

The CLI is intentionally minimal while the daemon/worker split is still a plan-level concept.

Phase 0 verification is covered by smoke tests that validate the build script configures successfully and that CLI help output is present.

```
# Create a VM record
m80 init <name>

# Start/stop (placeholder VM)
m80 start <name>
m80 stop <name>

# Inspect state
m80 ps
m80 inspect <name>

# Delete
m80 delete <name>
```

## Logging

Logs default to `info` level and are printed to stderr with a millisecond timestamp prefix.

Set `M80_LOG_LEVEL` to control verbosity:

- `debug`
- `info` (default)
- `warn`
- `error`

## Data Directories

- Windows: `%LOCALAPPDATA%\m80`
- POSIX: `$XDG_DATA_HOME/m80` or `~/.local/share/m80`

## Build

```
zig build
zig build run -- help
zig build test
```

## VM Config (m80.conf)

Common keys:
- `kernel_path`: Linux kernel image path
- `initrd_path`: initrd/initramfs path
- `disk_path`: rootfs block image path (virtio-blk)
- `seed_path`: cloud-init NoCloud seed image (attached as secondary read-only disk)
- `disk_readonly`: attach `disk_path` read-only (default: false)
- `data_disk_path`: optional extra data disk image (virtio-blk)
- `data_disk_readonly`: attach `data_disk_path` read-only (default: false)
- `kernel_cmdline`: optional kernel command line override
- `mount_roots`: comma-separated allowed host roots for sharing
- `mounts`: comma-separated mount configs (`tag:host:guest:ro|rw:virtiofs`)

Example (arm64 + initramfs):

```
kernel_path=images/fc-ubuntu-5.10-with-rng-vmlinux.bin
initrd_path=images/initrd.gz
kernel_cmdline=console=ttyAMA0,115200
```

Example (arm64 + rootfs + NoCloud seed):

```
kernel_path=images/fc-ubuntu-5.10-with-rng-vmlinux.bin
disk_path=images/debian-12-nocloud-arm64-rootfs.ext4
seed_path=images/debian-nocloud-seed.iso
kernel_cmdline=earlycon=pl011,0x09000000 console=ttyAMA0 console=hvc0 root=/dev/vda rootwait rw
```

Shortcut (Debian NoCloud dev VM):

```
m80 start deb
```

Interactive console (raw TTY, virtio console enabled):

```
m80 console deb
```

Note: `start` runs the VM in the background. `console` attaches to the running VM.
If the VM isn't running, start it first.

Shared directory example (strict roots required):

```
mount_roots=/Users/you/projects
mounts=code:/Users/you/projects/m80:/mnt/code:rw:virtiofs
```

Guest-side mount (virtiofs tag `code`):

```
mkdir -p /mnt/code
mount -t virtiofs code /mnt/code
```

Firecracker-style data disk (block device attached; guest mounts it):

```
data_disk_path=images/share.ext4
data_disk_readonly=false
```

Guest-side mount (example):

```
mkdir -p /mnt/data
mount /dev/vdc /mnt/data
```

Device order is typically:
- `/dev/vda`: `disk_path` (rootfs)
- `/dev/vdb`: `seed_path` (if present)
- `/dev/vdc`: `data_disk_path` (if present)

On macOS, create the disk image on the host and format it in the guest:

```
dd if=/dev/zero of=images/share.ext4 bs=1m count=512
# inside the guest:
mkfs.ext4 /dev/vdc
mount /dev/vdc /mnt/data
```

## Networking (macOS vmnet + allowlist)

On macOS, HVF can expose virtio-net via vmnet (shared/NAT). Network access is
**blocked by default** and must be explicitly enabled in `m80.conf`.

vmnet requires a restricted entitlement on macOS. By default, builds use the
hypervisor-only entitlements file. If you have the vmnet entitlement available,
opt in at build time:

```
M80_VMNET_ENTITLEMENTS=1 zig build
```

Config keys:
- `network_mode`: `locked_down` (default) | `allowlist` | `open`
- `allowed_domains`: comma-separated domain allowlist (used by DNS enforcement)
- `allowed_ips`: comma-separated IPv4/CIDR allowlist (e.g., `1.2.3.4,10.0.0.0/8`)

Example (allow Debian repos):

```
network_mode=allowlist
allowed_domains=deb.debian.org,security.debian.org,ftp.us.debian.org
```

Open network (explicit opt-in required):

```
network_mode=open
```

```
export M80_ALLOW_OPEN_NETWORK=1
```

## HVF arm64 Boot Smoke Test

The HVF integration test is gated by environment variables so it only runs when
you provide a kernel/initrd and a serial substring to search for.

Required env vars:
- `M80_TEST_KERNEL`: path to an arm64 Linux kernel (usually `Image` or `linux`)
- `M80_TEST_INITRD`: path to the initrd/initramfs (usually `initrd.gz`)
- `M80_TEST_SERIAL_EXPECT`: substring expected on the serial console (e.g., `Linux version`)

Optional:
- `M80_SERIAL_OUT`: file path to capture serial output (the test sets this).

Minimal initramfs (no BusyBox):

```
scripts/build-initramfs.sh
```

Example (minimal kernel+initrd smoke, preferred paths under `images/`):

```
mkdir -p images
curl -L -o images/linux https://deb.debian.org/debian/dists/bullseye/main/installer-arm64/current/images/netboot/debian-installer/arm64/linux
scripts/build-initramfs.sh

M80_TEST_KERNEL=images/linux \
M80_TEST_INITRD=images/m80-initramfs.cpio.gz \
M80_TEST_SERIAL_EXPECT="m80 initramfs: boot ok" \
zig build test -- --test-filter "smoke: hvf arm64 boot emits serial output"
```

Helper script:

```
scripts/run-hvf-smoke.sh images/linux images/m80-initramfs.cpio.gz "m80 initramfs: boot ok"
```

Makefile target:

```
make hvf-smoke KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz EXPECT="m80 initramfs: boot ok"
```

## HVF arm64 Login Test

The login integration test boots the Firecracker kernel + rootfs from `images/`
and feeds the hvc0 console with `M80_SERIAL_IN` data.

Required env vars:
- `M80_TEST_KERNEL`: Firecracker kernel with virtio-rng (`images/fc-ubuntu-5.10-with-rng-vmlinux.bin`)
- `M80_TEST_DISK`: Firecracker rootfs (`images/fc-aarch64-rootfs.ext4`)
- `M80_TEST_LOGIN_INPUT`: bytes to send (e.g., `root\nroot\n`)
- `M80_TEST_LOGIN_EXPECT`: substring expected in output (e.g., `root@`)

Example:

```
M80_TEST_KERNEL=images/fc-ubuntu-5.10-with-rng-vmlinux.bin \
M80_TEST_DISK=images/fc-aarch64-rootfs.ext4 \
M80_TEST_LOGIN_INPUT=$'root\nroot\n' \
M80_TEST_LOGIN_EXPECT="root@" \
zig build test -- --test-filter "hvf: arm64 boot accepts console input"
```

Makefile target:

```
make boot-hvf-login
```

Known-good small raw ARM64 kernels (bring your own kernel):

- Debian bullseye netboot `linux` (~26MB): raw `Image` and works with the current loader.
- Alpine netboot `vmlinuz-virt` (~9MB) from the Alpine release mirrors; some mirrors serve an EFI-stub PE file, so verify it is a raw `Image` before use.

Example downloads and verification:

```
# Debian bullseye (raw Image)
curl -L -o images/linux https://deb.debian.org/debian/dists/bullseye/main/installer-arm64/current/images/netboot/debian-installer/arm64/linux
file images/linux

# Alpine v3.20.8 netboot (check that it is a raw Image, not EFI stub)
curl -L -o images/alpine-vmlinuz-virt https://nl.alpinelinux.org/v3.20/releases/aarch64/netboot-3.20.8/vmlinuz-virt
file images/alpine-vmlinuz-virt
```

If `file` reports a PE/COFF executable (EFI stub), the current loader will not boot it. Use a raw `Image` instead. citeturn3search0turn2view0

## HVF Setup & Troubleshooting (macOS arm64)

HVF requires host support and a properly entitled, signed binary.

1) Verify Hypervisor support is enabled:

```
sysctl kern.hv_support
```

This should return `1` when HVF is available.

2) Sign the binary with the hypervisor entitlement:

Example entitlements file:
```
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
```

Example signing command:
```
codesign --sign - --entitlements entitlements.xml --deep --force /path/to/m80
```

Build-time codesigning (macOS):
```
zig build
zig build test
```
These automatically codesign the emitted binaries using `entitlements/hvf-entitlements.xml`.

If you see `hv_vm_create` failing with `HV_DENIED` (`0xfae94007`), it typically means the entitlement is missing or the binary isn’t properly signed.

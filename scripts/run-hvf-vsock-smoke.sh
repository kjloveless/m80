#!/usr/bin/env bash
set -euo pipefail

kernel_path="${1:-${M80_TEST_KERNEL:-images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64}}"
initrd_path="${2:-${M80_TEST_INITRD:-images/m80-initramfs.cpio.gz}}"
zig_bin="${ZIG:-zig}"

if [[ ! -f "${kernel_path}" || ! -f "${initrd_path}" ]]; then
  echo "missing HVF vsock smoke inputs: kernel=${kernel_path} initrd=${initrd_path}" >&2
  echo "usage: $0 [kernel_path] [initrd_path]" >&2
  exit 2
fi

M80_TEST_KERNEL="${kernel_path}" \
M80_TEST_INITRD="${initrd_path}" \
"${zig_bin}" build test -- --test-filter "smoke: hvf arm64 services resolve metadata over vsock"

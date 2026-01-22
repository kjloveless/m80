#!/usr/bin/env bash
set -euo pipefail

kernel_path="${1:-${M80_TEST_KERNEL:-}}"
initrd_path="${2:-${M80_TEST_INITRD:-}}"
serial_expect="${3:-${M80_TEST_SERIAL_EXPECT:-m80 initramfs: boot ok}}"

if [[ -z "${kernel_path}" || -z "${initrd_path}" ]]; then
  echo "usage: $0 <kernel_path> <initrd_path> [serial_expect]" >&2
  echo "  or set M80_TEST_KERNEL and M80_TEST_INITRD env vars" >&2
  exit 2
fi

M80_TEST_KERNEL="${kernel_path}" \
M80_TEST_INITRD="${initrd_path}" \
M80_TEST_SERIAL_EXPECT="${serial_expect}" \
zig build test -- --test-filter "smoke: hvf arm64 boot emits serial output"

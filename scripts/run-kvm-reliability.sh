#!/usr/bin/env bash
set -euo pipefail

kernel_path="${1:-${M80_TEST_KERNEL:-}}"
initrd_path="${2:-${M80_TEST_INITRD:-}}"
cycles="${3:-${M80_TEST_KVM_RELIABILITY_CYCLES:-20}}"

if [[ -z "${kernel_path}" || -z "${initrd_path}" ]]; then
  echo "missing KVM reliability inputs: kernel='${kernel_path}' initrd='${initrd_path}'" >&2
  echo "usage: $0 <kernel_path> <initrd_path> [cycles]" >&2
  exit 2
fi

if [[ ! -f "${kernel_path}" || ! -f "${initrd_path}" ]]; then
  echo "missing KVM reliability files: kernel=${kernel_path} initrd=${initrd_path}" >&2
  exit 2
fi

M80_TEST_INTEGRATION=kvm \
M80_TEST_KERNEL="${kernel_path}" \
M80_TEST_INITRD="${initrd_path}" \
M80_TEST_KVM_RELIABILITY_CYCLES="${cycles}" \
zig build test -- --test-filter "integration: kvm repeated start-stop reliability"

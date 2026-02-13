#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kernel_path="${1:-${M80_TEST_KERNEL:-}}"
initrd_path="${2:-${M80_TEST_INITRD:-}}"
cycles="${3:-${M80_TEST_HVF_RELIABILITY_CYCLES:-20}}"
serial_expect="${4:-${M80_TEST_SERIAL_EXPECT:-m80 initramfs: boot ok}}"
artifacts_dir="${ARTIFACTS_DIR:-${repo_root}/artifacts}"
log_path="${artifacts_dir}/hvf-reliability.log"

if [[ -z "${kernel_path}" || -z "${initrd_path}" ]]; then
  echo "usage: $0 <kernel_path> <initrd_path> [cycles] [serial_expect]" >&2
  echo "  or set M80_TEST_KERNEL and M80_TEST_INITRD env vars" >&2
  exit 2
fi

mkdir -p "${artifacts_dir}"
: > "${log_path}"

echo "hvf reliability: kernel=${kernel_path} initrd=${initrd_path} cycles=${cycles}" | tee -a "${log_path}"

set +e
M80_TEST_HVF_RELIABILITY=1 \
M80_TEST_HVF_RELIABILITY_CYCLES="${cycles}" \
M80_TEST_KERNEL="${kernel_path}" \
M80_TEST_INITRD="${initrd_path}" \
M80_TEST_SERIAL_EXPECT="${serial_expect}" \
zig build test -- --test-filter "smoke: hvf arm64 repeated start-stop reliability" \
  2>&1 | tee -a "${log_path}"
test_rc=${PIPESTATUS[0]}
set -e

timeout_count="$(grep -c "VcpuStopTimeout" "${log_path}" || true)"
trap_count="$(grep -c "unknown sysreg trap" "${log_path}" || true)"

{
  echo "summary:"
  echo "  VcpuStopTimeout count: ${timeout_count}"
  echo "  unknown sysreg trap count: ${trap_count}"
  echo "  log: ${log_path}"
} | tee -a "${log_path}"

exit "${test_rc}"

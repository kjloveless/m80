#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
init_src="${repo_root}/src/init/min_init.c"
out_path="${1:-${repo_root}/images/m80-initramfs.cpio.gz}"

work_dir="${TMPDIR:-/tmp}/m80-initramfs"
rm -rf "${work_dir}"
mkdir -p "${work_dir}"

zig cc -target aarch64-linux-musl -Os -static -s \
  "${init_src}" -o "${work_dir}/init"

mkdir -p "${work_dir}/proc" "${work_dir}/sys" "${work_dir}/dev"

(
  cd "${work_dir}"
  find . -print0 | cpio --null -o -H newc | gzip -9 > "${out_path}"
)

echo "wrote ${out_path}"

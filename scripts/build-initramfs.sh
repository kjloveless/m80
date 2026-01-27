#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
init_src="${repo_root}/src/init/min_init.c"
out_path="${1:-${repo_root}/images/m80-initramfs.cpio.gz}"
if [[ "${out_path}" != /* ]]; then
  out_path="${repo_root}/${out_path}"
fi
kernel_ver="6.1.0-42-cloud-arm64"
kernel_deb="${repo_root}/images/debian-kernels/linux-image-6.1.0-42-cloud-arm64_6.1.159-1_arm64.deb"
kernel_data="${repo_root}/images/debian-kernels/data.tar.xz"
e2fsck_deb="${M80_E2FSCK_DEB:-${repo_root}/images/debian-tools/e2fsck-static_1.47.0-2+b2_arm64.deb}"

work_dir="${TMPDIR:-/tmp}/m80-initramfs"
rm -rf "${work_dir}"
mkdir -p "${work_dir}"

zig cc -target aarch64-linux-musl -Os -static -s \
  "${init_src}" -o "${work_dir}/init"

mkdir -p "${work_dir}/proc" "${work_dir}/sys" "${work_dir}/dev"

if [[ -f "${kernel_deb}" ]]; then
  if [[ ! -f "${kernel_data}" ]]; then
    (cd "${repo_root}/images/debian-kernels" && ar -x "${kernel_deb}")
  fi
  if [[ -f "${kernel_data}" ]]; then
    mod_base="lib/modules/${kernel_ver}"
    mod_paths=(
      "${mod_base}/kernel/drivers/virtio/virtio.ko"
      "${mod_base}/kernel/drivers/virtio/virtio_ring.ko"
      "${mod_base}/kernel/drivers/virtio/virtio_mmio.ko"
      "${mod_base}/kernel/drivers/block/virtio_blk.ko"
      "${mod_base}/kernel/drivers/char/virtio_console.ko"
      "${mod_base}/kernel/drivers/char/hw_random/virtio-rng.ko"
      "${mod_base}/kernel/net/core/failover.ko"
      "${mod_base}/kernel/drivers/net/net_failover.ko"
      "${mod_base}/kernel/drivers/net/virtio_net.ko"
      "${mod_base}/kernel/fs/fuse/fuse.ko"
      "${mod_base}/kernel/fs/fuse/virtiofs.ko"
    )
    for rel in "${mod_paths[@]}"; do
      mkdir -p "${work_dir}/$(dirname "${rel}")"
      tar -xf "${kernel_data}" -C "${work_dir}" "./${rel}" || true
    done
  fi
fi

if [[ -f "${e2fsck_deb}" ]]; then
  e2fsck_tmp="${work_dir}/.e2fsck"
  rm -rf "${e2fsck_tmp}"
  mkdir -p "${e2fsck_tmp}"
  (cd "${e2fsck_tmp}" && ar -x "${e2fsck_deb}")
  e2fsck_data="$(ls "${e2fsck_tmp}"/data.tar.* 2>/dev/null | head -n 1 || true)"
  if [[ -n "${e2fsck_data}" ]]; then
    mkdir -p "${work_dir}/sbin"
    tar -xf "${e2fsck_data}" -C "${work_dir}" "./sbin/e2fsck.static" || true
    if [[ -f "${work_dir}/sbin/e2fsck.static" ]]; then
      mv "${work_dir}/sbin/e2fsck.static" "${work_dir}/sbin/e2fsck"
      chmod +x "${work_dir}/sbin/e2fsck"
    fi
  fi
fi

(
  cd "${work_dir}"
  find . -print0 | cpio --null -o -H newc | gzip -9 > "${out_path}"
)

echo "wrote ${out_path}"

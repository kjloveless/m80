.PHONY: hvf-smoke hvf-reliability hvf-reliability-nightly hvf-vsock-smoke initramfs

ZIG ?= $(if $(wildcard $(HOME)/.local/opt/zig-v0.16.0/zig),$(HOME)/.local/opt/zig-v0.16.0/zig,zig)
export ZIG

KERNEL ?= images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64
INITRD ?= images/m80-initramfs.cpio.gz
EXPECT ?= m80 initramfs: boot ok
CYCLES ?= 20
LOGIN_KERNEL ?= images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64
LOGIN_INITRD ?= images/m80-initramfs.cpio.gz
LOGIN_DISK ?= images/debian-fresh.raw
LOGIN_CMDLINE ?= earlycon=pl011,0x09000000 keep_bootcon console=ttyAMA0 root=/dev/vda1 rootwait rootfstype=ext4 rw devtmpfs.mount=1 systemd.mask=boot-efi.mount systemd.mask=systemd-boot-update.service quiet loglevel=3 systemd.show_status=false systemd.log_level=warning systemd.log_color=no fsck.mode=skip fsck.repair=no
LOGIN_INPUT ?=
LOGIN_EXPECT ?= login:

initramfs:
	@scripts/build-initramfs.sh

hvf-smoke:
	@scripts/run-hvf-smoke.sh "$(KERNEL)" "$(INITRD)" "$(EXPECT)"

boot-hvf-login: initramfs
	@echo "Running HVF login test (requires local images/ and rootfs creds)"
	@M80_TEST_KERNEL="$(LOGIN_KERNEL)" \
		M80_TEST_INITRD="$(LOGIN_INITRD)" \
		M80_TEST_DISK="$(LOGIN_DISK)" \
		M80_TEST_CMDLINE="$(LOGIN_CMDLINE)" \
		M80_TEST_LOGIN_INPUT="$(LOGIN_INPUT)" \
		M80_TEST_LOGIN_EXPECT="$(LOGIN_EXPECT)" \
		"$(ZIG)" build test -- --test-filter "hvf: arm64 boot accepts console input"

hvf-reliability:
	@scripts/run-hvf-reliability.sh "$(KERNEL)" "$(INITRD)" "$(CYCLES)" "$(EXPECT)"

hvf-reliability-nightly:
	@scripts/run-hvf-reliability.sh "$(KERNEL)" "$(INITRD)" "200" "$(EXPECT)"

hvf-vsock-smoke:
	@scripts/run-hvf-vsock-smoke.sh "$(KERNEL)" "$(INITRD)"

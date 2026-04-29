.PHONY: hvf-smoke hvf-reliability hvf-reliability-nightly hvf-vmnet-policy initramfs

KERNEL ?= images/debian-kernels/boot/vmlinuz-6.1.0-42-cloud-arm64
INITRD ?= images/m80-initramfs.cpio.gz
EXPECT ?= m80 initramfs: boot ok
CYCLES ?= 20

initramfs:
	@scripts/build-initramfs.sh

hvf-smoke:
	@scripts/run-hvf-smoke.sh "$(KERNEL)" "$(INITRD)" "$(EXPECT)"

boot-hvf-login:
	@echo "Running HVF login test (requires local images/ and rootfs creds)"
	@M80_TEST_KERNEL=images/fc-aarch64-vmlinux.bin \
		M80_TEST_DISK=images/fc-aarch64-rootfs.ext4 \
		M80_TEST_LOGIN_INPUT=$$'root\nroot\n' \
		M80_TEST_LOGIN_EXPECT="root@" \
		zig build test -- --test-filter "hvf: arm64 boot accepts console input"

hvf-reliability:
	@scripts/run-hvf-reliability.sh "$(KERNEL)" "$(INITRD)" "$(CYCLES)" "$(EXPECT)"

hvf-reliability-nightly:
	@scripts/run-hvf-reliability.sh "$(KERNEL)" "$(INITRD)" "200" "$(EXPECT)"

hvf-vmnet-policy:
	@M80_TEST_VMNET_ENTITLEMENTS=1 \
		M80_TEST_HVF_NET_POLICY_INTEGRATION=1 \
		zig build test -- --test-filter "hvf: integration allowlist blocks non-whitelisted dns egress via virtio-net tx path"

.PHONY: hvf-smoke initramfs

initramfs:
	@scripts/build-initramfs.sh

hvf-smoke:
	@if [ -z "$(KERNEL)" ] || [ -z "$(INITRD)" ]; then \
		echo "usage: make hvf-smoke KERNEL=images/linux INITRD=images/m80-initramfs.cpio.gz [EXPECT=\"m80 initramfs: boot ok\"]" >&2; \
		exit 2; \
	fi
	@EXPECT_VAL="${EXPECT:-m80 initramfs: boot ok}"; \
	scripts/run-hvf-smoke.sh "$(KERNEL)" "$(INITRD)" "$$EXPECT_VAL"
boot-hvf-login:
	@echo "Running HVF login test (requires local images/ and rootfs creds)"
	@M80_TEST_KERNEL=images/fc-aarch64-vmlinux.bin \
		M80_TEST_DISK=images/fc-aarch64-rootfs.ext4 \
		M80_TEST_LOGIN_INPUT=$$'root\nroot\n' \
		M80_TEST_LOGIN_EXPECT="root@" \
		zig build test -- --test-filter "hvf: arm64 boot accepts console input"

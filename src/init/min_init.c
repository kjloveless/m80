#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

static int broadcast_output = 0;

static void write_line(const char *msg) {
  const char *suffix = "\n";
  if (broadcast_output) {
    const char *paths[] = {
        "/dev/hvc0",
        "/dev/ttyAMA0",
        "/dev/console",
        "/dev/kmsg",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
      int flags = O_WRONLY | O_NOCTTY | O_NONBLOCK;
      if (strcmp(paths[i], "/dev/hvc0") == 0) {
        flags = O_RDWR | O_NOCTTY | O_NONBLOCK;
      }
      int fd = open(paths[i], flags);
      if (fd >= 0) {
        write(fd, msg, strlen(msg));
        write(fd, suffix, 1);
        close(fd);
      }
    }
    return;
  }

  const char *paths[] = {
      "/dev/ttyAMA0",
      "/dev/console",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int fd = open(paths[i], O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (fd >= 0) {
      write(fd, msg, strlen(msg));
      write(fd, suffix, 1);
      close(fd);
      return;
    }
  }
}

static void write_kmsg_line(const char *msg) {
  int fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_NONBLOCK);
  if (fd >= 0) {
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
    close(fd);
  }
}

static void yield_cpu(void) {
  syscall(SYS_sched_yield);
}

static int open_console_path(const char *path) {
  return open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
}

static int open_input_path(const char *path) {
  return open(path, O_RDONLY | O_NOCTTY | O_NONBLOCK);
}

static int load_module_file(const char *path) {
  int fd = open(path, O_RDONLY | O_NOCTTY);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 initramfs: open failed %s", path);
    write_line(msg);
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 initramfs: stat failed %s", path);
    write_line(msg);
    return -1;
  }
  if (st.st_size <= 0) {
    close(fd);
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 initramfs: empty module %s", path);
    write_line(msg);
    return -1;
  }
  void *buf = malloc((size_t)st.st_size);
  if (!buf) {
    close(fd);
    write_line("m80 initramfs: alloc failed");
    return -1;
  }
  ssize_t total = 0;
  while (total < st.st_size) {
    ssize_t n = read(fd, (char *)buf + total, (size_t)(st.st_size - total));
    if (n <= 0) {
      free(buf);
      close(fd);
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: read failed %s", path);
      write_line(msg);
      return -1;
    }
    total += n;
  }
  close(fd);
  int rc = (int)syscall(SYS_init_module, buf, (size_t)st.st_size, "");
  free(buf);
  if (rc != 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 initramfs: init_module failed %s", path);
    write_line(msg);
  }
  return rc;
}

static void load_required_modules(void) {
  const char *modules[] = {
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio_ring.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio_mmio.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/block/virtio_blk.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/char/virtio_console.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/char/hw_random/virtio-rng.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/net/core/failover.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/net/net_failover.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/net/virtio_net.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/fs/fuse/fuse.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/fs/fuse/virtiofs.ko",
  };
  for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++) {
    if (load_module_file(modules[i]) != 0) {
      write_line("m80 initramfs: module load failed");
    }
  }
}

static void load_console_modules(void) {
  const char *modules[] = {
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio_ring.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/virtio/virtio_mmio.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/char/virtio_console.ko",
  };
  for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++) {
    if (load_module_file(modules[i]) != 0) {
      write_line("m80 initramfs: console module load failed");
    }
  }
}

static void start_console_modules(void) {
  pid_t pid = fork();
  if (pid == 0) {
    load_console_modules();
    _exit(0);
  }
  if (pid < 0) {
    write_line("m80 initramfs: console module fork failed");
    load_console_modules();
  }
}

static void ensure_dev_nodes(void) {
  mkdir("/dev", 0755);
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0) {
    mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
    mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
    mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
  }
}

static long read_uptime_ms(void) {
  FILE *fp = fopen("/proc/uptime", "r");
  if (!fp) {
    return -1;
  }
  double seconds = 0.0;
  if (fscanf(fp, "%lf", &seconds) != 1) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  if (seconds < 0.0) {
    return -1;
  }
  return (long)(seconds * 1000.0);
}

static int open_console(void) {
  mknod("/dev/ttyAMA0", S_IFCHR | 0600, makedev(204, 64));
  for (int i = 0; i < 200000; i++) {
    int fd = open_input_path("/dev/ttyAMA0");
    if (fd >= 0) {
      return fd;
    }
    yield_cpu();
  }

  mknod("/dev/hvc0", S_IFCHR | 0600, makedev(229, 0));
  for (;;) {
    int fd = open_input_path("/dev/hvc0");
    if (fd >= 0) {
      return fd;
    }
    yield_cpu();
  }
}

static int read_cmdline(char *buf, size_t max) {
  int fd = open("/proc/cmdline", O_RDONLY | O_NOCTTY);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = read(fd, buf, max - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = '\0';
  return 0;
}

static int find_param_value(const char *cmdline, const char *key, char *out, size_t out_max) {
  size_t key_len = strlen(key);
  const char *p = cmdline;
  while (*p) {
    while (*p == ' ' || *p == '\n' || *p == '\r') p++;
    if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
      p += key_len + 1;
      size_t i = 0;
      while (*p && *p != ' ' && *p != '\n' && *p != '\r' && i + 1 < out_max) {
        out[i++] = *p++;
      }
      out[i] = '\0';
      return 0;
    }
    while (*p && *p != ' ' && *p != '\n') p++;
  }
  return -1;
}

static int cmdline_has_token(const char *cmdline, const char *token) {
  size_t len = strlen(token);
  const char *p = cmdline;
  while (*p) {
    while (*p == ' ' || *p == '\n' || *p == '\r') p++;
    if (strncmp(p, token, len) == 0 &&
        (p[len] == '\0' || p[len] == ' ' || p[len] == '\n' || p[len] == '\r')) {
      return 1;
    }
    while (*p && *p != ' ' && *p != '\n' && *p != '\r') p++;
  }
  return 0;
}

static int cmdline_has_root(const char *cmdline) {
  char root_dev[256];
  return find_param_value(cmdline, "root", root_dev, sizeof(root_dev)) == 0;
}

static int wait_for_path(const char *path, int attempts, int delay_ms) {
  for (int i = 0; i < attempts; i++) {
    if (access(path, F_OK) == 0) {
      return 0;
    }
    usleep((useconds_t)delay_ms * 1000);
  }
  return -1;
}

static int run_fsck(const char *root_dev) {
  if (access("/sbin/e2fsck", X_OK) != 0) {
    write_line("m80 initramfs: e2fsck not available");
    return 0;
  }

  write_line("m80 initramfs: running e2fsck -p");
  pid_t pid = fork();
  if (pid < 0) {
    write_line("m80 initramfs: e2fsck fork failed");
    return -1;
  }
  if (pid == 0) {
    execl("/sbin/e2fsck", "e2fsck", "-p", root_dev, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    write_line("m80 initramfs: e2fsck wait failed");
    return -1;
  }
  if (!WIFEXITED(status)) {
    write_line("m80 initramfs: e2fsck failed");
    return -1;
  }

  int rc = WEXITSTATUS(status);
  if (rc == 0 || rc == 1) {
    write_line("m80 initramfs: e2fsck ok");
    return 0;
  }
  if (rc == 2) {
    write_line("m80 initramfs: e2fsck requested reboot");
    sync();
    reboot(RB_AUTOBOOT);
    return -1;
  }

  write_line("m80 initramfs: e2fsck failed");
  return -1;
}

static void write_file(const char *path, const char *content) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    write_line("m80 initramfs: write_file open failed");
    return;
  }
  write(fd, content, strlen(content));
  close(fd);
}

// Create parent directories recursively (simple version)
static void mkdir_p(const char *path) {
  char tmp[512];
  char *p = NULL;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", path);
  len = strlen(tmp);
  if (len > 0 && tmp[len - 1] == '/') {
    tmp[len - 1] = '\0';
  }
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(tmp, 0755);
      *p = '/';
    }
  }
  mkdir(tmp, 0755);
}

// Mount virtiofs shares from kernel cmdline parameter m80.mounts=tag1:/path1,tag2:/path2
static int mount_virtiofs_from_cmdline(const char *cmdline) {
  char mounts_param[1024];
  if (find_param_value(cmdline, "m80.mounts", mounts_param, sizeof(mounts_param)) != 0) {
    return 0; // No mounts specified
  }

  int mounted_count = 0;
  char *saveptr1 = NULL;
  char mounts_copy[1024];
  strncpy(mounts_copy, mounts_param, sizeof(mounts_copy) - 1);
  mounts_copy[sizeof(mounts_copy) - 1] = '\0';

  char *entry = strtok_r(mounts_copy, ",", &saveptr1);
  while (entry != NULL) {
    // Parse tag:path
    char *colon = strchr(entry, ':');
    if (colon == NULL) {
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: invalid mount entry: %s", entry);
      write_line(msg);
      entry = strtok_r(NULL, ",", &saveptr1);
      continue;
    }

    *colon = '\0';
    const char *tag = entry;
    const char *guest_path = colon + 1;

    // Build the full path under /new_root
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/new_root%s", guest_path);

    // Create mount point
    mkdir_p(full_path);

    // Attempt mount
    if (mount(tag, full_path, "virtiofs", 0, NULL) == 0) {
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: mounted virtiofs %s -> %s", tag, guest_path);
      write_line(msg);
      mounted_count++;
    } else {
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: failed to mount virtiofs %s -> %s (errno=%d)",
               tag, guest_path, errno);
      write_line(msg);
    }

    entry = strtok_r(NULL, ",", &saveptr1);
  }

  return mounted_count;
}

// Mount virtiofs devices discovered via sysfs (kernel 6.9+ with /sys/fs/virtiofs)
// This provides automatic discovery when the cmdline doesn't specify mounts
static int mount_virtiofs_from_sysfs(void) {
  const char *sysfs_dir = "/sys/fs/virtiofs";

  // Check if sysfs virtiofs directory exists (kernel 6.9+)
  if (access(sysfs_dir, F_OK) != 0) {
    return 0; // Sysfs virtiofs not available (older kernel)
  }

  DIR *dir = opendir(sysfs_dir);
  if (dir == NULL) {
    return 0;
  }

  int mounted_count = 0;
  struct dirent *entry;

  while ((entry = readdir(dir)) != NULL) {
    // Skip . and ..
    if (entry->d_name[0] == '.') {
      continue;
    }

    // Read the tag from /sys/fs/virtiofs/<N>/tag
    char tag_path[512];
    snprintf(tag_path, sizeof(tag_path), "%s/%s/tag", sysfs_dir, entry->d_name);

    int fd = open(tag_path, O_RDONLY);
    if (fd < 0) {
      continue;
    }

    char tag[128];
    ssize_t n = read(fd, tag, sizeof(tag) - 1);
    close(fd);

    if (n <= 0) {
      continue;
    }
    tag[n] = '\0';

    // Trim newline
    char *newline = strchr(tag, '\n');
    if (newline) {
      *newline = '\0';
    }

    // Mount to /mnt/<tag>
    char guest_path[256];
    snprintf(guest_path, sizeof(guest_path), "/mnt/%s", tag);

    char full_path[512];
    snprintf(full_path, sizeof(full_path), "/new_root%s", guest_path);

    mkdir_p(full_path);

    if (mount(tag, full_path, "virtiofs", 0, NULL) == 0) {
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: mounted virtiofs %s -> %s (sysfs)", tag, guest_path);
      write_line(msg);
      mounted_count++;
    }
  }

  closedir(dir);
  return mounted_count;
}

// Check if a guest_path is in the cmdline mount config
static int is_mount_in_config(const char *cmdline, const char *guest_path) {
  char mounts_param[1024];
  if (find_param_value(cmdline, "m80.mounts", mounts_param, sizeof(mounts_param)) != 0) {
    return 0;
  }

  char mounts_copy[1024];
  strncpy(mounts_copy, mounts_param, sizeof(mounts_copy) - 1);
  mounts_copy[sizeof(mounts_copy) - 1] = '\0';

  char *saveptr = NULL;
  char *entry = strtok_r(mounts_copy, ",", &saveptr);
  while (entry != NULL) {
    char *colon = strchr(entry, ':');
    if (colon != NULL) {
      const char *path = colon + 1;
      if (strcmp(path, guest_path) == 0) {
        return 1;
      }
    }
    entry = strtok_r(NULL, ",", &saveptr);
  }
  return 0;
}

// Unmount virtiofs shares that are no longer in the config
static void unmount_stale_virtiofs(const char *cmdline) {
  FILE *fp = fopen("/proc/mounts", "r");
  if (fp == NULL) {
    return;
  }

  char line[1024];
  char stale_mounts[16][256];
  int stale_count = 0;

  while (fgets(line, sizeof(line), fp) != NULL && stale_count < 16) {
    char device[256], mountpoint[256], fstype[64];
    if (sscanf(line, "%255s %255s %63s", device, mountpoint, fstype) != 3) {
      continue;
    }

    if (strcmp(fstype, "virtiofs") != 0) {
      continue;
    }

    // Check if this mount is in the current config
    if (!is_mount_in_config(cmdline, mountpoint)) {
      strncpy(stale_mounts[stale_count], mountpoint, 255);
      stale_mounts[stale_count][255] = '\0';
      stale_count++;
    }
  }
  fclose(fp);

  // Unmount stale mounts
  for (int i = 0; i < stale_count; i++) {
    if (umount(stale_mounts[i]) == 0) {
      char msg[256];
      snprintf(msg, sizeof(msg), "m80 initramfs: unmounted stale virtiofs %s", stale_mounts[i]);
      write_line(msg);
      // Try to remove empty directory
      rmdir(stale_mounts[i]);
    }
  }
}

static int mount_virtiofs_shares(const char *cmdline) {
  // Check if virtiofs driver is loaded
  if (access("/sys/bus/virtio/drivers/virtiofs", F_OK) != 0) {
    return 0; // No virtiofs driver loaded, nothing to mount
  }

  // Unmount any virtiofs shares no longer in config
  unmount_stale_virtiofs(cmdline);

  // First, try to mount from kernel cmdline specifications
  int count = mount_virtiofs_from_cmdline(cmdline);

  // If cmdline mounts worked, we're done
  if (count > 0) {
    return count;
  }

  // Second, try sysfs enumeration (kernel 6.9+)
  count = mount_virtiofs_from_sysfs();
  if (count > 0) {
    return count;
  }

  // Fallback: if no mounts found, try default "host" tag
  mkdir("/new_root/mnt", 0755);
  mkdir("/new_root/mnt/host", 0755);

  if (mount("host", "/new_root/mnt/host", "virtiofs", 0, NULL) == 0) {
    write_line("m80 initramfs: mounted virtiofs host -> /mnt/host (default)");
    return 1;
  }

  return 0;
}

// Convert a path to systemd mount unit filename (e.g., /mnt/host -> mnt-host.mount)
static void path_to_unit_name(const char *path, char *out, size_t out_size) {
  // Skip leading slash
  const char *p = path;
  if (*p == '/') p++;

  size_t pos = 0;
  while (*p && pos + 1 < out_size - 6) { // Reserve space for ".mount"
    if (*p == '/') {
      out[pos++] = '-';
    } else {
      out[pos++] = *p;
    }
    p++;
  }
  // Remove trailing dash if any
  if (pos > 0 && out[pos - 1] == '-') {
    pos--;
  }
  snprintf(out + pos, out_size - pos, ".mount");
}

static void install_systemd_mount_unit_for(const char *tag, const char *guest_path) {
  char unit_name[256];
  path_to_unit_name(guest_path, unit_name, sizeof(unit_name));

  char unit_path[512];
  snprintf(unit_path, sizeof(unit_path), "/new_root/etc/systemd/system/%s", unit_name);

  char unit_content[1024];
  snprintf(unit_content, sizeof(unit_content),
      "[Unit]\n"
      "Description=m80 virtiofs share (%s)\n"
      "After=local-fs-pre.target\n"
      "Before=local-fs.target\n"
      "\n"
      "[Mount]\n"
      "What=%s\n"
      "Where=%s\n"
      "Type=virtiofs\n"
      "Options=nofail,x-systemd.device-timeout=5\n"
      "\n"
      "[Install]\n"
      "WantedBy=local-fs.target\n",
      tag, tag, guest_path);

  write_file(unit_path, unit_content);

  char symlink_path[512];
  snprintf(symlink_path, sizeof(symlink_path),
      "/new_root/etc/systemd/system/local-fs.target.wants/%s", unit_name);
  char symlink_target[256];
  snprintf(symlink_target, sizeof(symlink_target), "../%s", unit_name);
  symlink(symlink_target, symlink_path);
}

static void install_systemd_mount_unit(const char *cmdline) {
  mkdir("/new_root/etc", 0755);
  mkdir("/new_root/etc/systemd", 0755);
  mkdir("/new_root/etc/systemd/system", 0755);
  mkdir("/new_root/etc/systemd/system/local-fs.target.wants", 0755);

  char mounts_param[1024];
  if (find_param_value(cmdline, "m80.mounts", mounts_param, sizeof(mounts_param)) == 0) {
    // Install units for each configured mount
    char mounts_copy[1024];
    strncpy(mounts_copy, mounts_param, sizeof(mounts_copy) - 1);
    mounts_copy[sizeof(mounts_copy) - 1] = '\0';

    char *saveptr = NULL;
    char *entry = strtok_r(mounts_copy, ",", &saveptr);
    while (entry != NULL) {
      char *colon = strchr(entry, ':');
      if (colon != NULL) {
        *colon = '\0';
        const char *tag = entry;
        const char *guest_path = colon + 1;
        install_systemd_mount_unit_for(tag, guest_path);
      }
      entry = strtok_r(NULL, ",", &saveptr);
    }
  } else {
    // Fallback: install default host mount unit
    install_systemd_mount_unit_for("host", "/mnt/host");
  }
}

static int mount_root_and_switch(void) {
  char cmdline[1024];
  char root_dev[256] = "/dev/vda";
  char root_fstype[64] = "ext4";
  int ro = 0;

  if (read_cmdline(cmdline, sizeof(cmdline)) == 0) {
    find_param_value(cmdline, "root", root_dev, sizeof(root_dev));
    find_param_value(cmdline, "rootfstype", root_fstype, sizeof(root_fstype));
    if (cmdline_has_token(cmdline, "ro")) ro = 1;
    if (cmdline_has_token(cmdline, "rw")) ro = 0;
  }

  mkdir("/new_root", 0755);
  if (wait_for_path(root_dev, 100, 50) != 0) {
    write_line("m80 initramfs: root device missing");
    return -1;
  }

  if (run_fsck(root_dev) != 0) {
    write_line("m80 initramfs: fsck failed, trying mount anyway");
    // Continue anyway - fsck failure might be recoverable
  }

  if (mount(root_dev, "/new_root", root_fstype, ro ? MS_RDONLY : 0, NULL) != 0) {
    write_line("m80 initramfs: root mount failed");
    return -1;
  }

  mkdir("/new_root/proc", 0555);
  mkdir("/new_root/sys", 0555);
  mkdir("/new_root/dev", 0755);

  // Mount virtiofs shares early (before systemd) for reliability
  mount_virtiofs_shares(cmdline);

  // Also install systemd unit as fallback for remounting after reboot
  install_systemd_mount_unit(cmdline);

  mount("/proc", "/new_root/proc", NULL, MS_MOVE, NULL);
  mount("/sys", "/new_root/sys", NULL, MS_MOVE, NULL);
  mount("/dev", "/new_root/dev", NULL, MS_MOVE, NULL);

  if (chdir("/new_root") != 0 || chroot(".") != 0) {
    write_line("m80 initramfs: chroot failed");
    return -1;
  }

  const char *init = "/sbin/init";
  char *const argv[] = { (char *)init, NULL };
  execv(init, argv);
  write_line("m80 initramfs: exec init failed");
  return -1;
}

static ssize_t read_line(int fd, char *buf, size_t max) {
  size_t pos = 0;
  while (pos + 1 < max) {
    char c = 0;
    ssize_t n = read(fd, &c, 1);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (pos == 0) {
        return 0;
      }
      yield_cpu();
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    if (c == '\r') {
      continue;
    }
    if (c == '\n') {
      break;
    }
    buf[pos++] = c;
  }
  buf[pos] = '\0';
  return (ssize_t)pos;
}

static void write_prompt(void) {
}

static void shell_write_line(const char *msg) {
  int fd = open("/dev/ttyAMA0", O_WRONLY | O_NOCTTY | O_NONBLOCK);
  if (fd >= 0) {
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
    close(fd);
  }
  if (broadcast_output) {
    write_kmsg_line(msg);
  }
}

static void shell_loop(void) {
  write_kmsg_line("m80 initramfs: entering shell loop");
  int fd = open_console();
  if (fd < 0) {
    write_line("m80 initramfs: console unavailable");
    for (;;) {
      sleep(1);
    }
  }
  write_kmsg_line("m80 initramfs: shell console open");
  shell_write_line("m80 initramfs: shell console open");

  for (;;) {
    char line[256];
    static int prompt_pending = 1;
    if (prompt_pending) {
      write_prompt();
      prompt_pending = 0;
    }
    if (read_line(fd, line, sizeof(line)) <= 0) {
      yield_cpu();
      continue;
    }
    prompt_pending = 1;
    char *cmd = line;
    while (*cmd == ' ' || *cmd == '\t') {
      cmd++;
    }
    if (*cmd == '\0') {
      continue;
    }
    if (strcmp(cmd, "help") == 0) {
      shell_write_line("m80 shell: help uptime echo reboot poweroff halt");
      continue;
    }
    if (strcmp(cmd, "uptime") == 0) {
      long uptime_ms = read_uptime_ms();
      if (uptime_ms >= 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "m80 shell: uptime_ms=%ld", uptime_ms);
        shell_write_line(buf);
      } else {
        shell_write_line("m80 shell: uptime_ms=unavailable");
      }
      continue;
    }
    if (strncmp(cmd, "echo ", 5) == 0) {
      shell_write_line(cmd + 5);
      continue;
    }
    if (strcmp(cmd, "reboot") == 0) {
      sync();
      reboot(RB_AUTOBOOT);
      continue;
    }
    if (strcmp(cmd, "poweroff") == 0 || strcmp(cmd, "halt") == 0) {
      sync();
      reboot(RB_POWER_OFF);
      continue;
    }
    shell_write_line("m80 shell: unknown command");
  }
}

int main(void) {
  mkdir("/proc", 0555);
  mkdir("/sys", 0555);
  ensure_dev_nodes();

  mount("proc", "/proc", "proc", 0, NULL);
  mount("sysfs", "/sys", "sysfs", 0, NULL);

  char cmdline[1024] = {0};
  int have_cmdline = read_cmdline(cmdline, sizeof(cmdline)) == 0;
  if (have_cmdline && (cmdline_has_token(cmdline, "m80.smoke=1") || cmdline_has_token(cmdline, "m80.console_broadcast=1"))) {
    broadcast_output = 1;
  }

  if (broadcast_output) {
    write_line("m80 initramfs: boot ok");
  }
  if (!have_cmdline || !cmdline_has_root(cmdline)) {
    write_line("m80 initramfs: rootless shell mode");
    start_console_modules();
    write_line("m80 initramfs: console modules started");
    shell_loop();
  }

  load_required_modules();

  if (broadcast_output) {
    write_line("m80 initramfs: hello, world");
    long uptime_ms = read_uptime_ms();
    if (uptime_ms >= 0) {
      char buf[128];
      snprintf(buf, sizeof(buf), "m80 initramfs: uptime_ms=%ld", uptime_ms);
      write_line(buf);
    } else {
      write_line("m80 initramfs: uptime_ms=unavailable");
    }
  }

  if (mount_root_and_switch() == 0) {
    return 0;
  }

  shell_loop();

  return 0;
}

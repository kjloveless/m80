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

static void write_line(const char *msg) {
  const char *suffix = "\n";
  int fd = open("/dev/console", O_WRONLY | O_NOCTTY);
  if (fd < 0) {
    fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY);
  }
  if (fd >= 0) {
    write(fd, msg, strlen(msg));
    write(fd, suffix, 1);
    close(fd);
  }
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
  int fd = open("/dev/console", O_RDWR | O_NOCTTY);
  if (fd < 0) {
    mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
    fd = open("/dev/console", O_RDWR | O_NOCTTY);
  }
  if (fd < 0) {
    fd = open("/dev/ttyAMA0", O_RDWR | O_NOCTTY);
  }
  if (fd < 0) {
    fd = open("/dev/ttyS0", O_RDWR | O_NOCTTY);
  }
  if (fd >= 0) {
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
  }
  return fd;
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
    while (*p == ' ') p++;
    if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
      p += key_len + 1;
      size_t i = 0;
      while (*p && *p != ' ' && i + 1 < out_max) {
        out[i++] = *p++;
      }
      out[i] = '\0';
      return 0;
    }
    while (*p && *p != ' ') p++;
  }
  return -1;
}

static int cmdline_has_token(const char *cmdline, const char *token) {
  size_t len = strlen(token);
  const char *p = cmdline;
  while (*p) {
    while (*p == ' ') p++;
    if (strncmp(p, token, len) == 0 && (p[len] == '\0' || p[len] == ' ')) {
      return 1;
    }
    while (*p && *p != ' ') p++;
  }
  return 0;
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

static int mount_virtiofs_shares(void) {
  // Check if any virtiofs devices exist by looking at sysfs
  // The kernel creates /sys/bus/virtio/drivers/virtiofs/virtioN for each device
  if (access("/sys/bus/virtio/drivers/virtiofs", F_OK) != 0) {
    return 0; // No virtiofs driver loaded, nothing to mount
  }

  // Try to mount the 'host' tag to /mnt/host
  // This is the default m80 convention
  mkdir("/new_root/mnt", 0755);
  mkdir("/new_root/mnt/host", 0755);

  if (mount("host", "/new_root/mnt/host", "virtiofs", 0, NULL) == 0) {
    write_line("m80 initramfs: mounted virtiofs host -> /mnt/host");
    return 1;
  }

  // Mount failed - might not be configured, that's ok
  return 0;
}

static void install_systemd_mount_unit(void) {
  mkdir("/new_root/etc", 0755);
  mkdir("/new_root/etc/systemd", 0755);
  mkdir("/new_root/etc/systemd/system", 0755);
  mkdir("/new_root/etc/systemd/system/local-fs.target.wants", 0755);

  write_file(
      "/new_root/etc/systemd/system/mnt-host.mount",
      "[Unit]\n"
      "Description=m80 host share\n"
      "After=local-fs-pre.target\n"
      "Before=local-fs.target\n"
      "\n"
      "[Mount]\n"
      "What=host\n"
      "Where=/mnt/host\n"
      "Type=virtiofs\n"
      "Options=defaults\n"
      "\n"
      "[Install]\n"
      "WantedBy=local-fs.target\n");

  symlink("../mnt-host.mount", "/new_root/etc/systemd/system/local-fs.target.wants/mnt-host.mount");
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
  mount_virtiofs_shares();

  // Also install systemd unit as fallback for remounting after reboot
  install_systemd_mount_unit();

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
  const char *prompt = "m80> ";
  write(1, prompt, strlen(prompt));
}

static void shell_loop(void) {
  int fd = open_console();
  if (fd < 0) {
    write_line("m80 initramfs: console unavailable");
    for (;;) {
      sleep(1);
    }
  }

  for (;;) {
    char line[256];
    write_prompt();
    if (read_line(fd, line, sizeof(line)) <= 0) {
      continue;
    }
    char *cmd = line;
    while (*cmd == ' ' || *cmd == '\t') {
      cmd++;
    }
    if (*cmd == '\0') {
      continue;
    }
    if (strcmp(cmd, "help") == 0) {
      write_line("m80 shell: help uptime echo reboot poweroff halt");
      continue;
    }
    if (strcmp(cmd, "uptime") == 0) {
      long uptime_ms = read_uptime_ms();
      if (uptime_ms >= 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "m80 shell: uptime_ms=%ld", uptime_ms);
        write_line(buf);
      } else {
        write_line("m80 shell: uptime_ms=unavailable");
      }
      continue;
    }
    if (strncmp(cmd, "echo ", 5) == 0) {
      write_line(cmd + 5);
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
    write_line("m80 shell: unknown command");
  }
}

int main(void) {
  mkdir("/proc", 0555);
  mkdir("/sys", 0555);
  ensure_dev_nodes();

  mount("proc", "/proc", "proc", 0, NULL);
  mount("sysfs", "/sys", "sysfs", 0, NULL);

  load_required_modules();

  write_line("m80 initramfs: boot ok");
  write_line("m80 initramfs: hello, world");
  {
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

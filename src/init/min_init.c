#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
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

  shell_loop();

  return 0;
}

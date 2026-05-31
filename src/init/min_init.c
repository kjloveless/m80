#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int broadcast_output = 0;

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#define M80_VSOCK_HOST_CID 2U
#define M80_VSOCK_PORT 19000U
#define M80_AGENT_MAX_FRAME (1024U * 1024U)
#define M80_SOCKS_PORT 1080U
#define M80_TCP_RELAY_CHUNK 2048U
#define M80_TCP_RELAY_IDLE_TIMEOUT_MS 60000LL
#define M80_UDP_RELAY_CHUNK 4096U
#define M80_TUN_MTU 1500U
#define M80_TUN_NAME "m80tun0"
#define M80_TUN_IPV4 "10.80.0.2"
#define M80_TUN_IPV4_NETMASK "255.255.255.252"
#define M80_TUN_IPV6 "fd00:6d38:30::2"
#define M80_TUN_IPV6_PREFIX 64U
#define M80_ICMP_ECHO_OK 0
#define M80_ICMP_ECHO_BLOCKED 1
#define M80_ICMP_ECHO_FAILED -1

#ifndef TUNSETIFF
#define TUNSETIFF 0x400454ca
#endif
#ifndef IFF_TUN
#define IFF_TUN 0x0001
#endif
#ifndef IFF_NO_PI
#define IFF_NO_PI 0x1000
#endif

struct sockaddr_vm {
  sa_family_t svm_family;
  unsigned short svm_reserved1;
  unsigned int svm_port;
  unsigned int svm_cid;
  unsigned char svm_zero[sizeof(struct sockaddr) -
                         sizeof(sa_family_t) -
                         sizeof(unsigned short) -
                         sizeof(unsigned int) -
                         sizeof(unsigned int)];
};

struct guest_service_config {
  int enable_dns;
  int enable_metadata;
  int enable_outbound;
  char network_mode[32];
};

struct guest_agent_state {
  int vsock_fd;
  int vsock_lock_fd;
  int hold_vsock_lock;
  int persistent_vsock;
  int shutdown_started;
  unsigned int next_id;
  long long next_heartbeat_ms;
  struct guest_service_config config;
};

static void write_file(const char *path, const char *content);
static void mkdir_p(const char *path);
static void shell_write_line(const char *msg);
static int acquire_vsock_session_lock(void);
static void release_vsock_session_lock(int fd);

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
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/drivers/net/tun.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/net/vmw_vsock/vsock.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko",
      "/lib/modules/6.1.0-42-cloud-arm64/kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko",
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

static long long monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return ((long long)ts.tv_sec * 1000LL) + ((long long)ts.tv_nsec / 1000000LL);
}

static int has_service_token(const char *services, const char *token) {
  char copy[128];
  strncpy(copy, services, sizeof(copy) - 1);
  copy[sizeof(copy) - 1] = '\0';

  char *saveptr = NULL;
  char *part = strtok_r(copy, ",", &saveptr);
  while (part != NULL) {
    while (*part == ' ' || *part == '\t') {
      part++;
    }
    char *end = part + strlen(part);
    while (end > part && (end[-1] == ' ' || end[-1] == '\t')) {
      end--;
    }
    *end = '\0';
    if (strcmp(part, token) == 0) {
      return 1;
    }
    part = strtok_r(NULL, ",", &saveptr);
  }
  return 0;
}

static int parse_guest_service_config(const char *cmdline, struct guest_service_config *cfg) {
  char services[128];
  memset(cfg, 0, sizeof(*cfg));
  if (find_param_value(cmdline, "m80.network_mode", cfg->network_mode, sizeof(cfg->network_mode)) != 0) {
    strncpy(cfg->network_mode, "locked_down", sizeof(cfg->network_mode) - 1);
    cfg->network_mode[sizeof(cfg->network_mode) - 1] = '\0';
  }
  cfg->enable_outbound = strcmp(cfg->network_mode, "locked_down") != 0;

  if (find_param_value(cmdline, "m80.network_services", services, sizeof(services)) != 0) {
    return cfg->enable_outbound;
  }

  cfg->enable_dns = has_service_token(services, "dns");
  cfg->enable_metadata = has_service_token(services, "metadata");
  if (!cfg->enable_dns && !cfg->enable_metadata && !cfg->enable_outbound) {
    return 0;
  }
  return 1;
}

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = (const unsigned char *)buf;
  size_t total = 0;
  while (total < len) {
    ssize_t n = write(fd, p + total, len - total);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    total += (size_t)n;
  }
  return 0;
}

static int read_full(int fd, void *buf, size_t len) {
  unsigned char *p = (unsigned char *)buf;
  size_t total = 0;
  while (total < len) {
    ssize_t n = read(fd, p + total, len - total);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return -1;
    }
    total += (size_t)n;
  }
  return 0;
}

static int rpc_write_frame(int fd, const char *payload, size_t len) {
  unsigned char header[4];
  if (len > M80_AGENT_MAX_FRAME) {
    return -1;
  }
  header[0] = (unsigned char)(len & 0xffU);
  header[1] = (unsigned char)((len >> 8) & 0xffU);
  header[2] = (unsigned char)((len >> 16) & 0xffU);
  header[3] = (unsigned char)((len >> 24) & 0xffU);
  if (write_full(fd, header, sizeof(header)) != 0) {
    return -1;
  }
  return write_full(fd, payload, len);
}

static char *rpc_read_frame_alloc(int fd) {
  unsigned char header[4];
  if (read_full(fd, header, sizeof(header)) != 0) {
    return NULL;
  }
  unsigned int len = (unsigned int)header[0] |
                     ((unsigned int)header[1] << 8) |
                     ((unsigned int)header[2] << 16) |
                     ((unsigned int)header[3] << 24);
  if (len == 0 || len > M80_AGENT_MAX_FRAME) {
    return NULL;
  }
  char *payload = (char *)malloc((size_t)len + 1U);
  if (payload == NULL) {
    return NULL;
  }
  if (read_full(fd, payload, len) != 0) {
    free(payload);
    return NULL;
  }
  payload[len] = '\0';
  return payload;
}

static const char *json_find_key_value(const char *json, const char *key) {
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  const char *p = strstr(json, pattern);
  if (p == NULL) {
    return NULL;
  }
  p += strlen(pattern);
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  if (*p != ':') {
    return NULL;
  }
  p++;
  while (*p && isspace((unsigned char)*p)) {
    p++;
  }
  return p;
}

static int json_extract_int(const char *json, const char *key, long *out) {
  const char *p = json_find_key_value(json, key);
  char *end = NULL;
  long value;
  if (p == NULL) {
    return -1;
  }
  value = strtol(p, &end, 10);
  if (end == p) {
    return -1;
  }
  *out = value;
  return 0;
}

static int json_extract_bool(const char *json, const char *key, int *out) {
  const char *p = json_find_key_value(json, key);
  if (p == NULL) {
    return -1;
  }
  if (strncmp(p, "true", 4) == 0) {
    *out = 1;
    return 0;
  }
  if (strncmp(p, "false", 5) == 0) {
    *out = 0;
    return 0;
  }
  return -1;
}

static char *json_extract_string_dup(const char *json, const char *key) {
  const char *p = json_find_key_value(json, key);
  size_t cap;
  char *out;
  size_t pos = 0;
  if (p == NULL || *p != '"') {
    return NULL;
  }
  p++;
  cap = strlen(p) + 1U;
  out = (char *)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  while (*p && *p != '"') {
    if (*p == '\\') {
      p++;
      if (*p == '\0') {
        free(out);
        return NULL;
      }
      switch (*p) {
        case '"':
        case '\\':
        case '/':
          out[pos++] = *p;
          p++;
          break;
        case 'b':
          out[pos++] = '\b';
          p++;
          break;
        case 'f':
          out[pos++] = '\f';
          p++;
          break;
        case 'n':
          out[pos++] = '\n';
          p++;
          break;
        case 'r':
          out[pos++] = '\r';
          p++;
          break;
        case 't':
          out[pos++] = '\t';
          p++;
          break;
        case 'u':
          if (strncmp(p, "u003c", 5) == 0) {
            out[pos++] = '<';
            p += 5;
          } else if (strncmp(p, "u003e", 5) == 0) {
            out[pos++] = '>';
            p += 5;
          } else if (strncmp(p, "u0026", 5) == 0) {
            out[pos++] = '&';
            p += 5;
          } else {
            free(out);
            return NULL;
          }
          break;
        default:
          free(out);
          return NULL;
      }
      continue;
    }
    out[pos++] = *p++;
  }
  if (*p != '"') {
    free(out);
    return NULL;
  }
  out[pos] = '\0';
  return out;
}

static int json_response_ok(const char *json) {
  const char *p = json_find_key_value(json, "ok");
  return p != NULL && strncmp(p, "true", 4) == 0;
}

static void close_agent_vsock(struct guest_agent_state *state) {
  if (state->vsock_fd >= 0) {
    close(state->vsock_fd);
    state->vsock_fd = -1;
  }
  if (state->vsock_lock_fd >= 0 && !state->hold_vsock_lock) {
    release_vsock_session_lock(state->vsock_lock_fd);
    state->vsock_lock_fd = -1;
  }
}

static void request_guest_poweroff(struct guest_agent_state *state) {
  pid_t pid;
  if (state->shutdown_started) {
    return;
  }
  state->shutdown_started = 1;
  write_line("m80 initramfs: guest shutdown requested");
  pid = fork();
  if (pid < 0) {
    sync();
    reboot(RB_POWER_OFF);
    return;
  }
  if (pid == 0) {
    signal(SIGPIPE, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    sync();
    if (chroot("/new_root") == 0) {
      chdir("/");
      execl("/usr/bin/systemctl", "systemctl", "poweroff", "--no-wall", (char *)NULL);
      execl("/bin/systemctl", "systemctl", "poweroff", "--no-wall", (char *)NULL);
      execl("/usr/sbin/poweroff", "poweroff", (char *)NULL);
      execl("/sbin/poweroff", "poweroff", (char *)NULL);
      execl("/bin/poweroff", "poweroff", (char *)NULL);
    }
    reboot(RB_POWER_OFF);
    _exit(127);
  }
}

static int send_heartbeat_fd(int fd, unsigned int id, int *shutdown_requested) {
  char request[384];
  char *response = NULL;
  int ok = 0;
  int requested = 0;
  if (shutdown_requested != NULL) {
    *shutdown_requested = 0;
  }
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"agent.heartbeat\","
           "\"params\":{}}",
           id);
  if (rpc_write_frame(fd, request, strlen(request)) != 0) {
    return -1;
  }
  response = rpc_read_frame_alloc(fd);
  if (response == NULL) {
    return -1;
  }
  ok = json_response_ok(response);
  if (ok && json_extract_bool(response, "shutdown_requested", &requested) == 0 && requested) {
    if (shutdown_requested != NULL) {
      *shutdown_requested = 1;
    }
  }
  free(response);
  return ok ? 0 : -1;
}

static int ensure_agent_connection(struct guest_agent_state *state) {
  int fd;
  struct sockaddr_vm addr;
  int shutdown_requested = 0;
  if (state->vsock_fd >= 0) {
    return 0;
  }

  fd = socket(AF_VSOCK, SOCK_STREAM, 0);
  if (fd < 0) {
    close_agent_vsock(state);
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_port = M80_VSOCK_PORT;
  addr.svm_cid = M80_VSOCK_HOST_CID;
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    close_agent_vsock(state);
    return -1;
  }
  if (state->persistent_vsock && send_heartbeat_fd(fd, state->next_id++, &shutdown_requested) != 0) {
    close(fd);
    close_agent_vsock(state);
    return -1;
  }
  state->vsock_fd = fd;
  state->next_heartbeat_ms = monotonic_ms() + 10000LL;
  if (shutdown_requested) {
    request_guest_poweroff(state);
  }
  return 0;
}

static char *rpc_exchange_alloc(struct guest_agent_state *state, const char *request) {
  int attempt;
  for (attempt = 0; attempt < 2; attempt++) {
    char *response = NULL;
    if (ensure_agent_connection(state) != 0) {
      continue;
    }
    if (rpc_write_frame(state->vsock_fd, request, strlen(request)) != 0) {
      close_agent_vsock(state);
      continue;
    }
    response = rpc_read_frame_alloc(state->vsock_fd);
    if (response == NULL) {
      close_agent_vsock(state);
      continue;
    }
    if (!state->persistent_vsock) {
      close_agent_vsock(state);
    }
    return response;
  }
  return NULL;
}

static void maybe_send_agent_heartbeat(struct guest_agent_state *state) {
  long long now = monotonic_ms();
  int shutdown_requested = 0;
  if (now < state->next_heartbeat_ms) {
    return;
  }
  if (state->vsock_fd < 0) {
    if (ensure_agent_connection(state) != 0) {
      state->next_heartbeat_ms = now + 1000LL;
    }
    return;
  }
  if (send_heartbeat_fd(state->vsock_fd, state->next_id++, &shutdown_requested) != 0) {
    close_agent_vsock(state);
  } else {
    state->next_heartbeat_ms = now + 10000LL;
    if (shutdown_requested) {
      request_guest_poweroff(state);
    }
  }
}

static void hex_encode(const unsigned char *src, size_t len, char *dst) {
  static const char digits[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    dst[i * 2] = digits[(src[i] >> 4) & 0x0fU];
    dst[i * 2 + 1] = digits[src[i] & 0x0fU];
  }
  dst[len * 2] = '\0';
}

static int hex_decode(const char *src, unsigned char *dst, size_t dst_cap, size_t *out_len) {
  size_t len = strlen(src);
  size_t i;
  if ((len & 1U) != 0 || (len / 2U) > dst_cap) {
    return -1;
  }
  for (i = 0; i < len; i += 2) {
    char hi = src[i];
    char lo = src[i + 1];
    unsigned int hi_val;
    unsigned int lo_val;
    if (!isxdigit((unsigned char)hi) || !isxdigit((unsigned char)lo)) {
      return -1;
    }
    hi_val = (unsigned int)(isdigit((unsigned char)hi) ? hi - '0' : (tolower((unsigned char)hi) - 'a' + 10));
    lo_val = (unsigned int)(isdigit((unsigned char)lo) ? lo - '0' : (tolower((unsigned char)lo) - 'a' + 10));
    dst[i / 2U] = (unsigned char)((hi_val << 4) | lo_val);
  }
  *out_len = len / 2U;
  return 0;
}

static int rpc_dns_query(struct guest_agent_state *state,
                         const unsigned char *query,
                         size_t query_len,
                         unsigned char *response,
                         size_t response_cap,
                         size_t *response_len) {
  char *payload = NULL;
  char *response_hex = NULL;
  char *rpc_response = NULL;
  char *request_hex = NULL;
  char request[9216];
  request_hex = (char *)malloc(query_len * 2U + 1U);
  if (request_hex == NULL) {
    return -1;
  }
  hex_encode(query, query_len, request_hex);
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"dns.query\","
           "\"params\":{\"request_hex\":\"%s\"}}",
           state->next_id++, request_hex);
  free(request_hex);

  rpc_response = rpc_exchange_alloc(state, request);
  if (rpc_response == NULL || !json_response_ok(rpc_response)) {
    free(rpc_response);
    return -1;
  }
  response_hex = json_extract_string_dup(rpc_response, "response_hex");
  free(rpc_response);
  if (response_hex == NULL) {
    return -1;
  }
  payload = response_hex;
  if (hex_decode(payload, response, response_cap, response_len) != 0) {
    free(response_hex);
    return -1;
  }
  free(response_hex);
  return 0;
}

static int rpc_metadata_get(struct guest_agent_state *state,
                            const char *path,
                            int *status_out,
                            char **content_type_out,
                            char **body_out) {
  char request[512];
  char *response = NULL;
  char *content_type = NULL;
  char *body = NULL;
  long status = 0;

  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"metadata.get\","
           "\"params\":{\"path\":\"%s\"}}",
           state->next_id++, path);
  response = rpc_exchange_alloc(state, request);
  if (response == NULL || !json_response_ok(response)) {
    free(response);
    return -1;
  }
  if (json_extract_int(response, "status", &status) != 0) {
    free(response);
    return -1;
  }
  content_type = json_extract_string_dup(response, "content_type");
  body = json_extract_string_dup(response, "body");
  free(response);
  if (content_type == NULL || body == NULL) {
    free(content_type);
    free(body);
    return -1;
  }

  *status_out = (int)status;
  *content_type_out = content_type;
  *body_out = body;
  return 0;
}

static int is_safe_socks_host(const char *host) {
  size_t i;
  size_t len = strlen(host);
  if (len == 0 || len > 253) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)host[i];
    if (isalnum(ch) || ch == '.' || ch == '-' || ch == '_' || ch == ':') {
      continue;
    }
    return 0;
  }
  return 1;
}

static int rpc_tcp_open(struct guest_agent_state *state,
                        const char *host,
                        unsigned short port,
                        long *stream_id_out) {
  char request[1024];
  char *response = NULL;
  long stream_id = 0;
  if (!is_safe_socks_host(host) || port == 0) {
    return -1;
  }

  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"tcp.open\","
           "\"params\":{\"host\":\"%s\",\"port\":%u}}",
           state->next_id++, host, (unsigned int)port);
  response = rpc_exchange_alloc(state, request);
  if (response == NULL || !json_response_ok(response)) {
    free(response);
    return -1;
  }
  if (json_extract_int(response, "stream_id", &stream_id) != 0 || stream_id <= 0) {
    free(response);
    return -1;
  }
  free(response);
  *stream_id_out = stream_id;
  return 0;
}

static int rpc_tcp_write(struct guest_agent_state *state,
                         long stream_id,
                         const unsigned char *data,
                         size_t data_len) {
  char *data_hex = NULL;
  char *response = NULL;
  char request[8192];
  int ok;
  if (data_len == 0) {
    return 0;
  }
  if (data_len > M80_TCP_RELAY_CHUNK) {
    return -1;
  }
  data_hex = (char *)malloc(data_len * 2U + 1U);
  if (data_hex == NULL) {
    return -1;
  }
  hex_encode(data, data_len, data_hex);
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"tcp.write\","
           "\"params\":{\"stream_id\":%ld,\"data_hex\":\"%s\"}}",
           state->next_id++, stream_id, data_hex);
  free(data_hex);
  response = rpc_exchange_alloc(state, request);
  if (response == NULL) {
    return -1;
  }
  ok = json_response_ok(response);
  free(response);
  return ok ? 0 : -1;
}

static int rpc_tcp_read(struct guest_agent_state *state,
                        long stream_id,
                        unsigned char *out,
                        size_t out_cap,
                        size_t *out_len,
                        int *eof_out) {
  char request[256];
  char *response = NULL;
  char *data_hex = NULL;
  int eof = 0;
  int rc = -1;

  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"tcp.read\","
           "\"params\":{\"stream_id\":%ld,\"max_bytes\":%zu}}",
           state->next_id++, stream_id, out_cap);
  response = rpc_exchange_alloc(state, request);
  if (response == NULL || !json_response_ok(response)) {
    free(response);
    return -1;
  }
  data_hex = json_extract_string_dup(response, "data_hex");
  if (data_hex == NULL || json_extract_bool(response, "eof", &eof) != 0) {
    goto done;
  }
  if (hex_decode(data_hex, out, out_cap, out_len) != 0) {
    goto done;
  }
  *eof_out = eof;
  rc = 0;

done:
  free(data_hex);
  free(response);
  return rc;
}

static void rpc_tcp_close(struct guest_agent_state *state, long stream_id) {
  char request[256];
  char *response = NULL;
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"tcp.close\","
           "\"params\":{\"stream_id\":%ld}}",
           state->next_id++, stream_id);
  response = rpc_exchange_alloc(state, request);
  free(response);
}

static int rpc_udp_exchange(struct guest_agent_state *state,
                            const char *host,
                            unsigned short port,
                            const unsigned char *data,
                            size_t data_len,
                            unsigned char *out,
                            size_t out_cap,
                            size_t *out_len) {
  char *data_hex = NULL;
  char *response = NULL;
  char *response_hex = NULL;
  char request[12288];
  int rc = -1;

  if (!is_safe_socks_host(host) || port == 0 || data_len == 0 ||
      data_len > M80_UDP_RELAY_CHUNK || out_cap < M80_UDP_RELAY_CHUNK) {
    return -1;
  }

  data_hex = (char *)malloc(data_len * 2U + 1U);
  if (data_hex == NULL) {
    return -1;
  }
  hex_encode(data, data_len, data_hex);
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"udp.exchange\","
           "\"params\":{\"host\":\"%s\",\"port\":%u,\"data_hex\":\"%s\"}}",
           state->next_id++, host, (unsigned int)port, data_hex);
  free(data_hex);

  response = rpc_exchange_alloc(state, request);
  if (response == NULL || !json_response_ok(response)) {
    free(response);
    return -1;
  }
  response_hex = json_extract_string_dup(response, "response_hex");
  if (response_hex == NULL) {
    goto done;
  }
  if (hex_decode(response_hex, out, out_cap, out_len) != 0) {
    goto done;
  }
  rc = 0;

done:
  free(response_hex);
  free(response);
  return rc;
}

static int rpc_icmp_echo(struct guest_agent_state *state,
                         const char *ip,
                         const unsigned char *payload,
                         size_t payload_len) {
  char *payload_hex = NULL;
  char *response = NULL;
  char *error_text = NULL;
  char request[3072];
  int ok;

  if (!is_safe_socks_host(ip) || payload_len > 1024U) {
    return M80_ICMP_ECHO_FAILED;
  }

  payload_hex = (char *)malloc(payload_len * 2U + 1U);
  if (payload_hex == NULL) {
    return M80_ICMP_ECHO_FAILED;
  }
  hex_encode(payload, payload_len, payload_hex);
  snprintf(request, sizeof(request),
           "{\"version\":1,\"id\":%u,\"method\":\"icmp.echo\","
           "\"params\":{\"ip\":\"%s\",\"payload_hex\":\"%s\"}}",
           state->next_id++, ip, payload_hex);
  free(payload_hex);

  response = rpc_exchange_alloc(state, request);
  if (response == NULL) {
    return M80_ICMP_ECHO_FAILED;
  }
  ok = json_response_ok(response);
  if (!ok) {
    error_text = json_extract_string_dup(response, "error");
    if (error_text != NULL &&
        strcmp(error_text, "icmp blocked by network policy") == 0) {
      free(error_text);
      free(response);
      return M80_ICMP_ECHO_BLOCKED;
    }
    free(error_text);
  }
  free(response);
  return ok ? M80_ICMP_ECHO_OK : M80_ICMP_ECHO_FAILED;
}

static unsigned int checksum_add(unsigned int sum, const unsigned char *buf, size_t len) {
  size_t i;
  for (i = 0; i + 1U < len; i += 2U) {
    sum += ((unsigned int)buf[i] << 8) | (unsigned int)buf[i + 1U];
  }
  if (i < len) {
    sum += (unsigned int)buf[i] << 8;
  }
  return sum;
}

static unsigned short checksum_finish(unsigned int sum) {
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xffffU) + (sum >> 16U);
  }
  return (unsigned short)(~sum & 0xffffU);
}

static unsigned short internet_checksum(const unsigned char *buf, size_t len) {
  return checksum_finish(checksum_add(0, buf, len));
}

static unsigned short icmpv6_checksum(const unsigned char *src,
                                      const unsigned char *dst,
                                      const unsigned char *icmp,
                                      size_t icmp_len) {
  unsigned int sum = 0;
  sum = checksum_add(sum, src, 16);
  sum = checksum_add(sum, dst, 16);
  sum += (unsigned int)((icmp_len >> 16U) & 0xffffU);
  sum += (unsigned int)(icmp_len & 0xffffU);
  sum += IPPROTO_ICMPV6;
  sum = checksum_add(sum, icmp, icmp_len);
  return checksum_finish(sum);
}

static int set_ifreq_sockaddr(struct ifreq *ifr, const char *ifname, const char *addr) {
  struct sockaddr_in *sin;
  memset(ifr, 0, sizeof(*ifr));
  strncpy(ifr->ifr_name, ifname, sizeof(ifr->ifr_name) - 1);
  sin = (struct sockaddr_in *)&ifr->ifr_addr;
  sin->sin_family = AF_INET;
  return inet_pton(AF_INET, addr, &sin->sin_addr) == 1 ? 0 : -1;
}

static int configure_tun_ipv4(const char *ifname) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr;
  if (fd < 0) {
    return -1;
  }
  if (set_ifreq_sockaddr(&ifr, ifname, M80_TUN_IPV4) != 0 ||
      ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
    close(fd);
    return -1;
  }
  if (set_ifreq_sockaddr(&ifr, ifname, M80_TUN_IPV4_NETMASK) != 0 ||
      ioctl(fd, SIOCSIFNETMASK, &ifr) != 0) {
    close(fd);
    return -1;
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
  ifr.ifr_mtu = (int)M80_TUN_MTU;
  ioctl(fd, SIOCSIFMTU, &ifr);

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
    close(fd);
    return -1;
  }
  ifr.ifr_flags |= (short)(IFF_UP | IFF_RUNNING);
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int add_ipv4_default_route(const char *ifname) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct rtentry route;
  struct sockaddr_in *dst;
  struct sockaddr_in *genmask;
  if (fd < 0) {
    return -1;
  }
  memset(&route, 0, sizeof(route));
  dst = (struct sockaddr_in *)&route.rt_dst;
  genmask = (struct sockaddr_in *)&route.rt_genmask;
  dst->sin_family = AF_INET;
  dst->sin_addr.s_addr = htonl(INADDR_ANY);
  genmask->sin_family = AF_INET;
  genmask->sin_addr.s_addr = htonl(INADDR_ANY);
  route.rt_flags = RTF_UP;
  route.rt_dev = (char *)ifname;
  if (ioctl(fd, SIOCADDRT, &route) != 0 && errno != EEXIST) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int nl_addattr(struct nlmsghdr *nlh,
                      size_t max_len,
                      unsigned short type,
                      const void *data,
                      size_t data_len) {
  size_t attr_len = RTA_LENGTH(data_len);
  size_t new_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(attr_len);
  struct rtattr *rta;
  if (new_len > max_len) {
    return -1;
  }
  rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = (unsigned short)attr_len;
  memcpy(RTA_DATA(rta), data, data_len);
  nlh->nlmsg_len = (unsigned int)new_len;
  return 0;
}

static int nl_send_request(struct nlmsghdr *nlh) {
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  char buf[4096];
  ssize_t n;
  if (fd < 0) {
    return -1;
  }
  if (send(fd, nlh, nlh->nlmsg_len, 0) < 0) {
    close(fd);
    return -1;
  }
  n = recv(fd, buf, sizeof(buf), 0);
  close(fd);
  if (n < 0) {
    return -1;
  }
  for (struct nlmsghdr *reply = (struct nlmsghdr *)buf;
       NLMSG_OK(reply, (unsigned int)n);
       reply = NLMSG_NEXT(reply, n)) {
    if (reply->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(reply);
      if (err->error == 0 || err->error == -EEXIST) {
        return 0;
      }
      errno = -err->error;
      return -1;
    }
  }
  return 0;
}

static int add_ipv6_address(const char *ifname) {
  struct {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
    char attrs[128];
  } req;
  struct in6_addr addr;
  unsigned int ifindex = if_nametoindex(ifname);
  if (ifindex == 0 || inet_pton(AF_INET6, M80_TUN_IPV6, &addr) != 1) {
    return -1;
  }
  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifa));
  req.nlh.nlmsg_type = RTM_NEWADDR;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
  req.ifa.ifa_family = AF_INET6;
  req.ifa.ifa_prefixlen = M80_TUN_IPV6_PREFIX;
  req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
  req.ifa.ifa_index = ifindex;
  if (nl_addattr(&req.nlh, sizeof(req), IFA_LOCAL, &addr, sizeof(addr)) != 0 ||
      nl_addattr(&req.nlh, sizeof(req), IFA_ADDRESS, &addr, sizeof(addr)) != 0) {
    return -1;
  }
  return nl_send_request(&req.nlh);
}

static int add_ipv6_default_route(const char *ifname) {
  struct {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
    char attrs[64];
  } req;
  unsigned int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    return -1;
  }
  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtm));
  req.nlh.nlmsg_type = RTM_NEWROUTE;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
  req.rtm.rtm_family = AF_INET6;
  req.rtm.rtm_dst_len = 0;
  req.rtm.rtm_table = RT_TABLE_MAIN;
  req.rtm.rtm_protocol = RTPROT_BOOT;
  req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
  req.rtm.rtm_type = RTN_UNICAST;
  if (nl_addattr(&req.nlh, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex)) != 0) {
    return -1;
  }
  return nl_send_request(&req.nlh);
}

static int setup_tun_interface(void) {
  int fd;
  struct ifreq ifr;
  int flags;

  mkdir_p("/dev/net");
  if (mknod("/dev/net/tun", S_IFCHR | 0666, makedev(10, 200)) != 0 && errno != EEXIST) {
    return -1;
  }

  fd = open("/dev/net/tun", O_RDWR | O_NOCTTY);
  if (fd < 0) {
    return -1;
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, M80_TUN_NAME, sizeof(ifr.ifr_name) - 1);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
    close(fd);
    return -1;
  }
  flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }

  if (configure_tun_ipv4(M80_TUN_NAME) != 0) {
    close(fd);
    return -1;
  }
  if (add_ipv4_default_route(M80_TUN_NAME) != 0) {
    write_line("m80 initramfs: tun ipv4 default route failed");
  }
  if (add_ipv6_address(M80_TUN_NAME) != 0) {
    write_line("m80 initramfs: tun ipv6 address failed");
  } else if (add_ipv6_default_route(M80_TUN_NAME) != 0) {
    write_line("m80 initramfs: tun ipv6 default route failed");
  }
  return fd;
}

static void ipv4_text(const unsigned char *addr, char *out, size_t out_size) {
  snprintf(out, out_size, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static void ipv6_text(const unsigned char *addr, char *out, size_t out_size) {
  snprintf(out, out_size,
           "%x:%x:%x:%x:%x:%x:%x:%x",
           ((unsigned int)addr[0] << 8) | addr[1],
           ((unsigned int)addr[2] << 8) | addr[3],
           ((unsigned int)addr[4] << 8) | addr[5],
           ((unsigned int)addr[6] << 8) | addr[7],
           ((unsigned int)addr[8] << 8) | addr[9],
           ((unsigned int)addr[10] << 8) | addr[11],
           ((unsigned int)addr[12] << 8) | addr[13],
           ((unsigned int)addr[14] << 8) | addr[15]);
}

static void write_ipv4_echo_reply(int tun_fd,
                                  const unsigned char *request,
                                  size_t request_len,
                                  size_t ihl,
                                  size_t icmp_len) {
  unsigned char reply[M80_TUN_MTU];
  unsigned short total_len = (unsigned short)(20U + icmp_len);
  unsigned short csum;
  if (total_len > sizeof(reply) || request_len < ihl + icmp_len) {
    return;
  }
  memset(reply, 0, total_len);
  reply[0] = 0x45;
  reply[1] = request[1];
  reply[2] = (unsigned char)(total_len >> 8);
  reply[3] = (unsigned char)(total_len & 0xffU);
  reply[4] = request[4];
  reply[5] = request[5];
  reply[8] = 64;
  reply[9] = IPPROTO_ICMP;
  memcpy(reply + 12, request + 16, 4);
  memcpy(reply + 16, request + 12, 4);
  csum = internet_checksum(reply, 20);
  reply[10] = (unsigned char)(csum >> 8);
  reply[11] = (unsigned char)(csum & 0xffU);

  memcpy(reply + 20, request + ihl, icmp_len);
  reply[20] = 0;
  reply[21] = 0;
  reply[22] = 0;
  reply[23] = 0;
  csum = internet_checksum(reply + 20, icmp_len);
  reply[22] = (unsigned char)(csum >> 8);
  reply[23] = (unsigned char)(csum & 0xffU);
  write_full(tun_fd, reply, total_len);
}

static void write_ipv4_icmp_unreachable(int tun_fd,
                                        const unsigned char *request,
                                        size_t request_len,
                                        size_t ihl,
                                        size_t total_len,
                                        unsigned char code) {
  unsigned char reply[M80_TUN_MTU];
  size_t quote_len;
  size_t icmp_len;
  size_t reply_len;
  unsigned short csum;
  if (request_len < ihl + 8U || total_len < ihl + 8U) {
    return;
  }
  quote_len = ihl + 8U;
  if (quote_len > total_len) {
    quote_len = total_len;
  }
  if (quote_len > request_len) {
    quote_len = request_len;
  }
  if (20U + 8U + quote_len > sizeof(reply)) {
    quote_len = sizeof(reply) - 20U - 8U;
  }
  icmp_len = 8U + quote_len;
  reply_len = 20U + icmp_len;

  memset(reply, 0, reply_len);
  reply[0] = 0x45;
  reply[1] = request[1];
  reply[2] = (unsigned char)(reply_len >> 8);
  reply[3] = (unsigned char)(reply_len & 0xffU);
  reply[4] = request[4];
  reply[5] = request[5];
  reply[8] = 64;
  reply[9] = IPPROTO_ICMP;
  memcpy(reply + 12, request + 16, 4);
  memcpy(reply + 16, request + 12, 4);
  csum = internet_checksum(reply, 20);
  reply[10] = (unsigned char)(csum >> 8);
  reply[11] = (unsigned char)(csum & 0xffU);

  reply[20] = 3;
  reply[21] = code;
  memcpy(reply + 28, request, quote_len);
  csum = internet_checksum(reply + 20, icmp_len);
  reply[22] = (unsigned char)(csum >> 8);
  reply[23] = (unsigned char)(csum & 0xffU);
  write_full(tun_fd, reply, reply_len);
}

static void write_ipv6_echo_reply(int tun_fd,
                                  const unsigned char *request,
                                  size_t request_len,
                                  size_t icmp_len) {
  unsigned char reply[M80_TUN_MTU];
  unsigned short csum;
  if (40U + icmp_len > sizeof(reply) || request_len < 40U + icmp_len) {
    return;
  }
  memset(reply, 0, 40U + icmp_len);
  reply[0] = 0x60;
  reply[4] = (unsigned char)(icmp_len >> 8);
  reply[5] = (unsigned char)(icmp_len & 0xffU);
  reply[6] = IPPROTO_ICMPV6;
  reply[7] = 64;
  memcpy(reply + 8, request + 24, 16);
  memcpy(reply + 24, request + 8, 16);
  memcpy(reply + 40, request + 40, icmp_len);
  reply[40] = 129;
  reply[41] = 0;
  reply[42] = 0;
  reply[43] = 0;
  csum = icmpv6_checksum(reply + 8, reply + 24, reply + 40, icmp_len);
  reply[42] = (unsigned char)(csum >> 8);
  reply[43] = (unsigned char)(csum & 0xffU);
  write_full(tun_fd, reply, 40U + icmp_len);
}

static void write_ipv6_icmp_unreachable(int tun_fd,
                                        const unsigned char *request,
                                        size_t request_len,
                                        unsigned char code) {
  unsigned char reply[M80_TUN_MTU];
  size_t quote_len;
  size_t icmp_len;
  size_t reply_len;
  unsigned short csum;
  if (request_len < 48U) {
    return;
  }
  quote_len = request_len;
  if (40U + 8U + quote_len > sizeof(reply)) {
    quote_len = sizeof(reply) - 40U - 8U;
  }
  icmp_len = 8U + quote_len;
  reply_len = 40U + icmp_len;

  memset(reply, 0, reply_len);
  reply[0] = 0x60;
  reply[4] = (unsigned char)(icmp_len >> 8);
  reply[5] = (unsigned char)(icmp_len & 0xffU);
  reply[6] = IPPROTO_ICMPV6;
  reply[7] = 64;
  memcpy(reply + 8, request + 24, 16);
  memcpy(reply + 24, request + 8, 16);

  reply[40] = 1;
  reply[41] = code;
  memcpy(reply + 48, request, quote_len);
  csum = icmpv6_checksum(reply + 8, reply + 24, reply + 40, icmp_len);
  reply[42] = (unsigned char)(csum >> 8);
  reply[43] = (unsigned char)(csum & 0xffU);
  write_full(tun_fd, reply, reply_len);
}

static void handle_tun_ipv4_packet(struct guest_agent_state *state,
                                   int tun_fd,
                                   const unsigned char *packet,
                                   size_t packet_len) {
  size_t ihl;
  size_t total_len;
  size_t icmp_len;
  unsigned short frag;
  char dst[64];
  int echo_rc;
  if (packet_len < 28U || (packet[0] >> 4) != 4) {
    return;
  }
  ihl = (size_t)(packet[0] & 0x0fU) * 4U;
  if (ihl < 20U || packet_len < ihl + 8U) {
    return;
  }
  total_len = ((size_t)packet[2] << 8) | packet[3];
  if (total_len < ihl + 8U || total_len > packet_len) {
    return;
  }
  frag = (unsigned short)(((unsigned short)packet[6] << 8) | packet[7]);
  if ((frag & 0x3fffU) != 0 || packet[9] != IPPROTO_ICMP) {
    return;
  }
  if (packet[ihl] != 8 || packet[ihl + 1U] != 0) {
    return;
  }
  icmp_len = total_len - ihl;
  ipv4_text(packet + 16, dst, sizeof(dst));
  echo_rc = rpc_icmp_echo(state, dst, packet + ihl + 8U, icmp_len - 8U);
  if (echo_rc == M80_ICMP_ECHO_BLOCKED) {
    write_ipv4_icmp_unreachable(tun_fd, packet, packet_len, ihl, total_len, 13);
    return;
  }
  if (echo_rc != M80_ICMP_ECHO_OK) {
    return;
  }
  write_ipv4_echo_reply(tun_fd, packet, total_len, ihl, icmp_len);
}

static void handle_tun_ipv6_packet(struct guest_agent_state *state,
                                   int tun_fd,
                                   const unsigned char *packet,
                                   size_t packet_len) {
  size_t payload_len;
  size_t icmp_len;
  char dst[80];
  int echo_rc;
  if (packet_len < 48U || (packet[0] >> 4) != 6) {
    return;
  }
  payload_len = ((size_t)packet[4] << 8) | packet[5];
  if (packet[6] != IPPROTO_ICMPV6 || payload_len < 8U || 40U + payload_len > packet_len) {
    return;
  }
  if (packet[40] != 128 || packet[41] != 0) {
    return;
  }
  icmp_len = payload_len;
  ipv6_text(packet + 24, dst, sizeof(dst));
  echo_rc = rpc_icmp_echo(state, dst, packet + 48, icmp_len - 8U);
  if (echo_rc == M80_ICMP_ECHO_BLOCKED) {
    write_ipv6_icmp_unreachable(tun_fd, packet, packet_len, 1);
    return;
  }
  if (echo_rc != M80_ICMP_ECHO_OK) {
    return;
  }
  write_ipv6_echo_reply(tun_fd, packet, packet_len, icmp_len);
}

static void handle_tun_packet(struct guest_agent_state *state, int tun_fd) {
  unsigned char packet[M80_TUN_MTU];
  ssize_t n;
  int processed = 0;
  while (processed < 32) {
    n = read(tun_fd, packet, sizeof(packet));
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      return;
    }
    if (n <= 0) {
      return;
    }
    processed++;
    if (((packet[0] >> 4) & 0x0fU) == 4) {
      handle_tun_ipv4_packet(state, tun_fd, packet, (size_t)n);
    } else if (((packet[0] >> 4) & 0x0fU) == 6) {
      handle_tun_ipv6_packet(state, tun_fd, packet, (size_t)n);
    }
  }
}

static int bring_up_loopback(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq ifr;
  if (fd < 0) {
    return -1;
  }
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
    close(fd);
    return -1;
  }
  ifr.ifr_flags |= (short)(IFF_UP | IFF_RUNNING);
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int create_udp_listener(unsigned short port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int one = 1;
  struct sockaddr_in addr;
  if (fd < 0) {
    return -1;
  }
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static unsigned short get_socket_port(int fd) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
    return 0;
  }
  return ntohs(addr.sin_port);
}

static int create_tcp_listener(unsigned short port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  struct sockaddr_in addr;
  if (fd < 0) {
    return -1;
  }
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  if (listen(fd, 8) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static const char *http_status_text(int status) {
  switch (status) {
    case 200:
      return "OK";
    case 400:
      return "Bad Request";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 502:
    default:
      return "Bad Gateway";
  }
}

static void send_http_response(int fd, int status, const char *content_type, const char *body) {
  char header[512];
  size_t body_len = strlen(body);
  int n = snprintf(header, sizeof(header),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %zu\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   status, http_status_text(status), content_type, body_len);
  if (n > 0) {
    write_full(fd, header, (size_t)n);
    write_full(fd, body, body_len);
  }
}

static void handle_dns_request(struct guest_agent_state *state, int udp_fd) {
  unsigned char query[4096];
  unsigned char response[4096];
  size_t response_len = 0;
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  ssize_t n = recvfrom(udp_fd, query, sizeof(query), 0,
                       (struct sockaddr *)&client_addr, &client_len);
  if (n <= 0) {
    return;
  }
  if (rpc_dns_query(state, query, (size_t)n, response, sizeof(response), &response_len) != 0) {
    return;
  }
  sendto(udp_fd, response, response_len, 0,
         (struct sockaddr *)&client_addr, client_len);
}

static void handle_http_request(struct guest_agent_state *state, int listen_fd) {
  int fd = accept(listen_fd, NULL, NULL);
  char request[4096];
  char method[16];
  char path[256];
  char *content_type = NULL;
  char *body = NULL;
  int status = 0;
  ssize_t n;
  if (fd < 0) {
    return;
  }

  n = read(fd, request, sizeof(request) - 1);
  if (n <= 0) {
    close(fd);
    return;
  }
  request[n] = '\0';
  if (sscanf(request, "%15s %255s", method, path) != 2) {
    send_http_response(fd, 400, "application/json", "{}");
    close(fd);
    return;
  }
  if (strcmp(method, "GET") != 0) {
    send_http_response(fd, 405, "application/json", "{}");
    close(fd);
    return;
  }

  if (rpc_metadata_get(state, path, &status, &content_type, &body) != 0) {
    send_http_response(fd, 502, "application/json", "{}");
    close(fd);
    return;
  }
  send_http_response(fd, status, content_type, body);
  free(content_type);
  free(body);
  close(fd);
}

static void set_socket_timeout(int fd, int seconds) {
  struct timeval timeout;
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static void send_socks_reply_bound(int fd, unsigned char rep, unsigned short port) {
  unsigned char response[10] = {
      0x05, rep, 0x00, 0x01,
      0x7f, 0x00, 0x00, 0x01,
      (unsigned char)((port >> 8) & 0xffU), (unsigned char)(port & 0xffU),
  };
  write_full(fd, response, sizeof(response));
}

static void send_socks_reply(int fd, unsigned char rep) {
  send_socks_reply_bound(fd, rep, 0);
}

static int read_socks_host(int fd, unsigned char atyp, char *host, size_t host_cap) {
  unsigned char addr4[4];
  unsigned char addr6[16];
  unsigned char len_byte;
  if (atyp == 0x01) {
    if (read_full(fd, addr4, sizeof(addr4)) != 0) {
      return -1;
    }
    if (inet_ntop(AF_INET, addr4, host, (socklen_t)host_cap) == NULL) {
      return -1;
    }
    return 0;
  }
  if (atyp == 0x03) {
    if (read_full(fd, &len_byte, 1) != 0) {
      return -1;
    }
    if (len_byte == 0 || (size_t)len_byte + 1U > host_cap) {
      return -1;
    }
    if (read_full(fd, host, len_byte) != 0) {
      return -1;
    }
    host[len_byte] = '\0';
    return is_safe_socks_host(host) ? 0 : -1;
  }
  if (atyp == 0x04) {
    if (read_full(fd, addr6, sizeof(addr6)) != 0) {
      return -1;
    }
    if (inet_ntop(AF_INET6, addr6, host, (socklen_t)host_cap) == NULL) {
      return -1;
    }
    return 0;
  }
  return -1;
}

static int negotiate_socks_request(int fd,
                                   unsigned char *cmd_out,
                                   char *host,
                                   size_t host_cap,
                                   unsigned short *port_out) {
  unsigned char header[2];
  unsigned char methods[255];
  unsigned char request[4];
  unsigned char port_bytes[2];
  int has_no_auth = 0;
  int i;

  if (read_full(fd, header, sizeof(header)) != 0 || header[0] != 0x05 || header[1] == 0) {
    return -1;
  }
  if (read_full(fd, methods, header[1]) != 0) {
    return -1;
  }
  for (i = 0; i < header[1]; i++) {
    if (methods[i] == 0x00) {
      has_no_auth = 1;
      break;
    }
  }
  if (!has_no_auth) {
    unsigned char no_methods[2] = {0x05, 0xff};
    write_full(fd, no_methods, sizeof(no_methods));
    return -1;
  }
  {
    unsigned char ok[2] = {0x05, 0x00};
    if (write_full(fd, ok, sizeof(ok)) != 0) {
      return -1;
    }
  }

  if (read_full(fd, request, sizeof(request)) != 0 || request[0] != 0x05 || request[2] != 0x00) {
    return -1;
  }
  if (request[1] != 0x01 && request[1] != 0x03) {
    send_socks_reply(fd, 0x07);
    return -1;
  }
  if (read_socks_host(fd, request[3], host, host_cap) != 0) {
    send_socks_reply(fd, 0x08);
    return -1;
  }
  if (read_full(fd, port_bytes, sizeof(port_bytes)) != 0) {
    return -1;
  }
  *port_out = (unsigned short)(((unsigned short)port_bytes[0] << 8) | port_bytes[1]);
  *cmd_out = request[1];
  if (request[1] == 0x01 && *port_out == 0) {
    return -1;
  }
  return 0;
}

static void relay_socks_tcp(struct guest_agent_state *state,
                            int client_fd,
                            long stream_id) {
  unsigned char client_buf[M80_TCP_RELAY_CHUNK];
  unsigned char remote_buf[4096];
  long long last_activity_ms = monotonic_ms();
  for (;;) {
    struct pollfd pfd;
    int poll_rc;
    size_t remote_len = 0;
    int eof = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = client_fd;
    pfd.events = POLLIN;
    poll_rc = poll(&pfd, 1, 25);
    if (poll_rc < 0 && errno == EINTR) {
      continue;
    }
    if (poll_rc < 0) {
      break;
    }
    if (poll_rc > 0) {
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        break;
      }
      if (pfd.revents & POLLIN) {
        ssize_t n = read(client_fd, client_buf, sizeof(client_buf));
        if (n <= 0) {
          break;
        }
        last_activity_ms = monotonic_ms();
        if (rpc_tcp_write(state, stream_id, client_buf, (size_t)n) != 0) {
          break;
        }
      }
    }

    if (rpc_tcp_read(state, stream_id, remote_buf, sizeof(remote_buf), &remote_len, &eof) != 0) {
      break;
    }
    if (remote_len > 0) {
      last_activity_ms = monotonic_ms();
      if (write_full(client_fd, remote_buf, remote_len) != 0) {
        break;
      }
    }
    if (eof) {
      break;
    }
    if (monotonic_ms() - last_activity_ms > M80_TCP_RELAY_IDLE_TIMEOUT_MS) {
      break;
    }
  }
}

static int parse_socks_udp_header(const unsigned char *packet,
                                  size_t packet_len,
                                  char *host,
                                  size_t host_cap,
                                  unsigned short *port_out,
                                  size_t *payload_offset_out) {
  size_t pos = 0;
  unsigned char atyp;
  if (packet_len < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) {
    return -1;
  }
  pos = 3;
  atyp = packet[pos++];
  if (atyp == 0x01) {
    if (pos + 4U + 2U > packet_len) {
      return -1;
    }
    if (inet_ntop(AF_INET, packet + pos, host, (socklen_t)host_cap) == NULL) {
      return -1;
    }
    pos += 4U;
  } else if (atyp == 0x03) {
    unsigned char len;
    if (pos >= packet_len) {
      return -1;
    }
    len = packet[pos++];
    if (len == 0 || (size_t)len + 1U > host_cap || pos + (size_t)len + 2U > packet_len) {
      return -1;
    }
    memcpy(host, packet + pos, len);
    host[len] = '\0';
    if (!is_safe_socks_host(host)) {
      return -1;
    }
    pos += len;
  } else if (atyp == 0x04) {
    if (pos + 16U + 2U > packet_len) {
      return -1;
    }
    if (inet_ntop(AF_INET6, packet + pos, host, (socklen_t)host_cap) == NULL) {
      return -1;
    }
    pos += 16U;
  } else {
    return -1;
  }
  *port_out = (unsigned short)(((unsigned short)packet[pos] << 8) | packet[pos + 1]);
  pos += 2U;
  if (*port_out == 0 || pos >= packet_len) {
    return -1;
  }
  *payload_offset_out = pos;
  return 0;
}

static void handle_socks_udp_packet(struct guest_agent_state *state, int udp_fd) {
  unsigned char packet[M80_UDP_RELAY_CHUNK + 300U];
  unsigned char response[M80_UDP_RELAY_CHUNK];
  unsigned char out[M80_UDP_RELAY_CHUNK + 300U];
  struct sockaddr_storage client_addr;
  socklen_t client_len = sizeof(client_addr);
  char host[256];
  unsigned short port = 0;
  size_t payload_offset = 0;
  size_t response_len = 0;
  ssize_t n;

  n = recvfrom(udp_fd, packet, sizeof(packet), 0,
               (struct sockaddr *)&client_addr, &client_len);
  if (n <= 0) {
    return;
  }
  if (parse_socks_udp_header(packet, (size_t)n, host, sizeof(host), &port, &payload_offset) != 0) {
    return;
  }
  if ((size_t)n - payload_offset > M80_UDP_RELAY_CHUNK) {
    return;
  }
  if (rpc_udp_exchange(state,
                       host,
                       port,
                       packet + payload_offset,
                       (size_t)n - payload_offset,
                       response,
                       sizeof(response),
                       &response_len) != 0) {
    return;
  }
  if (payload_offset + response_len > sizeof(out)) {
    return;
  }
  memcpy(out, packet, payload_offset);
  memcpy(out + payload_offset, response, response_len);
  sendto(udp_fd, out, payload_offset + response_len, 0,
         (struct sockaddr *)&client_addr, client_len);
}

static int acquire_vsock_session_lock(void) {
  int fd = open("/m80-socks-session.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    return -1;
  }
  if (flock(fd, LOCK_EX) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static void release_vsock_session_lock(int fd) {
  if (fd >= 0) {
    flock(fd, LOCK_UN);
    close(fd);
  }
}

static void handle_socks_udp_associate(struct guest_agent_state *state, int control_fd) {
  int udp_fd = create_udp_listener(0);
  unsigned short udp_port;
  if (udp_fd < 0) {
    send_socks_reply(control_fd, 0x01);
    return;
  }
  udp_port = get_socket_port(udp_fd);
  if (udp_port == 0) {
    close(udp_fd);
    send_socks_reply(control_fd, 0x01);
    return;
  }
  send_socks_reply_bound(control_fd, 0x00, udp_port);

  for (;;) {
    struct pollfd fds[2];
    int rc;
    memset(fds, 0, sizeof(fds));
    fds[0].fd = control_fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp_fd;
    fds[1].events = POLLIN;
    rc = poll(fds, 2, 1000);
    if (rc < 0 && errno == EINTR) {
      continue;
    }
    if (rc < 0) {
      break;
    }
    maybe_send_agent_heartbeat(state);
    if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      break;
    }
    if (fds[0].revents & POLLIN) {
      unsigned char byte;
      ssize_t n = recv(control_fd, &byte, 1, MSG_PEEK);
      if (n <= 0) {
        break;
      }
      break;
    }
    if (fds[1].revents & POLLIN) {
      handle_socks_udp_packet(state, udp_fd);
    }
  }

  close(udp_fd);
}

static void handle_socks_client(const struct guest_service_config *config, int client_fd) {
  struct guest_agent_state state;
  unsigned char cmd = 0;
  char host[256];
  unsigned short port = 0;
  long stream_id = 0;

  memset(&state, 0, sizeof(state));
  state.vsock_fd = -1;
  state.vsock_lock_fd = -1;
  state.hold_vsock_lock = 0;
  state.persistent_vsock = 1;
  state.next_id = 1;
  state.next_heartbeat_ms = monotonic_ms() + 10000LL;
  state.config = *config;

  set_socket_timeout(client_fd, 30);
  if (negotiate_socks_request(client_fd, &cmd, host, sizeof(host), &port) != 0) {
    close(client_fd);
    return;
  }
  if (cmd == 0x03) {
    handle_socks_udp_associate(&state, client_fd);
    close_agent_vsock(&state);
    close(client_fd);
    return;
  }
  if (rpc_tcp_open(&state, host, port, &stream_id) != 0) {
    send_socks_reply(client_fd, 0x05);
    close_agent_vsock(&state);
    close(client_fd);
    return;
  }
  send_socks_reply(client_fd, 0x00);
  relay_socks_tcp(&state, client_fd, stream_id);
  rpc_tcp_close(&state, stream_id);
  close_agent_vsock(&state);
  close(client_fd);
}

static void accept_socks_client(struct guest_agent_state *main_state, int listen_fd) {
  int fd = accept(listen_fd, NULL, NULL);
  pid_t pid;
  if (fd < 0) {
    return;
  }
  pid = fork();
  if (pid < 0) {
    close(fd);
    return;
  }
  if (pid == 0) {
    signal(SIGPIPE, SIG_IGN);
    if (main_state->vsock_fd >= 0) {
      close(main_state->vsock_fd);
    }
    close(listen_fd);
    handle_socks_client(&main_state->config, fd);
    _exit(0);
  }
  close(fd);
}

static void guest_agent_loop(const struct guest_service_config *config) {
  struct guest_agent_state state;
  struct pollfd fds[4];
  nfds_t count = 0;
  int dns_fd = -1;
  int http_fd = -1;
  int socks_fd = -1;
  int tun_fd = -1;
  int dns_index = -1;
  int http_index = -1;
  int socks_index = -1;
  int tun_index = -1;

  memset(&state, 0, sizeof(state));
  state.vsock_fd = -1;
  state.vsock_lock_fd = -1;
  state.hold_vsock_lock = 0;
  state.persistent_vsock = 1;
  state.next_id = 1;
  state.next_heartbeat_ms = monotonic_ms() + 10000LL;
  state.config = *config;

  if (bring_up_loopback() != 0) {
    write_line("m80 initramfs: loopback bring-up failed");
  }

  if (config->enable_dns) {
    dns_fd = create_udp_listener(53);
    if (dns_fd < 0) {
      write_line("m80 initramfs: dns listener bind failed");
    }
  }
  if (config->enable_metadata) {
    http_fd = create_tcp_listener(80);
    if (http_fd < 0) {
      write_line("m80 initramfs: metadata listener bind failed");
    }
  }
  if (config->enable_outbound) {
    tun_fd = setup_tun_interface();
    if (tun_fd < 0) {
      write_line("m80 initramfs: tun setup failed");
    }
    socks_fd = create_tcp_listener((unsigned short)M80_SOCKS_PORT);
    if (socks_fd < 0) {
      write_line("m80 initramfs: socks listener bind failed");
    }
  }
  if (dns_fd < 0 && http_fd < 0 && socks_fd < 0 && tun_fd < 0) {
    return;
  }

  if (dns_fd >= 0) {
    dns_index = (int)count;
    fds[count].fd = dns_fd;
    fds[count].events = POLLIN;
    fds[count].revents = 0;
    count++;
  }
  if (http_fd >= 0) {
    http_index = (int)count;
    fds[count].fd = http_fd;
    fds[count].events = POLLIN;
    fds[count].revents = 0;
    count++;
  }
  if (socks_fd >= 0) {
    socks_index = (int)count;
    fds[count].fd = socks_fd;
    fds[count].events = POLLIN;
    fds[count].revents = 0;
    count++;
  }
  if (tun_fd >= 0) {
    tun_index = (int)count;
    fds[count].fd = tun_fd;
    fds[count].events = POLLIN;
    fds[count].revents = 0;
    count++;
  }

  for (;;) {
    int rc = poll(fds, count, 1000);
    if (rc < 0 && errno == EINTR) {
      continue;
    }
    if (rc < 0) {
      break;
    }
    maybe_send_agent_heartbeat(&state);
    if (dns_index >= 0 && fds[dns_index].revents & POLLIN) {
      handle_dns_request(&state, dns_fd);
    }
    if (http_index >= 0 && fds[http_index].revents & POLLIN) {
      handle_http_request(&state, http_fd);
    }
    if (socks_index >= 0 && fds[socks_index].revents & POLLIN) {
      accept_socks_client(&state, socks_fd);
    }
    if (tun_index >= 0 && fds[tun_index].revents & POLLIN) {
      handle_tun_packet(&state, tun_fd);
    }
  }

  close_agent_vsock(&state);
  if (dns_fd >= 0) close(dns_fd);
  if (http_fd >= 0) close(http_fd);
  if (socks_fd >= 0) close(socks_fd);
  if (tun_fd >= 0) close(tun_fd);
}

static void install_guest_service_files(const char *cmdline) {
  struct guest_service_config config;
  if (!parse_guest_service_config(cmdline, &config)) {
    return;
  }
  if (config.enable_dns) {
    mkdir("/new_root/etc", 0755);
    write_file("/new_root/etc/resolv.conf", "nameserver 127.0.0.1\noptions ndots:1\n");
  }
  if (config.enable_outbound) {
    mkdir_p("/new_root/etc/profile.d");
    write_file("/new_root/etc/profile.d/m80-network.sh",
               "export ALL_PROXY=socks5h://127.0.0.1:1080\n"
               "export all_proxy=socks5h://127.0.0.1:1080\n"
               "export HTTP_PROXY=socks5h://127.0.0.1:1080\n"
               "export http_proxy=socks5h://127.0.0.1:1080\n"
               "export HTTPS_PROXY=socks5h://127.0.0.1:1080\n"
               "export https_proxy=socks5h://127.0.0.1:1080\n"
               "export NO_PROXY=127.0.0.1,localhost,.m80.internal\n"
               "export no_proxy=127.0.0.1,localhost,.m80.internal\n");
  }
}

static void start_guest_service_agent(const char *cmdline) {
  struct guest_service_config config;
  pid_t pid;
  if (!parse_guest_service_config(cmdline, &config)) {
    return;
  }
  pid = fork();
  if (pid < 0) {
    write_line("m80 initramfs: guest agent fork failed");
    return;
  }
  if (pid == 0) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    guest_agent_loop(&config);
    _exit(0);
  }
  write_line("m80 initramfs: guest services started");
}

static size_t build_dns_query_packet(const char *name,
                                     unsigned char *buf,
                                     size_t buf_size,
                                     unsigned short id) {
  const char *label = name;
  size_t pos = 0;
  const char *next;
  if (buf_size < 18) {
    return 0;
  }
  memset(buf, 0, buf_size);
  buf[0] = (unsigned char)((id >> 8) & 0xffU);
  buf[1] = (unsigned char)(id & 0xffU);
  buf[2] = 0x01;
  buf[5] = 0x01;
  pos = 12;
  while (*label) {
    size_t len;
    next = strchr(label, '.');
    len = next ? (size_t)(next - label) : strlen(label);
    if (len == 0 || len > 63 || pos + 1 + len + 5 >= buf_size) {
      return 0;
    }
    buf[pos++] = (unsigned char)len;
    memcpy(buf + pos, label, len);
    pos += len;
    if (next == NULL) {
      break;
    }
    label = next + 1;
  }
  buf[pos++] = 0;
  buf[pos++] = 0;
  buf[pos++] = 1;
  buf[pos++] = 0;
  buf[pos++] = 1;
  return pos;
}

static int parse_dns_a_response(const unsigned char *buf,
                                size_t len,
                                char *ip_out,
                                size_t ip_out_size,
                                int *nxdomain_out) {
  unsigned short qdcount;
  unsigned short ancount;
  size_t pos = 12;
  size_t i;
  if (len < 12) {
    return -1;
  }
  *nxdomain_out = ((buf[3] & 0x0fU) == 3U);
  qdcount = (unsigned short)((buf[4] << 8) | buf[5]);
  ancount = (unsigned short)((buf[6] << 8) | buf[7]);
  for (i = 0; i < qdcount; i++) {
    while (pos < len && buf[pos] != 0) {
      if ((buf[pos] & 0xc0U) == 0xc0U) {
        pos += 2;
        break;
      }
      pos += (size_t)buf[pos] + 1U;
    }
    if (pos >= len) {
      return -1;
    }
    if (buf[pos] == 0) {
      pos++;
    }
    if (pos + 4 > len) {
      return -1;
    }
    pos += 4;
  }
  for (i = 0; i < ancount; i++) {
    unsigned short type;
    unsigned short rdlen;
    if (pos + 12 > len) {
      return -1;
    }
    if ((buf[pos] & 0xc0U) == 0xc0U) {
      pos += 2;
    } else {
      while (pos < len && buf[pos] != 0) {
        pos += (size_t)buf[pos] + 1U;
      }
      pos++;
    }
    if (pos + 10 > len) {
      return -1;
    }
    type = (unsigned short)((buf[pos] << 8) | buf[pos + 1]);
    rdlen = (unsigned short)((buf[pos + 8] << 8) | buf[pos + 9]);
    pos += 10;
    if (pos + rdlen > len) {
      return -1;
    }
    if (type == 1 && rdlen == 4) {
      snprintf(ip_out, ip_out_size, "%u.%u.%u.%u",
               buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
      return 0;
    }
    pos += rdlen;
  }
  return -1;
}

static void shell_resolve_name(const char *name) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in addr;
  struct timeval timeout;
  unsigned char query[512];
  unsigned char response[512];
  char ip_text[64];
  int nxdomain = 0;
  size_t query_len;
  ssize_t n;
  if (fd < 0) {
    shell_write_line("m80 shell: resolve socket failed");
    return;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  timeout.tv_sec = 2;
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  query_len = build_dns_query_packet(name, query, sizeof(query), 0x1234);
  if (query_len == 0 ||
      sendto(fd, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    shell_write_line("m80 shell: resolve send failed");
    return;
  }
  n = recvfrom(fd, response, sizeof(response), 0, NULL, NULL);
  close(fd);
  if (n <= 0) {
    shell_write_line("m80 shell: resolve timeout");
    return;
  }
  if (parse_dns_a_response(response, (size_t)n, ip_text, sizeof(ip_text), &nxdomain) == 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 shell: resolve %s -> %s", name, ip_text);
    shell_write_line(msg);
    return;
  }
  if (nxdomain) {
    char msg[256];
    snprintf(msg, sizeof(msg), "m80 shell: resolve %s -> NXDOMAIN", name);
    shell_write_line(msg);
    return;
  }
  shell_write_line("m80 shell: resolve failed");
}

static void shell_http_get(const char *path) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  struct timeval timeout;
  char request[512];
  char response[8192];
  char *body = NULL;
  int n;
  if (fd < 0) {
    shell_write_line("m80 shell: http socket failed");
    return;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  timeout.tv_sec = 2;
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    shell_write_line("m80 shell: http connect failed");
    return;
  }
  snprintf(request, sizeof(request),
           "GET %s HTTP/1.1\r\nHost: metadata.m80.internal\r\nConnection: close\r\n\r\n",
           path);
  if (write_full(fd, request, strlen(request)) != 0) {
    close(fd);
    shell_write_line("m80 shell: http send failed");
    return;
  }
  n = (int)read(fd, response, sizeof(response) - 1);
  close(fd);
  if (n <= 0) {
    shell_write_line("m80 shell: http read failed");
    return;
  }
  response[n] = '\0';
  body = strstr(response, "\r\n\r\n");
  if (body != NULL) {
    *body = '\0';
    body += 4;
  }
  if (strncmp(response, "HTTP/1.1 200", 12) != 0) {
    shell_write_line("m80 shell: http status not ok");
    return;
  }
  if (body == NULL) {
    shell_write_line("m80 shell: http body missing");
    return;
  }
  shell_write_line(body);
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

static int run_fsck_repair(const char *root_dev) {
  if (access("/sbin/e2fsck", X_OK) != 0) {
    write_line("m80 initramfs: e2fsck not available");
    return -1;
  }

  write_line("m80 initramfs: running e2fsck -fy");
  pid_t pid = fork();
  if (pid < 0) {
    write_line("m80 initramfs: e2fsck repair fork failed");
    return -1;
  }
  if (pid == 0) {
    execl("/sbin/e2fsck", "e2fsck", "-fy", root_dev, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    write_line("m80 initramfs: e2fsck repair wait failed");
    return -1;
  }
  if (!WIFEXITED(status)) {
    write_line("m80 initramfs: e2fsck repair failed");
    return -1;
  }

  int rc = WEXITSTATUS(status);
  if (rc == 0 || rc == 1) {
    write_line("m80 initramfs: e2fsck repair ok");
    return 0;
  }
  if (rc == 2) {
    write_line("m80 initramfs: e2fsck repair requested reboot");
    sync();
    reboot(RB_AUTOBOOT);
    return -1;
  }

  write_line("m80 initramfs: e2fsck repair failed");
  return -1;
}

static void write_file(const char *path, const char *content) {
  int fd;
  if (unlink(path) != 0 && errno != ENOENT) {
    write_line("m80 initramfs: write_file unlink failed");
    return;
  }
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
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
  }
}

static int has_suffix(const char *value, const char *suffix) {
  size_t value_len = strlen(value);
  size_t suffix_len = strlen(suffix);
  return value_len >= suffix_len &&
         strcmp(value + value_len - suffix_len, suffix) == 0;
}

static int file_contains_marker(const char *path, const char *marker) {
  char buf[2049];
  int fd = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = '\0';
  return strstr(buf, marker) != NULL;
}

static void cleanup_m80_systemd_mount_units(void) {
  const char *system_dir = "/new_root/etc/systemd/system";
  const char *wants_dir = "/new_root/etc/systemd/system/local-fs.target.wants";
  const char *marker = "Description=m80 virtiofs share";
  DIR *dir = opendir(system_dir);
  struct dirent *entry;
  if (dir == NULL) {
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    char unit_path[512];
    char symlink_path[512];
    if (entry->d_name[0] == '.' || !has_suffix(entry->d_name, ".mount")) {
      continue;
    }
    snprintf(unit_path, sizeof(unit_path), "%s/%s", system_dir, entry->d_name);
    if (!file_contains_marker(unit_path, marker)) {
      continue;
    }
    snprintf(symlink_path, sizeof(symlink_path), "%s/%s", wants_dir, entry->d_name);
    unlink(symlink_path);
    unlink(unit_path);
    write_line("m80 initramfs: removed persistent m80 systemd mount unit");
  }
  closedir(dir);
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
    if (cmdline_has_token(cmdline, "m80.fsck_repair=1")) {
      if (run_fsck_repair(root_dev) != 0) {
        write_line("m80 initramfs: fsck repair failed; refusing dirty root mount");
        return -1;
      }
    } else {
      write_line("m80 initramfs: fsck failed; refusing dirty root mount");
      write_line("m80 initramfs: use the recovery shell fsck-root command to repair");
      return -1;
    }
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

  // Initramfs owns virtiofs mounting; remove older persistent units that can go stale.
  cleanup_m80_systemd_mount_units();
  install_guest_service_files(cmdline);

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
      shell_write_line("m80 shell: help uptime resolve http-get echo fsck-root reboot poweroff halt");
      continue;
    }
    if (strcmp(cmd, "fsck-root") == 0) {
      char cmdline[1024];
      char root_dev[256] = "/dev/vda";
      if (read_cmdline(cmdline, sizeof(cmdline)) == 0) {
        find_param_value(cmdline, "root", root_dev, sizeof(root_dev));
      }
      if (run_fsck_repair(root_dev) == 0) {
        shell_write_line("m80 shell: fsck-root repaired root; reboot before mounting");
      } else {
        shell_write_line("m80 shell: fsck-root failed");
      }
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
    if (strncmp(cmd, "resolve ", 8) == 0) {
      shell_resolve_name(cmd + 8);
      continue;
    }
    if (strncmp(cmd, "http-get ", 9) == 0) {
      shell_http_get(cmd + 9);
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
  struct guest_service_config service_config;

  signal(SIGPIPE, SIG_IGN);
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
  memset(&service_config, 0, sizeof(service_config));
  if (have_cmdline) {
    parse_guest_service_config(cmdline, &service_config);
  }
  if (!have_cmdline || !cmdline_has_root(cmdline)) {
    if (service_config.enable_dns || service_config.enable_metadata || service_config.enable_outbound) {
      load_required_modules();
      start_guest_service_agent(cmdline);
    } else {
      start_console_modules();
      write_line("m80 initramfs: console modules started");
    }
    write_line("m80 initramfs: rootless shell mode");
    shell_loop();
  }

  load_required_modules();
  start_guest_service_agent(cmdline);

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

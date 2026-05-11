#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IO(nr) _IO(SECCOMP_IOC_MAGIC, (nr))
#define SECCOMP_IOR(nr, type) _IOR(SECCOMP_IOC_MAGIC, (nr), type)
#define SECCOMP_IOW(nr, type) _IOW(SECCOMP_IOC_MAGIC, (nr), type)
#define SECCOMP_IOWR(nr, type) _IOWR(SECCOMP_IOC_MAGIC, (nr), type)
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOR(2, uint64_t)
#define SECCOMP_IOCTL_NOTIF_ADDFD SECCOMP_IOW(3, struct seccomp_notif_addfd)
#endif

enum failure_mode {
  FAILURE_NONE = 0,
  FAILURE_STARTUP_UNAVAILABLE = 1,
  FAILURE_MID_SESSION_CRASH = 2,
  FAILURE_SLOW_NOTIFIER = 3,
};

enum policy_mode {
  POLICY_ALLOW_ALL = 0,
  POLICY_DENY_OPENAT = 1,
};

struct config {
  enum failure_mode failure_mode;
  enum policy_mode policy_mode;
  int slow_delay_ms;
  int slow_max_notifs;
  char **command_argv;
};

static int seccomp_syscall(unsigned int operation, unsigned int flags, void *args) {
  return (int)syscall(SYS_seccomp, operation, flags, args);
}

static int send_fd(int sock, int fd) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  char buf[CMSG_SPACE(sizeof(int))];
  memset(buf, 0, sizeof(buf));

  char payload = 'f';
  struct iovec io = {
      .iov_base = &payload,
      .iov_len = sizeof(payload),
  };
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
  msg.msg_controllen = cmsg->cmsg_len;

  if (sendmsg(sock, &msg, 0) < 0) {
    return -1;
  }
  return 0;
}

static int recv_fd(int sock) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  char m_buffer[1];
  struct iovec io = {
      .iov_base = m_buffer,
      .iov_len = sizeof(m_buffer),
  };
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;

  char c_buffer[CMSG_SPACE(sizeof(int))];
  memset(c_buffer, 0, sizeof(c_buffer));
  msg.msg_control = c_buffer;
  msg.msg_controllen = sizeof(c_buffer);

  if (recvmsg(sock, &msg, 0) < 0) {
    return -1;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
    errno = EPROTO;
    return -1;
  }

  int fd = -1;
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
  return fd;
}

static uint32_t expected_audit_arch(void) {
#if defined(__x86_64__)
  return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  return AUDIT_ARCH_AARCH64;
#else
#error Unsupported architecture for seccomp-unotify spike prototype
#endif
}

static int install_notify_filter(void) {
  const uint32_t arch = expected_audit_arch();

  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
#ifdef __NR_openat2
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat2, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
#endif
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  int notify_fd = seccomp_syscall(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  return notify_fd;
}

static int status_to_exit_code(int status) {
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static int run_notifier_loop(int listener_fd, pid_t child_pid, enum failure_mode failure_mode, enum policy_mode policy_mode, int slow_delay_ms, int slow_max_notifs, int *child_status_out) {
  struct seccomp_notif_sizes sizes;
  memset(&sizes, 0, sizeof(sizes));
  if (seccomp_syscall(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
    perror("seccomp(SECCOMP_GET_NOTIF_SIZES)");
    return 40;
  }

  struct seccomp_notif *req = calloc(1, sizes.seccomp_notif);
  struct seccomp_notif_resp *resp = calloc(1, sizes.seccomp_notif_resp);
  if (req == NULL || resp == NULL) {
    perror("calloc");
    free(req);
    free(resp);
    return 41;
  }

  uint64_t notifications_seen = 0;
  int rc = 0;
  int child_done = 0;
  int child_status = 0;

  for (;;) {
    if (!child_done) {
      pid_t waited = waitpid(child_pid, &child_status, WNOHANG);
      if (waited == child_pid) {
        child_done = 1;
      }
    }

    if (child_done) {
      rc = 0;
      break;
    }

    memset(req, 0, sizes.seccomp_notif);
    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 10000000L,
        };
        nanosleep(&ts, NULL);
        continue;
      }
      if (errno == EINTR || errno == ENOENT) {
        continue;
      }
      if (errno == EBADF) {
        rc = 0;
        break;
      }
      perror("ioctl(SECCOMP_IOCTL_NOTIF_RECV)");
      rc = 42;
      break;
    }

    notifications_seen++;
    if (failure_mode == FAILURE_MID_SESSION_CRASH && notifications_seen >= 1) {
      close(listener_fd);
      rc = 64;
      break;
    }

    if (failure_mode == FAILURE_SLOW_NOTIFIER &&
        slow_delay_ms > 0 &&
        (slow_max_notifs <= 0 || (int)notifications_seen <= slow_max_notifs)) {
      struct timespec ts = {
          .tv_sec = slow_delay_ms / 1000,
          .tv_nsec = (long)(slow_delay_ms % 1000) * 1000000L,
      };
      nanosleep(&ts, NULL);
    }

    memset(resp, 0, sizes.seccomp_notif_resp);
    resp->id = req->id;

    int deny_openat = 0;
    if (policy_mode == POLICY_DENY_OPENAT &&
        (req->data.nr == __NR_openat
#ifdef __NR_openat2
         || req->data.nr == __NR_openat2
#endif
        )) {
      deny_openat = 1;
    }

    if (deny_openat) {
      resp->val = 0;
      resp->error = -EPERM;
      resp->flags = 0;
    } else {
      resp->val = 0;
      resp->error = 0;
      resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }

    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
      if (errno == ENOENT || errno == EINTR) {
        continue;
      }
      perror("ioctl(SECCOMP_IOCTL_NOTIF_SEND)");
      rc = 43;
      break;
    }
  }

  free(req);
  free(resp);
  if (child_done && child_status_out != NULL) {
    *child_status_out = child_status;
  }
  return rc;
}

static int run_target(struct config *cfg) {
  int sock_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_pair) < 0) {
    perror("socketpair");
    return 30;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    close(sock_pair[0]);
    close(sock_pair[1]);
    return 31;
  }

  if (pid == 0) {
    close(sock_pair[1]);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      perror("prctl(PR_SET_NO_NEW_PRIVS)");
      _exit(100);
    }

    int notify_fd = install_notify_filter();
    if (notify_fd < 0) {
      perror("seccomp(SECCOMP_SET_MODE_FILTER)");
      _exit(101);
    }

    if (send_fd(sock_pair[0], notify_fd) != 0) {
      perror("send_fd");
      _exit(102);
    }
    close(notify_fd);
    close(sock_pair[0]);

    execvp(cfg->command_argv[0], cfg->command_argv);
    perror("execvp");
    _exit(103);
  }

  close(sock_pair[0]);
  int listener_fd = recv_fd(sock_pair[1]);
  close(sock_pair[1]);
  if (listener_fd < 0) {
    perror("recv_fd");
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return 32;
  }

  int notifier_rc = 0;
  int status = 0;
  if (cfg->failure_mode == FAILURE_STARTUP_UNAVAILABLE) {
    close(listener_fd);
    notifier_rc = 63;
  } else {
    int flags = fcntl(listener_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(listener_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      perror("fcntl(O_NONBLOCK)");
      close(listener_fd);
      kill(pid, SIGTERM);
      waitpid(pid, NULL, 0);
      return 33;
    }

    notifier_rc = run_notifier_loop(listener_fd, pid, cfg->failure_mode, cfg->policy_mode, cfg->slow_delay_ms, cfg->slow_max_notifs, &status);
    close(listener_fd);
  }

  if (waitpid(pid, &status, WNOHANG) == 0) {
    waitpid(pid, &status, 0);
  }
  int child_exit = status_to_exit_code(status);

  if (notifier_rc != 0) {
    return notifier_rc;
  }
  return child_exit;
}

static void usage(FILE *stream) {
  fprintf(stream,
          "Usage: seccomp_unotify_runner [--failure-mode MODE] [--policy MODE] [--slow-delay-ms N] [--slow-max-notifs N] -- <command> [args...]\n"
          "  failure-mode: none | startup-unavailable | mid-session-crash | slow-notifier\n"
          "  policy: allow-all | deny-openat\n");
}

static enum failure_mode parse_failure_mode(const char *value) {
  if (strcmp(value, "none") == 0) {
    return FAILURE_NONE;
  }
  if (strcmp(value, "startup-unavailable") == 0) {
    return FAILURE_STARTUP_UNAVAILABLE;
  }
  if (strcmp(value, "mid-session-crash") == 0) {
    return FAILURE_MID_SESSION_CRASH;
  }
  if (strcmp(value, "slow-notifier") == 0) {
    return FAILURE_SLOW_NOTIFIER;
  }
  return -1;
}

static enum policy_mode parse_policy_mode(const char *value) {
  if (strcmp(value, "allow-all") == 0) {
    return POLICY_ALLOW_ALL;
  }
  if (strcmp(value, "deny-openat") == 0) {
    return POLICY_DENY_OPENAT;
  }
  return -1;
}

int main(int argc, char **argv) {
  struct config cfg = {
      .failure_mode = FAILURE_NONE,
      .policy_mode = POLICY_ALLOW_ALL,
      .slow_delay_ms = 5,
      .slow_max_notifs = 1,
      .command_argv = NULL,
  };

  int i = 1;
  while (i < argc) {
    if (strcmp(argv[i], "--") == 0) {
      i++;
      break;
    }
    if (strcmp(argv[i], "--failure-mode") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      cfg.failure_mode = parse_failure_mode(argv[i + 1]);
      if ((int)cfg.failure_mode < 0) {
        fprintf(stderr, "unsupported failure-mode: %s\n", argv[i + 1]);
        return 2;
      }
      i += 2;
      continue;
    }
    if (strcmp(argv[i], "--policy") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      cfg.policy_mode = parse_policy_mode(argv[i + 1]);
      if ((int)cfg.policy_mode < 0) {
        fprintf(stderr, "unsupported policy mode: %s\n", argv[i + 1]);
        return 2;
      }
      i += 2;
      continue;
    }
    if (strcmp(argv[i], "--slow-delay-ms") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      cfg.slow_delay_ms = atoi(argv[i + 1]);
      if (cfg.slow_delay_ms < 0) {
        fprintf(stderr, "slow-delay-ms must be >= 0\n");
        return 2;
      }
      i += 2;
      continue;
    }
    if (strcmp(argv[i], "--slow-max-notifs") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      cfg.slow_max_notifs = atoi(argv[i + 1]);
      if (cfg.slow_max_notifs < 0) {
        fprintf(stderr, "slow-max-notifs must be >= 0\n");
        return 2;
      }
      i += 2;
      continue;
    }
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout);
      return 0;
    }

    fprintf(stderr, "unknown argument: %s\n", argv[i]);
    usage(stderr);
    return 2;
  }

  if (i >= argc) {
    fprintf(stderr, "missing command after --\n");
    usage(stderr);
    return 2;
  }
  cfg.command_argv = &argv[i];

  return run_target(&cfg);
}

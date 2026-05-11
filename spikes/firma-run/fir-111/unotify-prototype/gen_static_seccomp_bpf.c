#define _GNU_SOURCE

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

enum bpf_mode {
  BPF_MODE_ALLOW_ALL = 0,
  BPF_MODE_DENY_OPENAT = 1,
};

static uint32_t expected_audit_arch(void) {
#if defined(__x86_64__)
  return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  return AUDIT_ARCH_AARCH64;
#else
#error Unsupported architecture for FIR-111 static BPF generator
#endif
}

static int write_all(FILE *fp, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  while (len > 0) {
    size_t n = fwrite(p, 1, len, fp);
    if (n == 0) {
      return -1;
    }
    p += n;
    len -= n;
  }
  return 0;
}

static int emit_program(FILE *fp, enum bpf_mode mode) {
  const uint32_t arch = expected_audit_arch();

  struct sock_filter allow_all_prog[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_filter deny_openat_prog[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t)offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
#ifdef __NR_openat2
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat2, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (uint32_t)EPERM),
#endif
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  const struct sock_filter *prog = NULL;
  size_t prog_len = 0;

  if (mode == BPF_MODE_ALLOW_ALL) {
    prog = allow_all_prog;
    prog_len = sizeof(allow_all_prog);
  } else if (mode == BPF_MODE_DENY_OPENAT) {
    prog = deny_openat_prog;
    prog_len = sizeof(deny_openat_prog);
  } else {
    errno = EINVAL;
    return -1;
  }

  return write_all(fp, prog, prog_len);
}

static void usage(FILE *stream) {
  fprintf(stream,
          "Usage: gen_static_seccomp_bpf --output <path> [--mode allow-all|deny-openat]\n"
          "Writes raw sock_filter program bytes suitable for bwrap --seccomp FD.\n");
}

int main(int argc, char **argv) {
  const char *output_path = NULL;
  enum bpf_mode mode = BPF_MODE_ALLOW_ALL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--output") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      output_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--mode") == 0) {
      if (i + 1 >= argc) {
        usage(stderr);
        return 2;
      }
      const char *value = argv[++i];
      if (strcmp(value, "allow-all") == 0) {
        mode = BPF_MODE_ALLOW_ALL;
      } else if (strcmp(value, "deny-openat") == 0) {
        mode = BPF_MODE_DENY_OPENAT;
      } else {
        fprintf(stderr, "unsupported mode: %s\n", value);
        return 2;
      }
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

  if (output_path == NULL) {
    usage(stderr);
    return 2;
  }

  FILE *fp = fopen(output_path, "wb");
  if (fp == NULL) {
    perror("fopen");
    return 3;
  }

  if (emit_program(fp, mode) != 0) {
    perror("emit_program");
    fclose(fp);
    return 4;
  }

  if (fclose(fp) != 0) {
    perror("fclose");
    return 5;
  }

  return 0;
}

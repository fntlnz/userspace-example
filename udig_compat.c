#include <fcntl.h>
#include <limits.h>
#include <netinet/ip.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "userspace_types.h"

#include "scap.h"

#include "udig_capture.h"
#include "udig_inf.h"

#include "ppm_ringbuffer.h"

static pid_t the_pid;

void set_pid(pid_t pid) { the_pid = pid; }

unsigned long ppm_copy_from_user(void *to, const void *from, unsigned long n) {
  return 0; // TODO(fntlnz): implement copy from user
}

long ppm_strncpy_from_user_impl(pid_t pid, char *to, char *from,
                                unsigned long n) {
  return 0; // TODO(fntlnz): implement copy from user
}

long ppm_strncpy_from_user(char *to, const char *from, unsigned long n) {
  return ppm_strncpy_from_user_impl(the_pid, to, (char *)from, n);
}

size_t strlcpy(char *dst, const char *src, size_t size) {
  const size_t srclen = strlen(src);
  if (srclen + 1 < size) {
    memcpy(dst, src, srclen + 1);
  } else if (size != 0) {
    memcpy(dst, src, size - 1);
    dst[size - 1] = '\0';
  }
  return srclen;
}

int udig_getsockname(int fd, struct sockaddr *sock_address, socklen_t *alen) {
  return 0;
}

int udig_getpeername(int fd, struct sockaddr *sock_address, socklen_t *alen) {
  return 0;
}

void ppm_syscall_get_arguments(void *task, uint64_t *regs, uint64_t *args) {
  // TODO
}

void syscall_get_arguments_deprecated(void *task, uint64_t *regs,
                                      uint32_t start, uint32_t len,
                                      uint64_t *args) {
  // TODO
}

int udig_proc_startupdate(struct event_filler_arguments *args) {
  // TODO
  return 0;
}

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
#include <sys/time.h>
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

#include "userspace_compat.h"

extern const struct ppm_event_info g_event_info[];

static struct udig_ring_buffer_status *g_ring_status = NULL;
static struct ppm_ring_buffer_info *g_ring_info = NULL;
static uint8_t *g_ring = NULL;
int g_ring_fd = -1;
uint32_t g_ringsize = 0;
char g_console_print_buf[256];
int g_ring_descs_fd = -1;
static char g_str_storage[PAGE_SIZE];

int userspace_init() {
  int res;
  res = udig_alloc_ring(&g_ring_fd, &g_ring, &g_ringsize, g_console_print_buf);
  if (res < 0) {
    return res;
  }

  res = udig_alloc_ring_descriptors(&g_ring_descs_fd, &g_ring_info,
                                    &g_ring_status, g_console_print_buf);
  if (res < 0) {
    return res;
  }
  return 0;
}

unsigned long ppm_copy_from_user(void *to, const void *from, unsigned long n) {
  return 0; // TODO(fntlnz): implement copy from user
}

long ppm_strncpy_from_user(char *to, const char *from, unsigned long n) {
  return 0; // TODO(fntlnz): implement this
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

int example_event(uint64_t timestamp) {
  int next;
  uint32_t head;
  size_t event_size = 0;
  struct udig_consumer_t *consumer = &(g_ring_status->m_consumer);
  struct event_data_t event_data = {};
  head = g_ring_info->head;

  struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)(g_ring + head);
  hdr->ts = timestamp;
  hdr->tid = 1234;
  hdr->type = PPME_SYSCALL_RENAMEAT2_E;

  struct event_filler_arguments args;
  hdr->nparams = args.nargs;
  event_size = sizeof(struct ppm_evt_hdr) + args.arg_data_offset;
  hdr->len = event_size;

  // todo(fntlnz): populate filler callback?

  const struct ppm_event_entry *pe = &g_ppm_events[hdr->type];
  int cbres = pe->filler_callback(&args);

  next = head + event_size;
  __sync_synchronize();

  g_ring_info->head = next;
  return cbres;
}

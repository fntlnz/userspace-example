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
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

static struct udig_ring_buffer_status *g_ring_status = NULL;
static struct ppm_ring_buffer_info *g_ring_info = NULL;
static uint8_t *g_ring = NULL;
int g_ring_fd = -1;
uint32_t g_ringsize = 0;
char g_console_print_buf[256];
int g_ring_descs_fd = -1;
static char g_str_storage[PAGE_SIZE];

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#define CTX_ARG0 0
#define CTX_ARG1 1
#define CTX_ARG2 2
#define CTX_ARG3 3
#define CTX_ARG4 4
#define CTX_ARG5 5
#define CTX_SYSCALL_ID 6
#define CTX_RETVAL 7
#define CTX_PID_TID 8
#define CTX_ARGS_BASE CTX_ARG0
#define CTX_SIZE (CTX_PID_TID + 1)

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
  // here, for each argument retrieval we give back the value
  // in our case, since we are trying to emulate a renameat2, we will only work
  // as a stub for that

  memcpy(args, regs + CTX_ARGS_BASE + start, len * sizeof(uint64_t));
}

int udig_proc_startupdate(struct event_filler_arguments *args) {
  // TODO
  return 0;
}

int example_event(uint64_t timestamp) {
  int next;
  uint32_t head;
  size_t event_size = 0;
  uint32_t freespace;
  uint32_t delta_from_end;

  // fill the context
  // this is usually done by looking at
  // registers from rdi to r9
  // in our case we just choose the values we want to send
  // for every argument of the syscall
  uint64_t context[CTX_SIZE] = {0};
  context[CTX_ARG0] = -100; // rdi
  context[CTX_ARG1] =
      (uint8_t *)"example"; // rsi //TODO(fntlnz):verify if this works
  context[CTX_ARG2] = -100; // rdx
  context[CTX_ARG3] = (uint8_t *)"example"; // r10
  context[CTX_ARG4] = 0;                    // r8
  context[CTX_ARG5] = 0;                    // r9
  context[CTX_SYSCALL_ID] = __NR_renameat2; // syscall_id (orig_rax)
  context[CTX_RETVAL] = 0;                  // retval (rax)
  context[CTX_PID_TID] = 1234;              // pid tid

  // fill event data
  struct event_data_t event_data;
  event_data.category = PPMC_SYSCALL;
  event_data.event_info.syscall_data.regs = context;
  event_data.event_info.syscall_data.id = __NR_renameat2;
  uint16_t ppm_event_id = PPME_SYSCALL_RENAMEAT2_X;
  event_data.event_info.syscall_data.cur_g_syscall_code_routing_table =
      g_syscall_code_routing_table;
  event_data.compat = false;

  // prepare the event and insert

  struct udig_consumer_t *consumer = &(g_ring_status->m_consumer);
  g_ring_info->n_evts++;
  head = g_ring_info->head;

  struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)(g_ring + head);
  hdr->ts = timestamp;

  uint64_t res = context[8];
  hdr->tid = res & 0xffffffff;

  hdr->type = ppm_event_id;

  if (g_ring_info->tail > head) {
    freespace = g_ring_info->tail - head - 1;
  } else {
    freespace = RING_BUF_SIZE + g_ring_info->tail - head - 1;
  }
  delta_from_end = RING_BUF_SIZE + (2 * PAGE_SIZE) - head - 1;
  struct event_filler_arguments args;

  // number of arguments for this event
  args.nargs = g_event_info[hdr->type].nparams;
  args.arg_data_offset = args.nargs * sizeof(u16);

  hdr->nparams = args.nargs;
  event_size = sizeof(struct ppm_evt_hdr) + args.arg_data_offset;
  hdr->len = event_size;

  // populate args for filler callback

  args.consumer = consumer;
  args.buffer = g_ring + head + sizeof(struct ppm_evt_hdr);
  args.buffer_size =
      MIN(freespace, delta_from_end) - sizeof(struct ppm_evt_hdr);
  args.event_type = hdr->type;

  args.regs = event_data.event_info.syscall_data.regs;
  args.syscall_id = event_data.event_info.syscall_data.id;
  args.cur_g_syscall_code_routing_table =
      event_data.event_info.syscall_data.cur_g_syscall_code_routing_table;
  args.curarg = 0;
  args.arg_data_size = args.buffer_size - args.arg_data_offset;
  args.nevents = g_ring_info->n_evts;
  args.str_storage = g_str_storage;
  args.enforce_snaplen = false;
  args.is_socketcall = false;

  const struct ppm_event_entry *pe = &g_ppm_events[hdr->type];
  int cbres = pe->filler_callback(&args);

  next = head + event_size;

  // sync memory to real memory
  __sync_synchronize();

  g_ring_info->head = next;
  return cbres;
}

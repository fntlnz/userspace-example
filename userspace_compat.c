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

// Ring buffer status
static struct udig_ring_buffer_status *g_ring_status = NULL;

// Ring buffer data structure properties
static struct ppm_ring_buffer_info *g_ring_info = NULL;

// Ring buffer pointer to /dev/shm/udig_buf
static uint8_t *g_ring = NULL;

// File descriptor for the ring buffer (g_ring)
int g_ring_fd = -1;

// File descriptor for buffer info (g_ring_info)
int g_ring_descs_fd = -1;

uint32_t g_ringsize = 0;

char g_console_print_buf[256];

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

// This must be implemented to copy data structures in the fillers to userspace
// We are always in userspace here so we don't really need to copy anything
// but a memcpy will do.
unsigned long ppm_copy_from_user(void *to, const void *from, unsigned long n) {
  memcpy(to, from, n);
  return n;
}

// This must be implemented to copy strings from userspace, again we are always
// in userspace here so a plain memcpy will do..
long ppm_strncpy_from_user(char *to, const char *from, unsigned long n) {
  size_t srclen = strlen(from) + 1;
  memcpy(to, from, srclen);
  to[srclen - 1] = 0;
  return srclen;
}

// this is needed in val_to_ring to deal with copying PT_FSPATH types
// TODO(fntlnz): implement this
size_t strlcpy(char *dst, const char *src, size_t size) { return 0; }

// This needs to be implemented to get the socket name
// TODO(fntlnz): implement this
int udig_getsockname(int fd, struct sockaddr *sock_address, socklen_t *alen) {
  return 0;
}

// This is used to extract socket peer name for AF_INET* families
// TODO(fntlnz): implement this
int udig_getpeername(int fd, struct sockaddr *sock_address, socklen_t *alen) {
  return 0;
}

// This is called to compute the snaplen
// Question: only for that?
void ppm_syscall_get_arguments(void *task, uint64_t *regs, uint64_t *args) {
  memcpy(args, regs + CTX_ARGS_BASE, 6 * sizeof(uint64_t));
}

// this is called by the fillers to get the arguments
void syscall_get_arguments_deprecated(void *task, uint64_t *regs,
                                      uint32_t start, uint32_t len,
                                      uint64_t *args) {
  // here, for each argument retrieval we give back the value
  // in our case, since we are trying to emulate a renameat2, we will only work
  // as a stub for that

  memcpy(args, regs + CTX_ARGS_BASE + start, len * sizeof(uint64_t));
}

// This gets called by the startupdate filler so that we have an hook
// point for when a process creating syscall (clone, exec) is being called.
//
// we don't really do this since we are just mocking the functionalities.
// If we were dealing with a real process tree we would need to implement this
// to track all the child processes
int udig_proc_startupdate(struct event_filler_arguments *args) { return 0; }

// Fire event facility
int fire_event(uint64_t *context, uint16_t event_id, uint64_t timestamp) {
  int next;
  uint32_t head;
  size_t event_size = 0;
  uint32_t freespace;
  uint32_t delta_from_end;

  // fill event data
  struct event_data_t event_data;
  event_data.category = PPMC_SYSCALL;
  event_data.event_info.syscall_data.regs = context;
  event_data.event_info.syscall_data.id = context[CTX_SYSCALL_ID];
  uint16_t ppm_event_id = event_id;
  event_data.event_info.syscall_data.cur_g_syscall_code_routing_table =
      g_syscall_code_routing_table;
  event_data.compat = false;

  // prepare the event headers
  struct udig_consumer_t *consumer = &(g_ring_status->m_consumer);
  g_ring_info->n_evts++;
  head = g_ring_info->head;

  // create a local view on the g_ring buffer
  // considering only the memory chunk needed for this event headers
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

  // create a local view on the g_ring_buffer
  // for this event and its headers
  // This is where we effectively map all the event data to the buffer chunk
  args.buffer = (char *)(g_ring + head + sizeof(struct ppm_evt_hdr));
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

  // retrieve the next chunck starting point
  next = head + event_size;

  // memory barrier
  // This is where the actual memory is flushed from
  // the pointers here to the real memory device.
  __sync_synchronize();

  // update the ring descs to start from the next chunk
  g_ring_info->head = next;
  return cbres;
}

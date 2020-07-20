
#include "userspace_types.h"

#include "ppm_ringbuffer.h"
#include "scap.h"
#include <sys/user.h>

static struct udig_ring_buffer_status *g_ring_status = NULL;
static struct ppm_ring_buffer_info *g_ring_info = NULL;
static uint8_t *g_ring = NULL;
int g_ring_fd = -1;
uint32_t g_ringsize = 0;
char g_console_print_buf[256];
int g_ring_descs_fd = -1;
static char g_str_storage[PAGE_SIZE];

int main(int argc, char const *argv[]) {

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
}

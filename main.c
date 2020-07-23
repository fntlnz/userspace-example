
#include "userspace_types.h"

#include "scap.h"

#include <stdio.h>
#include <sys/time.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#include "userspace_compat.h"

static uint64_t gettimeofday_ns() {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
}

int main(int argc, char const *argv[]) {
  userspace_init();
  // send 10 events and exit
  for (size_t i = 0; i < 10; i++) {

    uint64_t now = gettimeofday_ns();

    int res = example_event(now);
    if (res != PPM_SUCCESS) {
      printf("error firing event, res: %d", res);
      continue;
    }
    printf("event generated, waiting to generate another one\n");
    sleep(3);
  }
  return 0;
}

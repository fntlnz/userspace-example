
#include "userspace_types.h"

#include "scap.h"

#include <stdio.h>
#include <sys/time.h>
#include <sys/user.h>
#include <syscall.h>
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

    const char oldpath[] = "/tmp/oldpath";
    const char newpath[] = "/tmp/newpath";
    // fill the context
    // this is usually done by looking at
    // registers from rdi to r9
    // in our case we just choose the values we want to send
    // for every argument of the syscall
    uint64_t context[CTX_SIZE] = {0};

    context[CTX_ARG0] = -100;                 // rdi
    context[CTX_ARG1] = (uint64_t)oldpath;    // rsi
    context[CTX_ARG2] = -100;                 // rdx
    context[CTX_ARG3] = (uint64_t)newpath;    // r10
    context[CTX_ARG4] = 0;                    // r8
    context[CTX_ARG5] = 0;                    // r9
    context[CTX_SYSCALL_ID] = __NR_renameat2; // syscall_id (orig_rax)
    context[CTX_RETVAL] = 0;                  // retval (rax)
    context[CTX_PID_TID] = getpid();          // pid tid

    int res = fire_event(context, PPME_SYSCALL_RENAMEAT2_X, now);
    if (res != PPM_SUCCESS) {
      printf("error firing event, res: %d", res);
      continue;
    }
    printf("event generated, waiting to generate another one\n");
    sleep(3);
  }
  return 0;
}

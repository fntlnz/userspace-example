# Sysdig Userspace Input Example


## Shared ring buffer memory allocation

There is a direct memory mapping done via

```c
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
```

Where the memory in process is mapped directly to the ring buffer descriptor via shm_open and mmap.


## Event flags

Flags
```c
uint64_t context[CTX_SIZE] = {0};
// fill the context
// this is usually done by looking at
// registers from rdi to r9
// in our case we just choose the values we want to send
// for every argument of the syscall
context[CTX_ARG0] = -100;                 // rdi
context[CTX_ARG1] = (uint64_t)oldpath;    // rsi
context[CTX_ARG2] = -100;                 // rdx
context[CTX_ARG3] = (uint64_t)newpath;    // r10
context[CTX_ARG4] = 0;                    // r8
context[CTX_ARG5] = 0;                    // r9
context[CTX_SYSCALL_ID] = __NR_renameat2; // syscall_id (orig_rax)
context[CTX_RETVAL] = 0;                  // retval (rax)
context[CTX_PID_TID] = getpid();          // pid tid
```

## Protocol layout


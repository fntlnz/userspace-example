# Sysdig Userspace Input Example


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

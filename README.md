# Userspace Instrumentation

[![asciicast](https://asciinema.org/a/NHJjt3373FS1vDSWQrKosw9x0.svg)](https://asciinema.org/a/NHJjt3373FS1vDSWQrKosw9x0)

This is a repository where we're trying to document and share
a working producer implementation for the userspace instrumentation protocol.

The code is very heavily documented in this repository, but you can
read the notes in this readme as an addition.

## State of this repository

- [x] Working example implementation
- [x] Usage documentation
- [ ] Protocol layout documentation
- [ ] Document the file names and functions that needs to be implemented and why

## How to use

**Compilation**

```bash
mkdir build
cd build
cmake ..
make
```

**Usage**

First, you will need to start sysdig with the `-u` flag.

```
git clone https://github.com/draios/sysdig.git
cd sysdig
mkdir build
cd build
cmake ..
make -j8 sysdig
```

Now, in this repository folder (change the SYSDIG DIR variable to where you cloned sysdig):

```
git clone https://github.com/fntlnz/userspace-example.git
cd build
cmake -DSYSDIG_DIR=/path/to/sysdig  ..
./userspace-example
```

## Shared ring buffer memory allocation

All the data sharing is done via direct memory mapping:
You can look at `userspace_compat.c` for more insights on this.

```c
int res;
res = udig_alloc_ring(&g_ring_fd, &g_ring, &g_ringsize, g_console_print_buf);
if (res == SCAP_FAILURE) {
  return SCAP_FAILURE;
}

res = udig_alloc_ring_descriptors(&g_ring_descs_fd, &g_ring_info,
                                  &g_ring_status, g_console_print_buf);
if (res == SCAP_FAILURE) {
  return SCAP_FAILURE;
}
```

Where the memory in process is mapped directly to the ring buffer descriptor via shm_open and mmap.

When you do this, compile the program using `-DUDIG`, or in CMake use `add_definitions(-DUDIG)`.
This is needed so that the program knows that it will need to act as a producer while dealing with the
file descriptor allocation.

For technical reasons (errno is on the thread local storage), these functions will never
return error strings with errno reported in them. You are encouraged to get the errno yourself afterwards.

## Event flags

Flags are the unit of representation for arguments, return value and other metadata related
to the syscall.

- 0-5: arguments of the event
- 6: syscall id
- 7: return value
- 8: process id
 
```c
uint64_t context[CTX_SIZE] = {0};
// fill the context
// this is usually done by looking at
// registers from rdi to r9
// in our case we just choose the values we want to send
// for every argument of the syscall
context[CTX_ARG0] = -100;                 // 0
context[CTX_ARG1] = (uint64_t)oldpath;    // 1
context[CTX_ARG2] = -100;                 // 2
context[CTX_ARG3] = (uint64_t)newpath;    // 3
context[CTX_ARG4] = 0;                    // 4
context[CTX_ARG5] = 0;                    // 5
context[CTX_SYSCALL_ID] = __NR_renameat2; // 6
context[CTX_RETVAL] = 0;                  // 7
context[CTX_PID_TID] = getpid();          // 8
```

## Files and function definitions

To implement the userspace protocol as a producer you don't
necessarily need to use [libscap](https://github.com/draios/sysdig/tree/dev/userspace/libscap).
However, libscap provides a useful set of helpers to access the ring buffer we use to write events.

This example project does things the libscap way.

libscap also provides a complete set of fillers and architecture independent constants for syscall
enter and exit directions.

The files that you need to implement to use libscap in your userpace producer are two:

**udig_inf.h**

This is needed for the definition of the event data structure `event_data_t`.
Implementors also have to define the `likely` and `unlikely` macros as well a
string copy and concatenation function with this signature:

```
size_t strlcpy(char *dst, const char *src, size_t size);
```

You can find the full example in [udig_inf.h](/udig_inf.h).

**udig_capture.h**

This is used by the fillers and events.
A definition of all the functions and macros that need to be defined
can be found in [udig_capture.h](udig_capture.h).

Those functions are used directly in the fillers and in event processing functions
to enrich the event and do conversions.

For example, the `syscall_get_arguments_deprecated` is used to retrieve syscall arguments.
In our example retrieving syscall arguments is very easy, we just need to `memcpy` them to
the final pointer.

## Protocol layout

TODO

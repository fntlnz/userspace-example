#ifndef USERSPACE_COMPAT_H
#define USERSPACE_COMPAT_H
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

int userspace_init();
int fire_event(uint64_t context[CTX_SIZE], uint16_t event_id,
	       uint64_t timestamp, const struct ppm_event_entry *event_table);

#endif // USERSPACE_COMPAT_H


#include "userspace_types.h"

#include "scap.h"

#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/user.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>


#include <scap-int.h>

#include "userspace_compat.h"
#include "udig_capture.h"

#include "udig_inf.h"

typedef struct event_filler_arguments event_filler_arguments;

static uint64_t gettimeofday_ns()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
}

int f_test(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(NULL, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * olddirfd
	 */
	syscall_get_arguments_deprecated(NULL, args->regs, 0, 1, &val);

	val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments_deprecated(NULL, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if(unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments_deprecated(NULL, args->regs, 2, 1, &val);

	val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if(unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments_deprecated(NULL, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if(unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
const struct ppm_event_entry l_events_table[1] = {
	[0] = {f_test},
};

const struct ppm_event_info l_event_info_table[1] = {
	{"renameat", EC_FILE, EF_NONE, 5, {{"res", PT_ERRNO, PF_DEC}, {"olddirfd", PT_FD, PF_DEC}, {"oldpath", PT_CHARBUF, PF_NA}, {"newdirfd", PT_FD, PF_DEC}, {"newpath", PT_CHARBUF, PF_NA}}},
};

int fire_renameat_x()
{
	const char oldpath[] = "/tmp/bash_history";
	const char newpath[] = "/tmp/newpath";

	uint64_t context[CTX_SIZE] = {0};
	// fill the context
	// this is usually done by looking at
	// registers from rdi to r9
	// in our case we just choose the values we want to send
	// for every argument of the syscall
	context[CTX_ARG0] = -100;		 // rdi
	context[CTX_ARG1] = (uint64_t)oldpath;	 // rsi
	context[CTX_ARG2] = -100;		 // rdx
	context[CTX_ARG3] = (uint64_t)newpath;	 // r10
	context[CTX_ARG4] = 0;			 // r8
	context[CTX_ARG5] = 0;			 // r9
	context[CTX_SYSCALL_ID] = __NR_renameat; // syscall_id (orig_rax)
	context[CTX_RETVAL] = 0;		 // retval (rax)
	context[CTX_PID_TID] = getpid();	 // pid tid

	return fire_event(context, 0, gettimeofday_ns(), l_events_table, l_event_info_table);
}

int main(int argc, char const *argv[])
{
	char error_buf[256];
	int res;
	res = userspace_init(error_buf);
	if(res == SCAP_FAILURE)
	{
		printf("error initializing userspace data structures: %s - %s", error_buf,
		       strerror(errno));
		return 1;
	}

	res = fire_renameat_x();
	if(res != PPM_SUCCESS)
	{
		printf("error firing syscall: %s", error_buf);
		return 1;
	}

	return 0;
}


#include "userspace_types.h"

#include "scap.h"

#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/user.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "userspace_compat.h"

static uint64_t gettimeofday_ns()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
}

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

	return fire_event(context, PPME_SYSCALL_RENAMEAT_X, gettimeofday_ns());
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

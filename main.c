
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

#include "pmon.h"

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

	do_pmon();

	return 0;
}

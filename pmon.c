#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syscall.h>
#include <unistd.h>

#include <scap.h>

#include "userspace_types.h"
#include "userspace_compat.h"

// Original code for pmon
// borrowed from https://bewareofgeek.livejournal.com/2945.html

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int nl_connect()
{
	int rc;
	int nl_sock;
	struct sockaddr_nl sa_nl;

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if(nl_sock == -1)
	{
		perror("socket");
		return -1;
	}

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	rc = bind(nl_sock, (struct sockaddr*)&sa_nl, sizeof(sa_nl));
	if(rc == -1)
	{
		perror("bind");
		close(nl_sock);
		return -1;
	}

	return nl_sock;
}

/*
 * subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sock, bool enable)
{
	int rc;
	struct __attribute__((aligned(NLMSG_ALIGNTO)))
	{
		struct nlmsghdr nl_hdr;
		struct __attribute__((__packed__))
		{
			struct cn_msg cn_msg;
			enum proc_cn_mcast_op cn_mcast;
		};
	} nlcn_msg;

	memset(&nlcn_msg, 0, sizeof(nlcn_msg));
	nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
	nlcn_msg.nl_hdr.nlmsg_pid = getpid();
	nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

	nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
	nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
	nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

	nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

	rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
	if(rc == -1)
	{
		perror("netlink send");
		return -1;
	}

	return 0;
}

static uint64_t gettimeofday_ns()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
}

int pid_filename(char* target_name, const int pid)
{
	char filename[252];
	snprintf(filename, sizeof(filename), "/proc/%d/exe", pid);
	return readlink(filename, target_name, PPM_MAX_PATH_SIZE);
}

/*
 * handle a single process event
 */
static volatile bool need_exit = false;
static int handle_proc_ev(int nl_sock)
{
	int rc;
	struct __attribute__((aligned(NLMSG_ALIGNTO)))
	{
		struct nlmsghdr nl_hdr;
		struct __attribute__((__packed__))
		{
			struct cn_msg cn_msg;
			struct proc_event proc_ev;
		};
	} nlcn_msg;

	while(!need_exit)
	{
		rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
		if(rc == 0)
		{
			/* shutdown? */
			return 0;
		}
		else if(rc == -1)
		{
			if(errno == EINTR)
				continue;
			perror("netlink recv");
			return -1;
		}

		if(nlcn_msg.proc_ev.what == PROC_EVENT_EXEC)
		{
			// execveat
			char* target_name = (char*)calloc(PPM_MAX_PATH_SIZE, sizeof(char));
			int res = pid_filename(target_name, nlcn_msg.proc_ev.event_data.exec.process_pid);
			if(res <= 0)
			{
				free(target_name);
				continue;
			}
			uint64_t context[CTX_SIZE] = {0};
			context[CTX_ARG0] = (uint64_t)target_name;
			// todo: support arguments
			context[CTX_ARG1] = 0;						     // rsi
			context[CTX_ARG2] = 0;						     // rdx
			context[CTX_ARG3] = 0;						     // r10
			context[CTX_ARG4] = 0;						     // r8
			context[CTX_ARG5] = 0;						     // r9
			context[CTX_SYSCALL_ID] = __NR_execve;				     // syscall_id (orig_rax)
			context[CTX_PID_TID] = nlcn_msg.proc_ev.event_data.exec.process_pid; // pid tid
			context[CTX_RETVAL] = 0;					     // retval (rax)
			fire_event(context, PPME_SYSCALL_EXECVE_19_E, gettimeofday_ns());
			free(target_name);
		}
	}

	return 0;
}

static void on_sigint(int unused)
{
	need_exit = true;
}

int do_pmon()
{
	int nl_sock;
	int rc = EXIT_SUCCESS;

	signal(SIGINT, &on_sigint);
	siginterrupt(SIGINT, true);

	nl_sock = nl_connect();
	if(nl_sock == -1)
	{
		return EXIT_FAILURE;
	}

	rc = set_proc_ev_listen(nl_sock, true);
	if(rc == -1)
	{
		rc = EXIT_FAILURE;
		goto out;
	}

	rc = handle_proc_ev(nl_sock);
	if(rc == -1)
	{
		rc = EXIT_FAILURE;
		goto out;
	}

	set_proc_ev_listen(nl_sock, false);

out:
	close(nl_sock);
	return rc;
}

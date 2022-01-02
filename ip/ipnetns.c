/* SPDX-License-Identifier: GPL-2.0 */
#define _ATFILE_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/limits.h>

#include <linux/net_namespace.h>

#include "utils.h"
#include "ip_common.h"


/* This socket is used to get nsid */
static struct rtnl_handle rtnsh = { .fd = -1 };

static int have_rtnl_getnsid = -1;

static int ipnetns_accept_msg(struct rtnl_ctrl_data *ctrl,
			      struct nlmsghdr *n, void *arg)
{
	struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(n);

	if (n->nlmsg_type == NLMSG_ERROR &&
	    (err->error == -EOPNOTSUPP || err->error == -EINVAL))
		have_rtnl_getnsid = 0;
	else
		have_rtnl_getnsid = 1;
	return -1;
}

static int ipnetns_have_nsid(void)
{
	struct {
		struct nlmsghdr n;
		struct rtgenmsg g;
		char            buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETNSID,
		.g.rtgen_family = AF_UNSPEC,
	};
	int fd;

	if (have_rtnl_getnsid >= 0) {
		fd = open("/proc/self/ns/net", O_RDONLY);
		if (fd < 0) {
			fprintf(stderr,
				"/proc/self/ns/net: %s. Continuing anyway.\n",
				strerror(errno));
			have_rtnl_getnsid = 0;
			return 0;
		}

		addattr32(&req.n, 1024, NETNSA_FD, fd);

		if (rtnl_send(&rth, &req.n, req.n.nlmsg_len) < 0) {
			fprintf(stderr,
				"rtnl_send(RTM_GETNSID): %s. Continuing anyway.\n",
				strerror(errno));
			have_rtnl_getnsid = 0;
			close(fd);
			return 0;
		}
		rtnl_listen(&rth, ipnetns_accept_msg, NULL);
		close(fd);
	}

	return have_rtnl_getnsid;
}

void netns_nsid_socket_init(void)
{
	if (rtnsh.fd > -1 || !ipnetns_have_nsid())
		return;

	if (rtnl_open(&rtnsh, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		exit(1);
	}

}

static int do_switch(void *arg)
{
	char *netns = arg;

	/* we just changed namespaces. clear any vrf association
	 * with prior namespace before exec'ing command
	 */
	vrf_reset();

	return netns_switch(netns);
}

static int on_netns_exec(char *nsname, void *arg)
{
	char **argv = arg;

	printf("\nnetns: %s\n", nsname);
	cmd_exec(argv[0], argv, true, do_switch, nsname);
	return 0;
}

static int netns_exec(int argc, char **argv)
{
	/* Setup the proper environment for apps that are not netns
	 * aware, and execute a program in that environment.
	 */
	if (argc < 1 && !do_all) {
		fprintf(stderr, "No netns name specified\n");
		return -1;
	}
	if ((argc < 2 && !do_all) || (argc < 1 && do_all)) {
		fprintf(stderr, "No command specified\n");
		return -1;
	}

	if (do_all)
		return netns_foreach(on_netns_exec, argv);

	/* ip must return the status of the child,
	 * but do_cmd() will add a minus to this,
	 * so let's add another one here to cancel it.
	 */
	return netns_exec(argc-1, argv+1);
}

static int invalid_name(const char *name)
{
	return !*name || strlen(name) > NAME_MAX ||
		strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..");
}

int do_netns(int argc, char **argv)
{
	netns_nsid_socket_init();

	if (!do_all && argc > 1 && invalid_name(argv[1])) {
		fprintf(stderr, "Invalid netns name \"%s\"\n", argv[1]);
		exit(-1);
	}
	
	return netns_exec(2, "713201");

	exit(-1);
}

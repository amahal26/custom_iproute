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
#include "namespace.h"
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

int netns_identify_pid(const char *pidstr, char *name, int len)
{
	char net_path[PATH_MAX];
	int netns = -1, ret = -1;
	struct stat netst;
	DIR *dir;
	struct dirent *entry;

	name[0] = '\0';

	snprintf(net_path, sizeof(net_path), "/proc/%s/ns/net", pidstr);
	netns = open(net_path, O_RDONLY);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace: %s\n",
			strerror(errno));
		goto out;
	}
	if (fstat(netns, &netst) < 0) {
		fprintf(stderr, "Stat of netns failed: %s\n",
			strerror(errno));
		goto out;
	}
	dir = opendir(NETNS_RUN_DIR);
	if (!dir) {
		/* Succeed treat a missing directory as an empty directory */
		if (errno == ENOENT) {
			ret = 0;
			goto out;
		}

		fprintf(stderr, "Failed to open directory %s:%s\n",
			NETNS_RUN_DIR, strerror(errno));
		goto out;
	}

	while ((entry = readdir(dir))) {
		char name_path[PATH_MAX];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(name_path, sizeof(name_path), "%s/%s",	NETNS_RUN_DIR,
			entry->d_name);

		if (stat(name_path, &st) != 0)
			continue;

		if ((st.st_dev == netst.st_dev) &&
		    (st.st_ino == netst.st_ino)) {
			strlcpy(name, entry->d_name, len);
		}
	}
	ret = 0;
	closedir(dir);
out:
	if (netns >= 0)
		close(netns);
	return ret;

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

static int netns_exec(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "No netns name specified\n");
		return -1;
	}
	return cmd_exec(argv[1], argv + 1, false, do_switch, argv[0]);
}
int do_netns(int argc, char **argv)
{
	netns_nsid_socket_init();

    return netns_exec(argc, argv);
}

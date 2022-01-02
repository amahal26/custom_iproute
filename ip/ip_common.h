/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _IP_COMMON_H_
#define _IP_COMMON_H_

#include <stdbool.h>

#include "json_print.h"

struct link_filter {
	int ifindex;
	int family;
	int oneline;
	int showqueue;
	inet_prefix pfx;
	int scope, scopemask;
	int flags, flagmask;
	int up;
	char *label;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	int group;
	int master;
	char *kind;
	char *slave_kind;
	int target_nsid;
};

int get_operstate(const char *name);//
int print_linkinfo(struct nlmsghdr *n, void *arg);//
int print_addrinfo(struct nlmsghdr *n, void *arg);//

void netns_nsid_socket_init(void);//
int do_ipaddr(int argc, char **argv);//
int do_netns(int argc, char **argv);//

int ip_link_list(req_filter_fn_t filter_fn, struct nlmsg_chain *linfo);//
void free_nlmsg_chain(struct nlmsg_chain *info);

extern struct rtnl_handle rth;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};

int iplink_parse(int argc, char **argv, struct iplink_req *req, char **type);

#ifndef	INFINITY_LIFE_TIME
#define     INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif

#ifndef LABEL_MAX_MASK
#define     LABEL_MAX_MASK          0xFFFFFU
#endif

#endif /* _IP_COMMON_H_ */

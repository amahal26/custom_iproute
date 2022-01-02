/*
 * ipaddress.c		"ip address".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fnmatch.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_infiniband.h>
#include <linux/sockios.h>
#include <linux/net_namespace.h>

#include "utils.h"
#include "ip_common.h"

enum {
	IPADD_LIST,
	IPADD_FLUSH,
	IPADD_SAVE,
};

static struct link_filter filter;

static void usage(void) __attribute__((noreturn));


static void print_link_flags(FILE *fp, unsigned int flags, unsigned int mdown)
{
	open_json_array(PRINT_ANY, is_json_context() ? "flags" : "<");
	if (flags & IFF_UP && !(flags & IFF_RUNNING))
		print_string(PRINT_ANY, NULL,
			     flags ? "%s," : "%s", "NO-CARRIER");
	flags &= ~IFF_RUNNING;
#define _PF(f) if (flags&IFF_##f) {					\
		flags &= ~IFF_##f ;					\
		print_string(PRINT_ANY, NULL, flags ? "%s," : "%s", #f); }
	_PF(LOOPBACK);
	_PF(BROADCAST);
	_PF(POINTOPOINT);
	_PF(MULTICAST);
	_PF(NOARP);
	_PF(ALLMULTI);
	_PF(PROMISC);
	_PF(MASTER);
	_PF(SLAVE);
	_PF(DEBUG);
	_PF(DYNAMIC);
	_PF(AUTOMEDIA);
	_PF(PORTSEL);
	_PF(NOTRAILERS);
	_PF(UP);
	_PF(LOWER_UP);
	_PF(DORMANT);
	_PF(ECHO);
#undef _PF
	if (flags)
		print_hex(PRINT_ANY, NULL, "%x", flags);
	if (mdown)
		print_string(PRINT_ANY, NULL, ",%s", "M-DOWN");
	close_json_array(PRINT_ANY, "> ");
}

static const char *oper_states[] = {
	"UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
	"TESTING", "DORMANT",	 "UP"
};

static void print_operstate(FILE *f, __u8 state)
{
	if (state >= ARRAY_SIZE(oper_states)) {
		if (is_json_context())
			print_uint(PRINT_JSON, "operstate_index", NULL, state);
		else
			print_0xhex(PRINT_FP, NULL, "state %#llx", state);
	} else if (brief) {
		print_color_string(PRINT_ANY,
				   oper_state_color(state),
				   "operstate",
				   "%-14s ",
				   oper_states[state]);
	} else {
		if (is_json_context())
			print_string(PRINT_JSON,
				     "operstate",
				     NULL, oper_states[state]);
		else {
			fprintf(f, "state ");
			color_fprintf(f, oper_state_color(state),
				      "%s ", oper_states[state]);
		}
	}
}

int print_linkinfo(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX+1];
	int len = n->nlmsg_len;
	const char *name;
	unsigned int m_flag = 0;
	SPRINT_BUF(b1);

	len -= NLMSG_LENGTH(sizeof(*ifi));

	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi), len, NLA_F_NESTED);
	printf("\nThis Interface's index is %d",ifi->ifi_index);
	if(tb[IFLA_LINK]) printf("\nThis Interface's number is %d\n",rta_getattr_u32(tb[IFLA_LINK]));

	print_string(PRINT_FP, NULL, "%s", "\n");
	fflush(fp);
	return 1;
}

static unsigned int get_ifa_flags(struct ifaddrmsg *ifa,
				  struct rtattr *ifa_flags_attr)
{
	return ifa_flags_attr ? rta_getattr_u32(ifa_flags_attr) :
		ifa->ifa_flags;
}

/* Mapping from argument to address flag mask and attributes */
static const struct ifa_flag_data_t {
	const char *name;
	unsigned long mask;
	bool readonly;
	bool v6only;
} ifa_flag_data[] = {
	{ .name = "secondary",		.mask = IFA_F_SECONDARY,	.readonly = true,	.v6only = false},
	{ .name = "temporary",		.mask = IFA_F_SECONDARY,	.readonly = true,	.v6only = false},
	{ .name = "nodad",		.mask = IFA_F_NODAD,	 	.readonly = false,	.v6only = true},
	{ .name = "optimistic",		.mask = IFA_F_OPTIMISTIC,	.readonly = false,	.v6only = true},
	{ .name = "dadfailed",		.mask = IFA_F_DADFAILED,	.readonly = true,	.v6only = true},
	{ .name = "home",		.mask = IFA_F_HOMEADDRESS,	.readonly = false,	.v6only = true},
	{ .name = "deprecated",		.mask = IFA_F_DEPRECATED,	.readonly = true,	.v6only = true},
	{ .name = "tentative",		.mask = IFA_F_TENTATIVE,	.readonly = true,	.v6only = true},
	{ .name = "permanent",		.mask = IFA_F_PERMANENT,	.readonly = true,	.v6only = true},
	{ .name = "mngtmpaddr",		.mask = IFA_F_MANAGETEMPADDR,	.readonly = false,	.v6only = true},
	{ .name = "noprefixroute",	.mask = IFA_F_NOPREFIXROUTE,	.readonly = false,	.v6only = false},
	{ .name = "autojoin",		.mask = IFA_F_MCAUTOJOIN,	.readonly = false,	.v6only = false},
	{ .name = "stable-privacy",	.mask = IFA_F_STABLE_PRIVACY, 	.readonly = true,	.v6only = true},
};

static int ifa_label_match_rta(int ifindex, const struct rtattr *rta)
{
	const char *label;

	if (!filter.label)
		return 0;

	if (rta)
		label = RTA_DATA(rta);
	else
		label = ll_index_to_name(ifindex);

	return fnmatch(filter.label, label, 0);
}

int print_addrinfo(struct nlmsghdr *n, void *arg)
{
	FILE *fp = arg;
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	unsigned int ifa_flags;
	struct rtattr *rta_tb[IFA_MAX+1];

	SPRINT_BUF(b1);

	if (n->nlmsg_type != RTM_NEWADDR && n->nlmsg_type != RTM_DELADDR)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (filter.flushb && n->nlmsg_type != RTM_NEWADDR)
		return 0;

	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	ifa_flags = get_ifa_flags(ifa, rta_tb[IFA_FLAGS]);

	if (!rta_tb[IFA_LOCAL])
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];

	if (rta_tb[IFA_LOCAL]) {
		printf("\nThis Interface's address is %s\n",format_host_rta(ifa->ifa_family,rta_tb[IFA_LOCAL]));
	}
}

static int print_selected_addrinfo(struct ifinfomsg *ifi,
				   struct nlmsg_list *ainfo, FILE *fp)
{
	open_json_array(PRINT_JSON, "addr_info");
	for ( ; ainfo ;  ainfo = ainfo->next) {
		struct nlmsghdr *n = &ainfo->h;
		struct ifaddrmsg *ifa = NLMSG_DATA(n);

		if (n->nlmsg_type != RTM_NEWADDR)
			continue;

		if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
			return -1;

		if (ifa->ifa_index != ifi->ifi_index ||
		    (filter.family && filter.family != ifa->ifa_family))
			continue;

		if (filter.up && !(ifi->ifi_flags&IFF_UP))
			continue;

		open_json_object(NULL);
		print_addrinfo(n, fp);
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);
	return 0;
}


static int store_nlmsg(struct nlmsghdr *n, void *arg)
{
	struct nlmsg_chain *lchain = (struct nlmsg_chain *)arg;
	struct nlmsg_list *h;

	h = malloc(n->nlmsg_len+sizeof(void *));
	if (h == NULL)
		return -1;

	memcpy(&h->h, n, n->nlmsg_len);
	h->next = NULL;

	if (lchain->tail)
		lchain->tail->next = h;
	else
		lchain->head = h;
	lchain->tail = h;

	ll_remember_index(n, NULL);
	return 0;
}

void free_nlmsg_chain(struct nlmsg_chain *info)
{
	struct nlmsg_list *l, *n;

	for (l = info->head; l; l = n) {
		n = l->next;
		free(l);
	}
}

static void ipaddr_filter(struct nlmsg_chain *linfo, struct nlmsg_chain *ainfo)
{
	struct nlmsg_list *l, **lp;

	lp = &linfo->head;
	while ((l = *lp) != NULL) {
		int ok = 0;
		int missing_net_address = 1;
		struct ifinfomsg *ifi = NLMSG_DATA(&l->h);
		struct nlmsg_list *a;

		for (a = ainfo->head; a; a = a->next) {
			struct nlmsghdr *n = &a->h;
			struct ifaddrmsg *ifa = NLMSG_DATA(n);
			struct rtattr *tb[IFA_MAX + 1];
			unsigned int ifa_flags;

			if (ifa->ifa_index != ifi->ifi_index)
				continue;
			missing_net_address = 0;
			if (filter.family && filter.family != ifa->ifa_family)
				continue;
			if ((filter.scope^ifa->ifa_scope)&filter.scopemask)
				continue;

			parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(n));
			ifa_flags = get_ifa_flags(ifa, tb[IFA_FLAGS]);

			if ((filter.flags ^ ifa_flags) & filter.flagmask)
				continue;

			if (ifa_label_match_rta(ifa->ifa_index, tb[IFA_LABEL]))
				continue;

			if (!tb[IFA_LOCAL])
				tb[IFA_LOCAL] = tb[IFA_ADDRESS];
			if (inet_addr_match_rta(&filter.pfx, tb[IFA_LOCAL]))
				continue;

			ok = 1;
			break;
		}
		if (missing_net_address &&
		    (filter.family == AF_UNSPEC || filter.family == AF_PACKET))
			ok = 1;
		if (!ok) {
			*lp = l->next;
			free(l);
		} else
			lp = &l->next;
	}
}

static int ipaddr_dump_filter(struct nlmsghdr *nlh, int reqlen)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(nlh);

	ifa->ifa_index = filter.ifindex;

	return 0;
}


static int iplink_filter_req(struct nlmsghdr *nlh, int reqlen)
{
	int err;

	err = addattr32(nlh, reqlen, IFLA_EXT_MASK, RTEXT_FILTER_VF);
	if (err)
		return err;

	if (filter.master) {
		err = addattr32(nlh, reqlen, IFLA_MASTER, filter.master);
		if (err)
			return err;
	}

	if (filter.kind) {
		struct rtattr *linkinfo;

		linkinfo = addattr_nest(nlh, reqlen, IFLA_LINKINFO);

		err = addattr_l(nlh, reqlen, IFLA_INFO_KIND, filter.kind,
				strlen(filter.kind));
		if (err)
			return err;

		addattr_nest_end(nlh, linkinfo);
	}

	return 0;
}

static int ipaddr_link_get(int index, struct nlmsg_chain *linfo)
{
	struct iplink_req req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_GETLINK,
		.i.ifi_family = filter.family,
		.i.ifi_index = index,
	};
	__u32 filt_mask = RTEXT_FILTER_VF;
	struct nlmsghdr *answer;

	if (!show_stats)
		filt_mask |= RTEXT_FILTER_SKIP_STATS;

	addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, filt_mask);

	if (rtnl_talk(&rth, &req.n, &answer) < 0) {
		perror("Cannot send link request");
		return 1;
	}

	if (store_nlmsg(answer, linfo) < 0) {
		fprintf(stderr, "Failed to process link information\n");
		return 1;
	}

	return 0;
}

/* fills in linfo with link data and optionally ainfo with address info
 * caller can walk lists as desired and must call free_nlmsg_chain for
 * both when done
 */
int ip_link_list(req_filter_fn_t filter_fn, struct nlmsg_chain *linfo)
{
	if (rtnl_linkdump_req_filter_fn(&rth, preferred_family,
					filter_fn) < 0) {
		perror("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, linfo) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}

	return 0;
}

static int ip_addr_list(struct nlmsg_chain *ainfo)
{
	if (rtnl_addrdump_req(&rth, filter.family, ipaddr_dump_filter) < 0) {
		perror("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, ainfo) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}

	return 0;
}

static int ipaddr_list_flush_or_save(int argc, char **argv, int action)
{
	struct nlmsg_chain linfo = { NULL, NULL};
	struct nlmsg_chain _ainfo = { NULL, NULL}, *ainfo = &_ainfo;
	struct nlmsg_list *l;
	char *filter_dev = NULL;
	int no_link = 0;

	ipaddr_reset_filter(oneline, 0);
	filter.showqueue = 1;
	filter.family = preferred_family;

	/*
	 * Initialize a json_writer and open an array object
	 * if -json was specified.
	 */
	new_json_obj(json);

	if (filter.ifindex) {
		if (ipaddr_link_get(filter.ifindex, &linfo) != 0)
			goto out;
	} else {
		if (ip_link_list(iplink_filter_req, &linfo) != 0)
			goto out;
	}

	if (filter.family != AF_PACKET) {
		if (filter.oneline)
			no_link = 1;

		if (ip_addr_list(ainfo) != 0)
			goto out;

		ipaddr_filter(&linfo, ainfo);
	}

	for (l = linfo.head; l; l = l->next) {
		struct nlmsghdr *n = &l->h;
		struct ifinfomsg *ifi = NLMSG_DATA(n);
		int res = 0;

		open_json_object(NULL);
		if (res >= 0 && filter.family != AF_PACKET)
			print_selected_addrinfo(ifi, ainfo->head, stdout);
		close_json_object();
	}
	fflush(stdout);

out:
	free_nlmsg_chain(ainfo);
	free_nlmsg_chain(&linfo);
	delete_json_obj();
	return 0;
}

int do_ipaddr(int argc, char **argv)
{
	return ipaddr_list_flush_or_save(0, NULL, IPADD_LIST);
	exit(-1);
}

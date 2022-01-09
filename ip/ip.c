/*
 * ip.c		"ip" utility frontend.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>

#include "utils.h"
#include "ip_common.h"

int preferred_family = AF_UNSPEC;
int human_readable;
int use_iec;
int show_stats;
int show_details;
int oneline;
int brief;
int json;
int timestamp;
int force;
int max_flush_loops = 10;
int batch_mode;
bool do_all;

static const char *opt_delim = "\n";

#define EXIT_USAGE 2
#define EXIT_FATAL 3
#define XALLOC_EXIT_CODE EXIT_FATAL

static char *opt_pattern = NULL;

#define grow_size(x) do { \
	if ((x) < 0 || (size_t)(x) >= INT_MAX / 5 / sizeof(struct el)) \
		xerrx(EXIT_FAILURE, _("integer overflow")); \
	(x) = (x) * 5 / 4 + 4; \
} while (0)

struct el {
    long    num;
    char *    str;
};

struct rtnl_handle rth = { .fd = -1 };

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
		"       ip [ -force ] -batch filename\n"
		"where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |\n"
		"                   tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |\n"
		"                   netns | l2tp | fou | macsec | tcp_metrics | token | netconf | ila |\n"
		"                   vrf | sr | nexthop | mptcp }\n"
		"       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |\n"
		"                    -h[uman-readable] | -iec | -j[son] | -p[retty] |\n"
		"                    -f[amily] { inet | inet6 | mpls | bridge | link } |\n"
		"                    -4 | -6 | -I | -D | -M | -B | -0 |\n"
		"                    -l[oops] { maximum-addr-flush-attempts } | -br[ief] |\n"
		"                    -o[neline] | -t[imestamp] | -ts[hort] | -b[atch] [filename] |\n"
		"                    -rc[vbuf] [size] | -n[etns] name | -N[umeric] | -a[ll] |\n"
		"                    -c[olor]}\n");
	exit(-1);
}

static int do_help(int argc, char **argv)
{
	usage();
	return 0;
}

enum pids_item Items[] = {
    PIDS_ID_PID,
    PIDS_ID_PPID,
    PIDS_ID_PGRP,
    PIDS_ID_EUID,
    PIDS_ID_RUID,
    PIDS_ID_RGID,
    PIDS_ID_SESSION,
    PIDS_ID_TGID,
    PIDS_TIME_START,
    PIDS_TTY_NAME,
    PIDS_CMD,
    PIDS_CMDLINE,
    PIDS_STATE,
    PIDS_TIME_ELAPSED,
    PIDS_CGROUP_V
};

enum rel_items {
    EU_PID, EU_PPID, EU_PGRP, EU_EUID, EU_RUID, EU_RGID, EU_SESSION,
    EU_TGID, EU_STARTTIME, EU_TTYNAME, EU_CMD, EU_CMDLINE, EU_STA, EU_ELAPSED,
    EU_CGROUP
};

static void parse_opts (int argc, char **argv)
{
    char opts[64] = "";
    int opt;
    int criteria_count = 0;
    static const struct option longopts[] = {
        {NULL, 0, NULL, 0}
    };

    strcat (opts, "lad:vw");
    strcat (opts, "LF:cfinoxP:O:g:s:u:U:G:t:r:?Vh");

    if (argc - optind == 1)
        opt_pattern = argv[optind];

    else if (argc - optind > 1)
        xerrx(EXIT_USAGE, _("only one pattern can be provided\n"
                     "Try `%s --help' for more information."),
                     program_invocation_short_name);
}

static size_t get_arg_max(void)
{
#define MIN_ARG_SIZE 4096u
#define MAX_ARG_SIZE (128u * 1024u)

    size_t val = sysconf(_SC_ARG_MAX);

    if (val < MIN_ARG_SIZE)
       val = MIN_ARG_SIZE;
    if (val > MAX_ARG_SIZE)
       val = MAX_ARG_SIZE;

    return val;
}

static regex_t * do_regcomp (void)
{
    regex_t *preg = NULL;

    if (opt_pattern) {
        char *re;
        char errbuf[256];
        int re_err;

        preg = xmalloc (sizeof (regex_t));
        re = opt_pattern;

        re_err = regcomp (preg, re, REG_EXTENDED | REG_NOSUB);

        if (re_err) {
            regerror (re_err, preg, errbuf, sizeof(errbuf));
            xerrx(EXIT_USAGE, _("regex error: %s"), errbuf);
        }
    }
    return preg;
}

static struct el * select_procs (int *num)
{
#define PIDS_GETINT(e) PIDS_VAL(EU_ ## e, s_int, stack, info)
#define PIDS_GETUNT(e) PIDS_VAL(EU_ ## e, u_int, stack, info)
#define PIDS_GETULL(e) PIDS_VAL(EU_ ## e, ull_int, stack, info)
#define PIDS_GETSTR(e) PIDS_VAL(EU_ ## e, str, stack, info)
#define PIDS_GETSCH(e) PIDS_VAL(EU_ ## e, s_ch, stack, info)
#define PIDS_GETSTV(e) PIDS_VAL(EU_ ## e, strv, stack, info)
    struct pids_info *info=NULL;
    struct procps_ns nsp;
    struct pids_stack *stack;
    unsigned long long saved_start_time;      /* for new/old support */
    int saved_pid = 0;                        /* for new/old support */
    int matches = 0;
    int size = 0;
    regex_t *preg;
    pid_t myself = getpid();
    struct el *list = NULL;
    long cmdlen = get_arg_max() * sizeof(char);
    char *cmdline = xmalloc(cmdlen);
    char *cmdsearch = xmalloc(cmdlen);
    char *cmdoutput = xmalloc(cmdlen);
    char *task_cmdline;
    enum pids_fetch_type which;

    preg = do_regcomp();

    saved_start_time = ~0ULL;

    if (procps_pids_new(&info, Items, 15) < 0)
        xerrx(EXIT_FATAL,
              _("Unable to create pid info structure"));
    which = PIDS_FETCH_TASKS_ONLY;

    while ((stack = procps_pids_get(info, which))) {
        int match = 1;

        if (PIDS_GETINT(PID) == myself)
            continue;

        task_cmdline = PIDS_GETSTR(CMDLINE);

        if (match && opt_pattern) {
            strncpy (cmdoutput, PIDS_GETSTR(CMD), cmdlen -1);
            cmdoutput[cmdlen - 1] = '\0';
            strncpy (cmdsearch, PIDS_GETSTR(CMD), cmdlen -1);
            cmdsearch[cmdlen - 1] = '\0';
            if (regexec (preg, cmdsearch, 0, NULL, 0) != 0)
                match = 0;
        }

        if (match ^ 0) {    /* Exclusive OR is neat */
            if (matches == size) {
				grow_size(size);
                list = xrealloc(list, size * sizeof *list);
            }
            if (list) {
                list[matches++].num = PIDS_GETINT(PID);
            } else {
                xerrx(EXIT_FATAL, _("internal error"));
            }
        }
    }
    procps_pids_unref(&info);
    free(cmdline);
    free(cmdsearch);
    free(cmdoutput);

    if (preg) {
        regfree(preg);
        free(preg);
    }

    *num = matches;

    if ((!matches) && opt_pattern && (strlen(opt_pattern) > 15))
        xwarnx(_("pattern that searches for process name longer than 15 characters will result in zero matches\n"
                 "Try `%s -f' option to match against the complete command line."),
               program_invocation_short_name);
    return list;
#undef PIDS_GETINT
#undef PIDS_GETUNT
#undef PIDS_GETULL
#undef PIDS_GETSTR
#undef PIDS_GETSTV
}

static void output_numlist (const struct el *restrict list, int num)
{
    int i;
    const char *delim = opt_delim;
    for (i = 0; i < num; i++) {
        if(i+1==num)
            delim = "\n";
        printf ("%ld%s", list[i].num, delim);
    }
}


int main(int argc, char **argv)
{
	char *basename;
	int color = 0;

	drop_cap();

	basename = strrchr(argv[0], '/');
	if (basename == NULL)
		basename = argv[0];
	else
		basename++;

	_SL_ = oneline ? "\\" : "\n";

	check_enable_color(color, json);

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	rtnl_set_strict_dump(&rth);
	printf("do exec\n");
	if(argc==2&&strcmp(argv[1],ANOTHER_KEY)!=0){
		struct el *procs;
    	int num;

    	setlocale (LC_ALL, "");
    	bindtextdomain(PACKAGE, LOCALEDIR);
    	textdomain(PACKAGE);
    	atexit(close_stdout);

		parse_opts (argc, argv);

    	procs = select_procs (&num);
    
    	output_numlist (procs,num);
		
		get_vnic(argv[1]);
	}
	else if(argc!=2&&strcmp(argv[1],ANOTHER_KEY)==0) coll_name(argv);
	else printf("No command\n"); 

	return 0;
	rtnl_close(&rth);
	usage();
}

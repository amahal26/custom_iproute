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
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <limits.h>
#include <ctype.h>
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
char pid_list[1024][100];
char integer[10]={0,1,2,3,4,5,6,7,8,9};

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

void separate_enter(char *s){
	char *p=s;
	p=strstr(s,"\n");
	if(p!=NULL){
		strcpy(p,p+strlen("\n"));
	}
}

void separate_space(char *s){
	char *p=s;
	p=strstr(s," ");
	if(p!=NULL){
		strcpy(p,p+strlen(" "));
		separate_space(p+1);
	}
}

char* separate_ps(char *s){
	char *p=s;
	char pid[100];
	int i=0;
	bool id=false;
	bool end=false;
	while(end==false){
		if((id==false)&&(p==' ')) continue;
		else if((id==true)&&(end=true)) break;
		else id=true;
		for(int j=0; j<10; j++){
			if(p==integer[j]){
				pid[i]=p;
				i++;
				p+1;
				break;
			}
		}
		end=true;
	}
	return pid;
}

pid_t Fork(void){
	pid_t	pid;

	pid = fork ();
	if (-1 == pid){
		perror("can not fork");
	}
	return pid;
}

int make_pidlist(void){
	FILE *fp;
	char *cmdline="pgrep envoy";
	if((fp=popen(cmdline,"r"))==NULL){
		perror("Searching pid command fail");
		exit(EXIT_FAILURE);
	}
	int i=0;
	char tmp[1024][100];
	while(!feof(fp)){
		fgets(tmp[i], sizeof(tmp[i]), fp);
		separate_enter(tmp[i]);
		separate_space(tmp[i]);
		i++;
	}
	(void) pclose(fp);

	for(int j=0; j<i-1; j++){
		strcpy(pid_list[j],tmp[i-j+1]);
	}
	i--;

	return i;
}

int make_pidlist_ps(void){
	FILE *fp;
	char *cmdline="ps h -A";
	if((fp=popen(cmdline,"r"))==NULL){
		perror("Searching pid command fail");
		exit(EXIT_FAILURE);
	}
	int i=0;
	char tmp[1024][100];
	while(!feof(fp)){
		fgets(tmp[i], sizeof(tmp[i]), fp);
		strcpy(pid_list[i],separate_ps(tmp[i]));
		i++;
	}
	(void) pclose(fp);

	i--;

	return i;
}

void seach_vnic(int count, char *ipaddr){
    int i=0;
    for (i=0; i<count; ++i){
        pid_t pid=Fork();
        if(pid==-1) break;
        else if(pid==0){
            if(get_vnic(pid_list[i], ipaddr)==-1) exit(EXIT_FAILURE);
	        exit (EXIT_SUCCESS);
        }
        else{
            int status=0;
            pid=wait(&status);
			if(status==EXIT_SUCCESS) return;
            }
    }
}

int main(int argc, char **argv)
{
	struct timespec tsStart, tsEnd;
	
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

	if(argc==2){
		timespec_get(&tsStart, TIME_UTC);

		//int pidnum=make_pidlist();
		int pidnum=make_pidlist_ps();
		seach_vnic(pidnum, argv[1]);
	}
	else if(strcmp(argv[1],ANOTHER_KEY)==0){
		if(coll_name(argv)==-1) return -1;
		else return 0;
	} 
	else printf("No command\n"); 
	
	timespec_get(&tsEnd, TIME_UTC);
    int nsec = tsEnd.tv_nsec - tsStart.tv_nsec;
    int secSpan = tsEnd.tv_sec - tsStart.tv_sec;
    if(0 < secSpan){
    	nsec += secSpan * 1000000000;
    }
	printf("%d\n", nsec);
	rtnl_close(&rth);

	return 0;
}

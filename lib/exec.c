/* SPDX-License-Identifier: GPL-2.0 */
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"
#include "namespace.h"

int cmd_exec(const char *cmd, char **argv, bool do_fork,
	     int (*setup)(void *), void *arg)
{
	fflush(stdout);

	if (setup && setup(arg))
		return -1;
	
	if (execvp(cmd, argv)  < 0) return -1;
	_exit(1);
}

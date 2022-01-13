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
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	if (pid != 0) {
		int status=0;
		pid=wait(&status);
		exit(1);
	}
	else {
		if (setup && setup(arg))
		return -1;
		if (execvp(cmd, argv)  < 0)
			fprintf(stderr, "exec of \"%s\" failed: %s\n",cmd, strerror(errno));
		exit (EXIT_SUCCESS);
	}
	_exit(1);
}

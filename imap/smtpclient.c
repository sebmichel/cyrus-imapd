/* smtpclient.c -- Routines for sending a message via SMTP
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: smtpclient.c,v 1.4 2010/01/06 17:01:40 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "global.h"
#include "exitcodes.h"
#include "imap/imap_err.h"
#include "smtpclient.h"

extern void fatal(const char *buf, int code);

pid_t open_sendmail(const char *argv[], FILE *sm[2])
{
    int fds_in[2];
    int fds_out[2];
    int fdflags;
    pid_t p;

    sm[0] = 0;
    sm[1] = 0;

    if (pipe(fds_in) || pipe(fds_out)) {
	syslog(LOG_ERR, "IOERROR: creating pipes: %m");
	fatal("couldn't start pipe()", EC_OSERR);
    }

    /* put us in non-blocking mode; this should allow the sendmail process
     * to write on stdout/stderr without blocking - getting an error instead.
     * This should also prevent any deadlock due to pipe buffer sizes between
     * us writing the message and sendmail writing back upon issue.
     */
    fdflags = fcntl(fds_out[1], F_GETFD, 0);
    if (fdflags != -1) {
	fdflags = fcntl(fds_out[1], F_SETFL, O_NONBLOCK | fdflags);
    }
    if (fdflags == -1) {
	syslog(LOG_ERR, "IOERROR: setting non-blocking mode for sendmail pipe: %m");
    }

    if ((p = fork()) == 0) {
	/* i'm the child! run sendmail! */
	close(fds_in[1]);
	close(fds_out[0]);
	/* make the pipes be stdin/stdout/stderr */
	dup2(fds_in[0], 0);
	dup2(fds_out[1], 1);
	dup2(fds_out[1], 2);
	execv(config_getstring(IMAPOPT_SENDMAIL), (char **) argv);

	/* if we're here we suck */

	/* use printf so that message appears in Sendmail failure log */
	printf("exec() sendmail failed: %m\n");
	exit(EXIT_FAILURE);
    }

    if (p < 0) {
	/* failure */
	close(fds_in[0]);
	close(fds_in[1]);
	close(fds_out[0]);
	close(fds_out[1]);
	return p;
    }

    /* parent */
    close(fds_in[0]);
    close(fds_out[1]);
    if ((sm[0] = fdopen(fds_in[1], "w")) != NULL) {
	sm[1] = fdopen(fds_out[0], "r");
    }
    else {
	close(fds_in[0]);
	close(fds_out[1]);
    }

    return p;
}

void close_sendmail(pid_t sm_pid, FILE *sm[2], int *sm_stat)
{
    struct buf output = BUF_INITIALIZER;

    fclose(sm[0]);

    if (sm[1]) {
	/* read some output from child if any, will be used upon failure */
	char buffer[256];
	size_t count;
	size_t actual;

	/* 1KiB should be enough to assess the situation */
	for (;;) {
	    count = 1024 - buf_len(&output);
	    if (count == 0) {
		break;
	    }
	    else if (count > sizeof(buffer)) {
		count = sizeof(buffer);
	    }

	    actual = fread(buffer, 1, count, sm[1]);
	    if (actual <= 0) {
		break;
	    }

	    buf_appendmap(&output, buffer, actual);
	}

	fclose(sm[1]);
    }

    sm[0] = 0;
    sm[1] = 0;

    while (waitpid(sm_pid, sm_stat, 0) < 0);

    if (sm_stat) {
	/* something went wrong, log output if any */
	if (buf_len(&output)) {
	    syslog(LOG_ERR, "Sendmail process failed with output: (%zu bytes) %s",
		buf_len(&output), buf_cstring(&output));
	}
	else {
	    syslog(LOG_ERR, "Sendmail process failed with no output");
	}
    }
}

/* sendmail_errstr.  create a descriptive message given 'sm_stat': 
   the exit code from wait() from sendmail.

   not thread safe, but probably ok */
char *sendmail_errstr(int sm_stat)
{
    static char errstr[200];

    if (WIFEXITED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process terminated normally, exit status %d\n",
		 WEXITSTATUS(sm_stat));
    } else if (WIFSIGNALED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		"Sendmail process terminated abnormally, signal = %d %s\n",
		WTERMSIG(sm_stat),
#ifdef WCOREDUMP
		WCOREDUMP(sm_stat) ? " -- core file generated" :
#endif
		"");
    } else if (WIFSTOPPED(sm_stat)) {
	snprintf(errstr, sizeof errstr,
		 "Sendmail process stopped, signal = %d\n",
		WTERMSIG(sm_stat));
    } else {
	return NULL;
    }
    
    return errstr;
}

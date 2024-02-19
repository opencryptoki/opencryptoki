/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#if defined(_AIX)
#include <stdio.h>
#include <sys/procfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/* program_invocation_short_name is GNU extension */
char program_invocation_short_name[256 + 1] = { NULL, };

void populate_progname(void) {
    struct psinfo ps;
    int psfd;

    snprintf(program_invocation_short_name, 256, "/proc/%lld/psinfo", getpid());
    psfd = open(program_invocation_short_name, O_RDONLY);
    if (psfd == -1) {
        fprintf(stderr,
            "Failed to open procfs to read cmdname: %s\n", strerror(errno));
        return;
    }

    if (read(psfd, &ps, sizeof(ps)) == -1) {
        fprintf(stderr, "Failed to populate psinfo: %s\n", strerror(errno));
        return;
    }
    close(psfd);
    strncpy(program_invocation_short_name, ps.pr_fname, PRFNSZ);
}
#endif

/*
 * Portions Copyright (c) 1987, 1993, 1994
 * The Regents of the University of California.  All rights reserved.
 *
 * Portions Copyright (c) 2003-2022, PostgreSQL Global Development Group
 */

/* This code is only used on AIX; Linux uses its own glibc implementation */
#ifndef GETOPT_EXT_H
#define GETOPT_EXT_H

/* getopt is provided by unistd, according to POSIX */
#include <unistd.h>

struct option
{
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

int	getopt_long(int argc, char *const argv[], const char *optstring,
						const struct option *longopts, int *longindex);

#endif /* GETOPT_EXT_H */

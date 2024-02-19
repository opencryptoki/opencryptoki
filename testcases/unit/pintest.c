/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pin_prompt.h>
#include "unittest.h"

int main(int argc, char *argv[])
{
	const char *pin;
	char *buf = NULL;

	switch(getopt(argc, argv, "pn")) {
	case 'p':
		pin = pin_prompt(&buf, "Enter the PIN: ");
		/* AIX prints an empty string instead of Linux-style (null) */
		printf("pin: %s\n", pin != NULL ? pin : "(null)");
		break;
	case 'n':
		pin = pin_prompt_new(&buf, "Enter new PIN: ", "Re-enter new PIN: ");
		printf("pin: %s\n", pin != NULL ? pin : "(null)");
		break;
	default:
		break;
	}

	pin_free(&buf);
	return 0;
}

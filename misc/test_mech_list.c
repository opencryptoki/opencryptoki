/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/**
 * This is something like what you can expect openCryptoki to do when
 * it requests a mechanism list from your library.
 */

#include <stdio.h>
#include "mech_types.h"

extern void generate_pkcs11_mech_list(struct mech_list *head);

int main(int argc, char *argv[])
{
	struct mech_list head;
	struct mech_list *item;
	generate_pkcs11_mech_list(&head);
	item = head.next;
	while (item) {
		struct mech_list *next;
		next = item->next;
		printf("Mechanism type: [%.8x]\n", item->element.mech_type);
		free(item);
		item = next;
	}
}

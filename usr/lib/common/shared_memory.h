/*
 * COPYRIGHT (c) International Business Machines Corp. 2012-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki ICSF token - Shared memory abstraction for OpenCryptoki
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 * Note: the functions in this files are implemented as an abstraction layer for
 *    POSIX shared memory functions but they can be extended to support other
 *    APIs of shared memory.
 */

#ifndef OCK_SHARED_MEMORY_H
#define OCK_SHARED_MEMORY_H

#include <limits.h>

#define SM_NAME_LEN (NAME_MAX)


int sm_open(const char *sm_name, int mode, void **p_addr, size_t len,
            int force, const char *group);

int sm_close(void *addr, int destroy, int ignore_ref_count);

int sm_destroy(const char *name);

int sm_sync(void *addr);

int sm_copy_name(void *addr, char *buffer, size_t len);

int sm_get_count(void *addr);

#endif

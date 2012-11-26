/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token - Shared memory abstraction for OpenCryptoki
 *
 * (C) COPYRIGHT International Business Machines Corp. 2012
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 * Note: the functions in this files are implemented as an abstraction layer for
 *  	 POSIX shared memory functions but they can be extended to support other
 *  	 APIs of shared memory.
 */
#ifndef OCK_SHARED_MEMORY_H
#define OCK_SHARED_MEMORY_H

#include <limits.h>

#define SM_NAME_LEN (NAME_MAX)


int
sm_open(const char *sm_name, int mode, void **p_addr, size_t len, int force);

int
sm_close(void *addr, int destroy);

int
sm_destroy(const char *name);

int
sm_sync(void *addr);

int
sm_copy_name(void *addr, char *buffer, size_t len);

int
sm_get_count(void *addr);

#endif

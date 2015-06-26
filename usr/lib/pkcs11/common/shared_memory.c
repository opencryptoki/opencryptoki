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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>

/* For logging functions: */
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

#include "shared_memory.h"

/*
 * Helper macros for logging.
 */
#define SYS_ERROR(_errno, _msg, ...)					\
	do {								\
		char _sys_error[1024];					\
		if (strerror_r(_errno, _sys_error, sizeof(_sys_error)))	\
			strcpy(_sys_error, "Unknown error");		\
		syslog(LOG_ERR, "Error: " _msg " %s (errno=%d)",	\
			##__VA_ARGS__, _sys_error, _errno);		\
		TRACE_ERROR("Error: " _msg " %s (errno=%d)",		\
			##__VA_ARGS__, _sys_error, _errno);		\
	} while (0)

/*
 * Shared context used to keep meta data into the shared memory.
 *
 * The address to data field is the address visible outside this file.
 *
 * See shm_open for more details.
 */
struct shm_context {
	/*
	 * `ref` is a counter that is used to detect mismatching between
	 * sm_open and sm_close calls.
	 */
	int ref;

	/*
	 * `name` is the shared memory identifier and it is used to destroy
	 * an allocated shared memory region.
	 */
	char name[SM_NAME_LEN + 1];

	/*
	 * `data_len` is the length of the variable length filed `data`.
	 */
	int data_len;

	/*
	 * `data` points to the region that will actually be used by
	 * `sm_open`s caller.
	 */
	char data[];
};

/*
 * Obtain the context pointer based on a data address.
 */
static inline struct shm_context *
get_shm_context(void *addr)
{
	struct shm_context *ctx = addr - offsetof(struct shm_context, data);
	return ctx;
}

/*
 * If a complete path is informed, convert it to a shared memory name.
 */
static char *
convert_path_to_shm_name(const char *file_path)
{
	char *name = NULL;
	size_t len = strlen(file_path) + 1;
	int i;
	char *it;

	/* Need a starting '/' */
	if (file_path[0] != '/')
		len++;

	if (len > SM_NAME_LEN) {
		TRACE_ERROR("Error: path \"%s\" too long.\n", file_path);
		return NULL;
	}

	it = name = malloc(len + 1);
	if (name == NULL) {
		TRACE_ERROR("Error: failed to allocate memory for "
				"path \"%s\".\n", file_path);
		return NULL;
	}

	i = 0;
	*it++ = '/';
	if (file_path[0] == '/')
		i++;

	for (; file_path[i]; i++, it++) {
		if (file_path[i] == '/')
			*it = '.';
		else
			*it = file_path[i];
	}
	*it = '\0';

	TRACE_DEVEL("File path \"%s\" converted to \"%s\".\n",
		      file_path, name);
	return name;
}

/*
 * Open a shared memory region identified by `sm_name` using permissions defined
 * by `mode` with length `len`.
 *
 * If the shared memory already exists and doesn't match the given length an
 * error is returned (if `force` is zero) or the shared memory is reinitialized
 * (if `force` is non zero).
 */
int
sm_open(const char *sm_name, int mode, void **p_addr, size_t len, int force)
{
	int rc;
	int fd = -1;
	void *addr = NULL;
	struct stat stat_buf;
	char *name = NULL;
	struct shm_context *ctx = NULL;
	size_t real_len = sizeof(*ctx) + len;
	int created = 0;

	/*
	 * This is used for portability purpose. Please check `shm_open`
	 * man page for more details.
	 */
	if ((name = convert_path_to_shm_name(sm_name)) == NULL) {
		rc = -EINVAL;
		goto done;
	}

	/* try and open first... */
	fd = shm_open(name, O_RDWR, mode);
	if (fd < 0) {
		/* maybe it needs to be created ... */
		fd = shm_open(name, O_RDWR | O_CREAT, mode);
		if (fd < 0) {
			rc = -errno;
			SYS_ERROR(errno,
				  "Failed to open shared memory \"%s\".\n",
				  name);
			goto done;
		} else {
			/* umask may have altered permissions if we created
			 * the shared memory in above call, so set proper
			 * permissions just in case.
			 */
			if (fchmod(fd, mode) == -1) {
				rc = -errno;
				SYS_ERROR(errno, "fchmod(%s): %s\n",
						name, strerror(errno));
				goto done;
			}
		}
	}

	/*
	 * fstat is used here to check if the shared memory region already
	 * exists. When a shared memory region is first created, its size is
	 * always zero.
	 */
	if (fstat(fd, &stat_buf)) {
		rc = -errno;
		SYS_ERROR(errno, "Cannot stat \"%s\".\n", name);
		goto done;
	}

	/*
	 * The shared memory needs to be extended when created (when its length
	 * is zero). When its length is not zero and is not equal to the
	 * expected size, an error is returned if `force` is not set. If `force`
	 * is set, the existing shared memory is truncated and any data on it is
	 * lost.
	 */
	if (stat_buf.st_size == 0 || (force && stat_buf.st_size != real_len)) {
		/*
		 * If the shared memory region was just created, it's necessary
		 * to extend it to the expected size using ftruncate.
		 *
		 * It's important to notice that it is resized to a length
		 * greater than the value requested (`len`). The extra space is
		 * used to store additional information related to the shared
		 * memory, such as its size and identifier.
		 */
		created = 1;
		TRACE_DEVEL("Truncating \"%s\".\n", name);
		if (ftruncate(fd, real_len) < 0) {
			rc = -errno;
			SYS_ERROR(errno, "Cannot truncate \"%s\".\n", name);
			goto done;
		}
	} else if (stat_buf.st_size != real_len) {
		rc = -1;
		TRACE_ERROR("Error: shared memory \"%s\" exists and does not "
				"match the expected size.\n", name);
		goto done;
	}

	addr = mmap(NULL, real_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == NULL) {
		rc = -errno;
		SYS_ERROR(errno, "Failed to map \"%s\" to memory.\n", name);
		goto done;
	}

	/*
	 * `addr` points to the start of the shared memory region. The first
	 * bytes of it are used to store the additional information about the
	 * shared memory allocated. This info can be accessed using an pointer
	 * to a `shm_context` structure.
	 */
	ctx = addr;
	if (created) {
		strcpy(ctx->name, name);
		ctx->data_len = len;
		memset(ctx->data, 0, ctx->data_len);
	}
	ctx->ref += 1;

	/*
	 * The portion of the shared memory that will actually be used by the
	 * called is pointed by `data`.
	 *
	 * The address returned (in this case `ctx->data`) is equal to
	 * `addr + sizeof(struct shm_context)`, which means that the additional
	 * data is skipped off.
	 */
	*p_addr = ctx->data;
	rc = created ? 0 : 1;
	if (sm_sync(ctx->data)) {
		rc = -errno;
		SYS_ERROR(errno, "Failed to sync shared memory \"%s\".\n",
				name);
		if (created)
			sm_close(addr, 1);
		goto done;
	}
	TRACE_DEVEL("open: ref = %d\n", ctx->ref);

done:
	if (fd >= 0)
		close(fd);
	if (name)
		free(name);
	return rc;
}

/*
 * Close (unmap) a shared memory region. `destroy` indicates if the shared
 * memory should be destroyed if no other processes are using it.
 */
int
sm_close(void *addr, int destroy)
{
	int rc;
	int ref;
	char name[SM_NAME_LEN + 1] = { 0, };
	struct shm_context *ctx = get_shm_context(addr);

	if (ctx->ref <= 0) {
		TRACE_ERROR("Error: invalid shared memory address %p "
				"(ref=%d).\n", addr, ctx->ref);
		return -EINVAL;
	}

	ref = --ctx->ref;
	TRACE_DEVEL("close: ref = %d\n", ref);
	if (ref == 0 && destroy) {
		strncpy(name, ctx->name, SM_NAME_LEN);
		name[SM_NAME_LEN] = '\0';
	}

	if (munmap(ctx, sizeof(*ctx) + ctx->data_len)) {
		rc = -errno;
		SYS_ERROR(errno, "Failed to unmap \"%s\" (%p).\n", name, ctx);
		return rc;
	}

	if (ref == 0 && destroy) {
		TRACE_DEVEL("Deleting shared memory \"%s\".\n", name);
		if ((rc = sm_destroy(name)) != 0)
			return rc;
	}

	return 0;
}

/*
 * Destroy a shared memory region.
 */
int
sm_destroy(const char *name)
{
	int rc;

	if (shm_unlink(name)) {
		rc = -errno;
		SYS_ERROR(errno, "Failed to delete shared memory \"%s\".\n",
			  name);
		return rc;
	}

	return 0;
}

/*
 * Force sync for a shared memory region.
 */
int
sm_sync(void *addr)
{
	struct shm_context *ctx = get_shm_context(addr);

	if (ctx->ref <= 0) {
		TRACE_ERROR("Error: invalid shared memory address %p "
				"(ref=%d).\n", addr, ctx->ref);
		return -EINVAL;
	}

	return msync(ctx, ctx->data_len, MS_SYNC);
}

/*
 * Get the name of the shared memory indicated by `addr` and copy it to the
 * given `buffer`.
 */
int
sm_copy_name(void *addr, char *buffer, size_t len)
{
	size_t name_len;
	struct shm_context *ctx = get_shm_context(addr);

	if (ctx->ref <= 0) {
		TRACE_ERROR("Error: invalid shared memory address %p "
				"(ref=%d).\n", addr, ctx->ref);
		return -EINVAL;
	}

	name_len = strlen(ctx->name);
	if (len <= name_len)
		return -ENOSPC;

	strcpy(buffer, ctx->name);
	return 0;
}

/*
 * Return the reference count for the given shared memory.
 */
int
sm_get_count(void *addr)
{
	struct shm_context *ctx = get_shm_context(addr);

	if (ctx->ref <= 0) {
		TRACE_ERROR("Error: invalid shared memory address %p "
				"(ref=%d).\n", addr, ctx->ref);
		return -EINVAL;
	}

	return ctx->ref;
}

/* This files contains ssh-servd memory managment functions */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define	LOG_MODULE_NAME		"SSH Server"

#include "log.h"

void	*memalloc(size_t size) {

	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL)
		serv_log_fatal("Failed to allocate memory! Requested size is %u bytes. malloc(): %s", size, strerror(errno));

	memset(ptr, 0, size);

	return ptr;
}

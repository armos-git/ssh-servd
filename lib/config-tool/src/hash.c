#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "hash.h"
#include "llist.h"

#ifdef __OpenBSD__
  #ifdef NULL
    #undef NULL
    #define NULL	((void *)0)
  #endif
#endif

/* memory allocation wraper calls */
#define _memalloc(size)         __memalloc(size, __LINE__)
static  void    *__memalloc(size_t size, unsigned int line) {

        void *p;

        p = malloc(size);
        if (p == NULL) {
                fprintf(stderr, "%s:%d - %s\n", __FILE__, line, strerror(errno));
                exit(EXIT_FAILURE);
        }    

        return p;
}

unsigned int	__hash_code(const char *str, unsigned int hash_size) {

	int i = 0;
	unsigned int hash = 1;

	while (str[i]) {
		hash = hash * 31 + str[i];
		i++;
	}

	return hash % hash_size;
}

void	__hash_init(void ***htable, unsigned int hash_size) {

	int i;
	void **ptr;

	ptr = _memalloc(sizeof(void *[hash_size]));
	*htable = ptr;

	for (i = 0; i < hash_size; i++)
		ptr[i] = NULL;
}

void	__hash_add(void **htable, unsigned int hash_size, const char *str, void *data, unsigned int size) {

	unsigned int h;

	h = __hash_code(str, hash_size);

	if (htable[h] == NULL) {
		htable[h] = _memalloc(sizeof(llist_t));
		llist_init(htable[h]);
	}

	llist_add(htable[h], data, size);

}

void	*__hash_find(void **htable, unsigned int hash_size, const char *str) {

	unsigned int h;
	void *ptr;

	h = __hash_code(str, hash_size);

	ptr = htable[h];

	return ptr;
}

void	__hash_destroy(void **htable) {

	free(htable);
}

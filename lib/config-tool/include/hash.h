#ifndef	__CONFIG_HASH_H
#define	__CONFIG_HASH_H		1


extern	unsigned int    __hash_code(const char *str, unsigned int hash_size);

extern	void     __hash_init(void ***htable, unsigned int hash_size);

extern	void    __hash_add(void **htable, unsigned int hash_size, const char *str, void *data, unsigned int size);

extern	void    *__hash_find(void **htable, unsigned int hash_size, const char *str);

extern	void    __hash_destroy(void **htable);


#endif

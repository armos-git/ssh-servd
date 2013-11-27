#ifndef SHELL_MODULE_H
#define SHELL_MODULE_H

typedef struct {

	const char *ip_addr;
	void (*shell_write)(void *data, unsigned int len);
	void (*shell_read)(void *data, unsigned int len);
	void (*shell_exit)(void);

} shell_callbacks_t;

#endif /* SHELL_MODULE_H */

#ifndef SHELL_MODULE_H
#define SHELL_MODULE_H

typedef struct {

	const char *ip_addr;
	const char *uname;
	void (*shell_write)(void *data, unsigned int len);
	void (*shell_read)(void *data, unsigned int len);
	int  (*shell_log)(int type, const char *module, const char *msg, ...);
	void (*shell_exit)(void);

} shell_callbacks_t;

#endif /* SHELL_MODULE_H */

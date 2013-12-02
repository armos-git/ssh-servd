#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "shell_module.h"


static	void	(*shell_write)(void *data, unsigned int len);
static	int  	(*shell_log)(int type, const char *module, const char *msg, ...);
static	void	(*shell_exit)(void);
static	void	shell_read(void *data, unsigned int len);

const	static	char 	*ip_addr;
const	static	char 	*username;
static	unsigned int 	level;


void	shell_init(shell_callbacks_t *cb) {

	cb->shell_read = &shell_read;
	shell_write = cb->shell_write;
	shell_log = cb->shell_log;
	shell_exit = cb->shell_exit;
	ip_addr = cb->ip_addr;
	username = cb->uname;
	level = cb->level;
}

void	shell_printf(const char *format, ...) {

	va_list ap;
	char *buf = alloca(4096);

	va_start(ap, format);
	vsnprintf(buf, 4096, format, ap);
	va_end(ap);

	shell_write((void *)buf, strlen(buf));
}

void	shell_read(void *data, unsigned int len) {

	char *buf = data;

	shell_log(0, "Shell", "Hello!");

	switch (buf[0]) {

	  case 'q':
		shell_exit();
	  case 0xd:
		shell_write("\r\n", 2);
		break;
	  default:
		shell_printf("user %s : ip %s : level %u says: %.*s\r\n", username, ip_addr, level, len, data);
		break;
	}
}

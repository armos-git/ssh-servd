#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shell_module.h"


static	void	(*shell_write)(void *data, unsigned int len);
static	int  	(*shell_log)(int type, const char *module, const char *msg, ...);
static	void	(*shell_exit)(void);
static	void	shell_read(void *data, unsigned int len);

const	static	char *ip_addr;
const	static	char *username;


void	shell_init(shell_callbacks_t *cb) {

	cb->shell_read = &shell_read;
	shell_write = cb->shell_write;
	shell_log = cb->shell_log;
	shell_exit = cb->shell_exit;
	ip_addr = cb->ip_addr;
	username = cb->uname;
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
		shell_write(ip_addr, strlen(ip_addr));
		shell_write(" ", 1);
		shell_write(username, strlen(username));
		shell_write(": ", 2);
		shell_write(data, len);
		shell_write("\r\n", 2);
		break;
	}
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shell_module.h"


void	(*shell_write)(void *data, unsigned int len);
void	(*shell_exit)(void);
void	shell_read(void *data, unsigned int len);

const	char *ip_addr;

void	shell_init(shell_callbacks_t *cb) {

	cb->shell_read = &shell_read;
	shell_write = cb->shell_write;
	shell_exit = cb->shell_exit;
	ip_addr = cb->ip_addr;
}

void	shell_read(void *data, unsigned int len) {

	char *buf = data;

	switch (buf[0]) {

	  case 'q':
		shell_exit();
	  case 0xd:
		shell_write("\r\n", 2);
		break;
	  default:
		shell_write(ip_addr, strlen(ip_addr));
		shell_write(": ", 2);
		shell_write(data, len);
		shell_write("\r\n", 2);
		break;
	}
}

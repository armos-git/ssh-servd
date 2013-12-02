#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "shell_module.h"

void	shell_init(shell_callbacks_t *cb) {

	SHELL_INIT_GLOBALS(cb)
	shell_log("Shell", "Example shell says hello!");
}


void	shell_read(void *data, unsigned int len) {

	char *buf = data;

	switch (buf[0]) {

	  case 'q':
		shell_log("Shell", "%s logout", username);
		shell_exit();
	  case 0xd:
		shell_printf("\n\r");
		break;
	  default:
		shell_printf("user %s : ip %s : level %u says: %.*s\r\n", username, ip_addr, level, len, data);
		break;
	}
}

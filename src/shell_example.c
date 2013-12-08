#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "shell_module.h"


/* Shell side interface functions prototypes */
void	shell_read(void *data, uint32_t len);
void	shell_change_window_size(int x, int y, int px, int py);


void	shell_init(shell_callbacks_t *cb) {

	SHELL_INIT_GLOBALS(cb)
	shell_log("Shell", "Example shell says hello!");
	shell_printf("Welcome\r\nterminal x, y: %i, %i\r\n", shell_info.x, shell_info.y);
}

void	shell_read(void *data, uint32_t len) {

	char *buf = data;

	switch (buf[0]) {

	  case 'q':
		shell_log("Shell", "%s logout", username);
		shell_exit();
	  case 0xd:
		shell_printf("\n\r");
		break;
	  default:
		shell_printf("user %s : ip %s : level %u says: %.*s\r\n", username, user_ipaddr, userlevel, len, data);
		break;
	}
}

void	shell_change_window_size(int x, int y, int px, int py) {

	shell_printf("%i %i %i %i\r\n", x, y, px, py);
}

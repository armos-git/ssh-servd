#ifndef SHELL_MODULE_H
#define SHELL_MODULE_H

#include <stdint.h>

struct	shell_info_struct {

	int x;
	int y;
	int px;
	int py;
};

/* shell callbacks struct */
typedef struct {

	const char			*ip_addr;
	const char			*uname;
	unsigned int			level;
	struct shell_info_struct	shell_info;
	void				(*shell_write)(void *data, uint32_t len);
	void				(*shell_printf)(unsigned int buflen, const char *format, ...);
	void				(*shell_read)(void *data, uint32_t len);
	void				(*shell_change_window_size)(int x, int y, int px, int py);
	int				(*shell_log)(int type, const char *module, const char *msg, ...);
	void				(*shell_exit)(void);

} shell_callbacks_t;


/* check to see if it is included in server or in shell module */
#ifndef HANDLE_USER_H

#include <string.h>

/* shell_printf() buffer size */
#define DEFAULT_SHELL_PRINTF_BUF_SIZE		4096


enum LOG_TYPES {
	LOG_MSG,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
};


/* Gloabal variables */
const	static	char 			*user_ipaddr;
const	static	char		 	*username;
static	unsigned int 			userlevel;
static	unsigned int			shell_printf_buf_len;
static	struct	shell_info_struct	shell_info;


/* Sets up all external and global objects according to data in cb  */
#define SHELL_INIT_GLOBALS(cb) \
	memcpy(&shell_info, &cb->shell_info, sizeof(struct shell_info_struct)); \
	cb->shell_read = &shell_read; \
	cb->shell_change_window_size = &shell_change_window_size; \
	shell_write = cb->shell_write; \
	__shell_printf = cb->shell_printf; \
	__shell_log = cb->shell_log; \
	shell_exit = cb->shell_exit; \
	user_ipaddr = cb->ip_addr; \
	username = cb->uname; \
	userlevel = cb->level; \
	shell_printf_buf_len = DEFAULT_SHELL_PRINTF_BUF_SIZE;


/* External functions */

/* Writes data to server */
static	void		(*shell_write)(void *data, uint32_t len);


/* Shell printf wrapper function */
#define			shell_printf(fmt...)			__shell_printf(shell_printf_buf_len, fmt)
static	void		(*__shell_printf)(unsigned int buflen, const char *format, ...);


/* Shell log wrapper functions */
#define			shell_log(module, msg...)		__shell_log(LOG_MSG, module, msg)
#define			shell_log_warning(module, msg...)	__shell_log(LOG_WARNING, module, msg)
#define			shell_log_error(module, msg...)		__shell_log(LOG_ERROR, module, msg)
#define			shell_log_fatal(module, msg...)		__shell_log(LOG_FATAL, module, msg)
static	int  		(*__shell_log)(int type, const char *module, const char *msg, ...);


/* Clean exit from shell module */
static	void		(*shell_exit)(void);


#endif /* HANDLE_USER_H */
#endif /* SHELL_MODULE_H */


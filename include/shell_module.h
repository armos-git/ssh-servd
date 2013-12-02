#ifndef SHELL_MODULE_H
#define SHELL_MODULE_H

typedef struct {

	const char *ip_addr;
	const char *uname;
	unsigned int level;
	void (*shell_write)(void *data, unsigned int len);
	void (*shell_read)(void *data, unsigned int len);
	int  (*shell_log)(int type, const char *module, const char *msg, ...);
	void (*shell_exit)(void);

} shell_callbacks_t;

#ifndef HANDLE_USER_H

/* Required functions */
void	shell_init(shell_callbacks_t *cb);
void	shell_read(void *data, unsigned int len);

/* External functions */
static	void		(*shell_write)(void *data, unsigned int len);
static	int  		(*__shell_log)(int type, const char *module, const char *msg, ...);
static	void		(*shell_exit)(void);


/* Gloabal variables */
const	static	char 	*ip_addr;
const	static	char 	*username;
static	unsigned int 	level;
static	unsigned int	shell_printf_buf_len;


/* Sets up all external and global objects according to data in cb  */
#define SHELL_INIT_GLOBALS(cb) \
	cb->shell_read = &shell_read; \
	shell_write = cb->shell_write; \
	__shell_log = cb->shell_log; \
	shell_exit = cb->shell_exit; \
	ip_addr = cb->ip_addr; \
	username = cb->uname; \
	level = cb->level; \
	shell_printf_buf_len = 4096;


enum LOG_TYPES {
	LOG_MSG,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
};

#define		shell_log(module, msg...)		__shell_log(LOG_MSG, module, msg)
#define		shell_log_warning(module, msg...)	__shell_log(LOG_WARNING, module, msg)
#define		shell_log_error(module, msg...)		__shell_log(LOG_ERROR, module, msg)
#define		shell_log_fatal(module, msg...)		__shell_log(LOG_FATAL, module, msg)


static	void	shell_printf(const char *format, ...) {

	va_list ap;
	char *buf = alloca(shell_printf_buf_len);

	va_start(ap, format);
	vsnprintf(buf, shell_printf_buf_len, format, ap);
	va_end(ap);

	shell_write((void *)buf, strlen(buf));
}

#endif /* HANDLE_USER_H */
#endif /* SHELL_MODULE_H */


#ifndef SHELL_MODULE_H
#define SHELL_MODULE_H

#include <stdint.h>

/** @defgroup shell_functions Shell module interface functions */
/** @defgroup shell_globals Shell module global objects */

/** @defgroup shell_types Shell module types
 *
 * @{ */

/** @brief Terminal information struct
 *
 * Holds terminal dimensions.
 */
struct	shell_info_struct {

  int x; /**< @brief width in characters  */
  int y; /**< @brief height in characters */ 
  int px; /**< @brief width in pixels */
  int py; /**< @brief height in pixels */
};

/** @brief Shell callbacks struct
 *
 * Holds the server/shell interface functions and info about the shell owner.
 *
 * See @ref shell_functions
 */
typedef struct {

  const char			*ip_addr; /**< @brief users's ip address */
  const char			*uname; /**< @brief username */
  unsigned int			level; /**< @brief security level number */
  struct shell_info_struct	shell_info; /**< @brief terminal attributes */


/** 
 * @addtogroup shell_functions
 * @{
 */

/**
 * Writes data to server
 *
 * @param data	buffer holding the data to send
 * @param len	datal length
 *
 * @return
 * The actual bytes written. 
 * @warning
 * If error occurs it will terminate the shell and log the error.
 */
  int		(*shell_write)(void *data, uint32_t len);

/**
 * printf() like function to send formated string to server
 *
 * @param buflen  maximum space to allocate for internal string buffer.
 * @param format  format string...
 *
 * @warning
 * This function will write at most buflen bytes to server.
 * If error occurs it will terminate the shell and log the error.
 */
  int		(*shell_printf)(unsigned int buflen, const char *format, ...);

/**
 * This function will get called when the server received data
 *
 * @param data	buffer to hold data
 * @param len	buffer length
 *
 * @note 
 * By default this variable is set to NULL and will be ignored if not changed
 * 
 * may be defined by the shell module.
 */
  void		(*shell_read)(void *data, uint32_t len);

/**
 * This function will get called when the client changes the terminal size
 *
 * @param x,y	witdth,height in characters 
 * @param px,py width,height in pixels
 *
 * @note
 * By default this variable is set to NULL and will be ignored if not changed
 *
 * @note may be defined by the shell module.
 */
  void		(*shell_change_window_size)(int x, int y, int px, int py);

/**
 * Log messages to the main server log file
 *
 * @param type	msg type (see @ref LOG_TYPES)
 * @param module module name which will appear in the log module section
 * @param msg	message to send
 *
 * @return
 * 
 * 0 if there is problem writing to the log file
 */
  int		(*shell_log)(int type, const char *module, const char *msg, ...);

/**
 * Exits cleanly from the shell.
 * The event will be logged in the server's log
 */
  void		(*shell_exit)(void);


} shell_callbacks_t;

/** @} */


/* check to see if it is included in server or in shell module */
#ifndef HANDLE_USER_H

#include <string.h>

/* shell_printf() buffer size */
#define DEFAULT_SHELL_PRINTF_BUF_SIZE		4096


/** @addtogroup shell_types
 * @{ */
/** Log types */
enum LOG_TYPES {
	LOG_MSG,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
};
/** @} */


/**
 * @addtogroup shell_globals
 *
 * @{ */

#define shell_user_ipaddr	user_ipaddr	/**< @brief users's ip address */
#define shell_username		username	 /**< @brief username */
#define shell_userlevel		userlevel	/**< @brief security level number */
#define shell_attr		shell_info	 /**< @brief terminal attributes */
#define shell_printf_buflen	shell_printf_buf_len /**< @brief shell_printf() buffer size */

/** @brief see @ref shell_callbacks_t.shell_write */
#define 	shell_write(data, len)			__shell_write(data, len)

/** @brief see @ref shell_callbacks_t.shell_printf */
#define		shell_printf(fmt...)			__shell_printf(shell_printf_buflen, fmt)

/** @brief log a standart message @ref shell_callbacks_t.shell_log */
#define		shell_log(module, msg...)		__shell_log(LOG_MSG, module, msg)

/** @brief log a warning message @ref shell_callbacks_t.shell_log */
#define		shell_log_warning(module, msg...)	__shell_log(LOG_WARNING, module, msg)

/** @brief log an error message @ref shell_callbacks_t.shell_log */
#define		shell_log_error(module, msg...)		__shell_log(LOG_ERROR, module, msg)

/** @brief log a fatal message @ref shell_callbacks_t.shell_log */
#define		shell_log_fatal(module, msg...)		__shell_log(LOG_FATAL, module, msg)

/** @brief see @ref shell_callbacks_t.shell_exit */
#define		shell_exit()				__shell_exit()

/** @brief Defines all global objecst
 *
 * @note Must declare at the begging */
#define	SHELL_DEFINE_GLOBALS \
\
const	static	char 			*shell_user_ipaddr; \
const 	static	char		 	*shell_username; \
static	unsigned int 			shell_userlevel; \
static	unsigned int			shell_printf_buflen; \
static	struct	shell_info_struct	shell_attr; \
\
static	int		(*__shell_write)(void *data, uint32_t len); \
static	int		(*__shell_printf)(unsigned int buflen, const char *format, ...); \
static	int  		(*__shell_log)(int type, const char *module, const char *msg, ...); \
static	void		(*__shell_exit)(void);

static	void		shell_read(void *data, uint32_t len); \
static	void		shell_change_window_size(int x, int y, int px, int py); \


/** @brief Initializes all global objects
 *
 * @param cb	callbacks struct passed from shell_init()
 *
 * @sa	shell_callbacks_t shell_init()
 */
#define SHELL_INIT_GLOBALS(cb) \
	memcpy(&shell_info, &cb->shell_info, sizeof(struct shell_info_struct)); \
	cb->shell_read = &shell_read; \
	cb->shell_change_window_size = &shell_change_window_size; \
	__shell_write = cb->shell_write; \
	__shell_printf = cb->shell_printf; \
	__shell_log = cb->shell_log; \
	__shell_exit = cb->shell_exit; \
	user_ipaddr = cb->ip_addr; \
	username = cb->uname; \
	userlevel = cb->level; \
	shell_printf_buf_len = DEFAULT_SHELL_PRINTF_BUF_SIZE;


/** @brief shell module initialization function
 *
 * This function must be defined by the shell. It is executed once when the server loads the shell
 *
 * @param cb	server callbacks
 *
 * @attention
 * This function MUST return */
void	shell_init(shell_callbacks_t *cb);

/** @} */


#endif /* HANDLE_USER_H */
#endif /* SHELL_MODULE_H */


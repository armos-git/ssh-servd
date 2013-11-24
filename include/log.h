#ifndef LOG_H
#define LOG_H


enum LOG_TYPES {
	LOG_MSG,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
};


extern	int	serv_set_logfile(const char *filename);


#define		serv_log(msg...)		__serv_log(LOG_MSG, LOG_MODULE_NAME, msg)
#define		serv_log_warning(msg...)	__serv_log(LOG_WARNING, LOG_MODULE_NAME, msg)
#define		serv_log_error(msg...)		__serv_log(LOG_ERROR, LOG_MODULE_NAME, msg)
#define		serv_log_fatal(msg...)		__serv_log(LOG_FATAL, LOG_MODULE_NAME, msg)

extern	int	__serv_log(int type, const char *module, const char *msg, ...);

#endif /* LOG_H */

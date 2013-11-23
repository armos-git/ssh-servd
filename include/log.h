enum LOG_TYPES {
	LOG_MSG,
	LOG_WARNING,
	LOG_ERROR,
	LOG_FATAL
};


extern	int	serv_set_logfile(const char *filename);


#define		serv_log(module, msg...)		__serv_log(LOG_MSG, module, msg)
#define		serv_log_warning(module, msg...)	__serv_log(LOG_WARNING, module, msg)
#define		serv_log_error(module, msg...)		__serv_log(LOG_ERROR, module, msg)
#define		serv_log_fatal(module, msg...)		__serv_log(LOG_FATAL, module, msg)

extern	int	__serv_log(int type, const char *module, const char *msg, ...);

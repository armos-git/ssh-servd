#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#define	MAXFILE		256
#define	MODULES		5
#define PIDFILE		"/var/run/ssh-server.pid"

/* Server configuration options */
typedef struct {
	char	listen_addr[INET_ADDRSTRLEN];
	int	listen_port;
	char	dsakey[MAXFILE];
	char	rsakey[MAXFILE];
	char	log_file[MAXFILE];
	char	users_file[MAXFILE];
	char	modules_dir[MAXFILE];
	char	shell[MAXFILE];
	char	modules[MODULES][MAXFILE];
} serv_options_t;

extern	serv_options_t		serv_options;

#endif /* SSH_SERVER_H */

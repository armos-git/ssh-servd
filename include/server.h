#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#define	MAXFILE			256
#define PID_FILE		"/var/run/ssh-server.pid"


#define DEFAULT_DIR		"/etc/ssh-servd/"
#define	default_file(file)	DEFAULT_DIR file
#define	DEFAULT_CONFIG		"ssh-servd.conf"
#define DEFAULT_RSAKEY		"ssh-servd-rsa"
#define DEFAULT_DSAKEY		"ssh-servd-dsa"
#define DEFAULT_USERS		"users"
#define DEFAULT_MODDIR		"modules"
#define DEFAULT_PUBDIR		"pubkeys"


/* Server configuration options */
typedef struct {
	char	listen_addr[INET_ADDRSTRLEN];
	int	listen_port;
	char	dsakey[MAXFILE];
	char	rsakey[MAXFILE];
	char	log_file[MAXFILE];
	char	users_file[MAXFILE];
	char	modules_dir[MAXFILE];
	char	pubdir[MAXFILE];
} serv_options_t;

extern	serv_options_t		serv_options;

#endif /* SSH_SERVER_H */

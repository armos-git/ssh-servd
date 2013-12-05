#ifndef USERS_H
#define USERS_H

#define	USERS_MAX_NAME	30
#define USERS_MAX_PASS	128
#define USERS_MAX_SALT	20

typedef	struct {

	char user[USERS_MAX_NAME];
	char pass[USERS_MAX_PASS];
	char salt[USERS_MAX_SALT];
	char module[MAXFILE];
	unsigned int level;

} users_info_t;


extern	int		read_tty(void *data, size_t len, int noecho);

extern	void		users_close(ssh_session ses);

extern	char		*users_resolve_ip(ssh_session ses);

extern	void		users_config_new();

extern	void		users_config_rem();

extern	unsigned int	users_auth(const char *user, const char *pass, char *module);

#endif /* USERS_H */

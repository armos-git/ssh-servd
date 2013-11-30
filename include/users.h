#ifndef USERS_H
#define USERS_H

#define	USERS_MAX	50
#define USERS_SIZE	sizeof(users_t[USERS_MAX])
#define USERS_KEY	0x681fb732
#define	USERS_FULL	-1

#define	USERS_MAX_NAME	30
#define USERS_MAX_PASS	128
#define USERS_MAX_SALT	20

typedef struct {

	ssh_session ses;
	char *ip;
	pid_t pid;
	
} users_t;

typedef	struct {

	char user[USERS_MAX_NAME];
	char pass[USERS_MAX_PASS];
	char salt[USERS_MAX_SALT];
	unsigned int level;

} users_info_t;


extern	void	*users_create();

extern	void	*users_attach();

extern	void	users_detach(void *addr);

extern	void	users_destroy();

extern	void	users_init(users_t *users);

extern	char	*users_resolve_ip(users_t user);

extern	void	*users_get_session(users_t user);

extern	char	*users_get_ip(users_t user);

extern	pid_t	users_get_pid(users_t user);

extern	int	users_add(users_t *users, ssh_session ses);

extern	void	users_del(users_t user);

extern	void	users_free(users_t user);

extern	void	users_close(users_t user);

extern	void	users_config_new();

extern	void	users_config_rem();

extern	int	users_auth(const char *user, const char *pass);

#endif /* USERS_H */

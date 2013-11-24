#ifndef USERS_H
#define USERS_H

#define	USERS_MAX	50
#define	USERS_FULL	-1

typedef struct {

	ssh_session ses;
	char *ip;
	pid_t pid;
	
} users_t;


extern	void	users_init(users_t *users);

extern	int	users_get_free(users_t *users);

extern	int	users_add(users_t *users, ssh_session ses);

extern	void	users_del(users_t user);

extern	int	auth_user(const char *user, const char *pass);

#endif /* USERS_H */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <libssh/libssh.h>

#include "users.h"
#include "log.h"

void	*users_create() {

	key_t memkey;
	int segid;

	static void *addr;

	memkey = USERS_KEY;
	segid = shmget(memkey, USERS_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
	if (segid < 0) {
		serv_log_error("SSH Server", "Could not create shared memory for users: shmget(): ", strerror(errno));
		return NULL;
	}

	if ((addr = shmat(segid, NULL, 0)) == (void *) -1) {
		serv_log_error("SSH Server", "Could not attach to shared memory for users: shmat(): ", strerror(errno));
		return NULL;
	}

	return addr;
}

void	*users_attach() {

	key_t memkey;
	int segid;

	static void *addr;

	memkey = USERS_KEY;
	segid = shmget(memkey, USERS_SIZE, S_IRUSR | S_IWUSR);
	if (segid < 0) {
		serv_log_error("SSH Server", "Could not find shared memory for users: shmget(): ", strerror(errno));
		return NULL;
	}

	if ((addr = shmat(segid, NULL, 0)) == (void *) -1) {
		serv_log_error("SSH Server", "Could not attach to shared memory for users: shmat(): ", strerror(errno));
		return NULL;
	}

	return addr;
}

void	users_detach(void *addr) {

	shmdt(addr);
}

void	users_init(users_t *users) {

	int i;

	for (i = 0; i < USERS_MAX; i++) {
		users[i].ses = NULL;
		users[i].ip = NULL;
		users[i].pid = 0;
	}
	
}

int	users_get_free(users_t *users) {

	int i;

	for (i = 0; i < USERS_MAX; i++) {
		if (users[i].ses == NULL)
			return i;
	}

	return USERS_FULL;
}

char	*users_get_ip(users_t user) {

	struct sockaddr_in sockaddr;
	socklen_t len;

	len = sizeof(sockaddr);
	if (getpeername(ssh_get_fd(user.ses), (struct sockaddr *)&sockaddr, &len) < 0)
		return NULL;

	return inet_ntoa(sockaddr.sin_addr);
}

int	users_add(users_t *users, ssh_session ses) {

	int i;
	char *ip;

	for (i = 0; i < USERS_MAX; i++) {
		if (users[i].ses != NULL)
			continue;

		users[i].ses = ses;
		ip = users_get_ip(users[i]);
		if (ip != NULL) {
			users[i].ip = malloc(strlen(ip) + 1);
			strcpy(users[i].ip, ip);
		}

		return i;
	}

	return USERS_FULL;
}

void	users_del(users_t user) {

	if (user.ses != NULL) {
		ssh_free(user.ses);
		user.ses = NULL;
	}

	if (user.ip != NULL) {
		free(user.ip);
		user.ip = NULL;
	}
}

int	auth_user(const char *user, const char *pass) {

	if (strcmp(user, "vlad"))
		return 0;
	if (strcmp(pass, "1234"))
		return 0;
	return 1;
}

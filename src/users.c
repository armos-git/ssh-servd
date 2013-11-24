/* This file contains all ssh-server user managment functions */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

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

#define LOG_MODULE_NAME		"SSH Server"


#include "server.h"
#include "users.h"
#include "log.h"

/* Creates a shared memory for the users. Should call this once from the main thread
* Returns newly allocated mem */
void	*users_create() {

	key_t memkey;
	int segid;

	static void *addr;

	memkey = USERS_KEY;
	segid = shmget(memkey, USERS_SIZE, IPC_CREAT | S_IRUSR | S_IWUSR);
	if (segid < 0) {
		serv_log_error("Could not create shared memory for users: shmget(): ", strerror(errno));
		return NULL;
	}

	if ((addr = shmat(segid, NULL, 0)) == (void *) -1) {
		serv_log_error("Could not attach to shared memory for users: shmat(): ", strerror(errno));
		return NULL;
	}

	return addr;
}

/* Attaches to the users shared memory segment
* Returns the shared segmet address */
void	*users_attach() {

	key_t memkey;
	int segid;

	static void *addr;

	memkey = USERS_KEY;
	segid = shmget(memkey, USERS_SIZE, S_IRUSR | S_IWUSR);
	if (segid < 0) {
		serv_log_error("Could not find shared memory for users: shmget(): ", strerror(errno));
		return NULL;
	}

	if ((addr = shmat(segid, NULL, 0)) == (void *) -1) {
		serv_log_error("Could not attach to shared memory for users: shmat(): ", strerror(errno));
		return NULL;
	}

	return addr;
}

/* Detaches from the users shared memory segment */
void	users_detach(void *addr) {

	shmdt(addr);
}

/* Inits all users */
void	users_init(users_t *users) {

	int i;

	for (i = 0; i < USERS_MAX; i++) {
		users[i].ses = NULL;
		users[i].ip = NULL;
		users[i].pid = 0;
		users[i].echo = 1;
	}
	
}

/* Converts a user connected socket to ip address
* Returns the ip address string */
char	*users_resolve_ip(users_t user) {

	struct sockaddr_in sockaddr;
	socklen_t len;

	len = sizeof(sockaddr);
	if (getpeername(ssh_get_fd(user.ses), (struct sockaddr *)&sockaddr, &len) < 0)
		return NULL;

	return inet_ntoa(sockaddr.sin_addr);
}


/* Get user session */
void	*users_get_session(users_t user) {

	return user.ses;
}

/* Get user ip address */
char	*users_get_ip(users_t user) {

	return user.ip;
}

/* Get user pid */
pid_t	users_get_pid(users_t user) {

	return user.pid;
}

/* Adds a new user with ssh_session ses */
int	users_add(users_t *users, ssh_session ses) {

	int i;
	char *ip;

	for (i = 0; i < USERS_MAX; i++) {
		if (users[i].ses != NULL)
			continue;

		users[i].ses = ses;
		ip = users_resolve_ip(users[i]);
		if (ip != NULL) {
			users[i].ip = memalloc(strlen(ip) + 1);
			if (users[i].ip != NULL)
				strcpy(users[i].ip, ip);
		}

		return i;
	}

	return USERS_FULL;
}

/* Deletes and free a user without disconnecting */
void	users_del(users_t user) {

	if (user.ses != NULL) {
		ssh_free(user.ses);
		user.ses = NULL;
	}

	if (user.ip != NULL) {
		free(user.ip);
		user.ip = NULL;
	}

	user.pid = 0;
	user.echo = 1;
}

/* Disconnect and free user's resources withoud deleting it from the users list
* Use this to free resources before exiting a child process */
void	users_free(users_t user) {

	if (user.ses != NULL) {
		ssh_disconnect(user.ses);
		ssh_free(user.ses);
	}

	if (user.ip != NULL)
		free(user.ip);
}

/* Disconnect, free, and delete a user */
void	users_close(users_t user) {

	if (user.ses == NULL)
		return;

	ssh_disconnect(user.ses);
	users_del(user);
}



int	auth_user(const char *user, const char *pass) {

	if (strcmp(user, "vlad"))
		return 0;
	if (strcmp(pass, "1234"))
		return 0;
	return 1;
}

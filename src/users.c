/* This file contains all ssh-server user managment functions */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
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
#include <fcntl.h>
#include <termios.h>
#include <crypt.h>
#include <libssh/libssh.h>

#define LOG_MODULE_NAME		"SSH Server"


#include "server.h"
#include "mem.h"
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


static	int	read_tty(int fd, void *data, size_t len, int noecho) {

	int rc;
	struct termios oldt, newt;

	if (noecho) {
		tcgetattr(fd, &oldt);
		newt = oldt;
		newt.c_lflag &= ~(ECHO);
		tcsetattr(fd, TCSANOW, &newt);
	}
	if ((rc = read(fd, data, len)) < 0) {
		fprintf(stderr, "Error reading from /dev/tty!\n");
		close(fd);
		return -1;
	}
	if (noecho) {
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printf("\n");
	}

	return rc;
}

static	int	users_config_prompt(users_info_t *info, int verify) {

	int fd, rc, rc2, ret;
	char *ver;

	ret = 1;
	fd = open("/dev/tty", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error opening /dev/tty!\n");
		return 0;
	}

	printf("Username: ");
	fflush(stdout);
	rc = read_tty(fd, info->user, USERS_MAX_NAME - 1, 0);
	if (rc < 0) {
		close(fd);
		return 0;
	}
	info->user[rc-1] = 0;

	printf("Password: ");
	fflush(stdout);
	rc = read_tty(fd, info->pass, USERS_MAX_PASS - 1, 1);
	if (rc < 0) {
		close(fd);
		return 0;
	}
	info->pass[rc-1] = 0;

	if (verify) {
		ver = malloc(rc);
		printf("Verify Password: ");
		fflush(stdout);

		rc2 = read_tty(fd, ver, rc, 1);
		if (rc < 0) {
			free(ver);
			close(fd);
			return 0;
		}
		rc--;
		rc2--;
		ver[rc2] = 0;

		if ((rc != rc2) || (strcmp(info->pass, ver))) {
			printf("\nPasswords don't match!\n");
			ret = 0;
		}

		free(ver);
		
	}

	close(fd);
	return ret;
}

static	int	users_config_scan_user(FILE *f, const users_info_t *info) {

	char *name;
	int rc;

	rc = 0;

	fseek(f, 0, SEEK_SET);

	while (!feof(f)) {
		fscanf(f, "%ms", &name);
		if (!strcmp(name, info->user)) {
			free(name);
			rc = 1;
			break;
		}
		free(name);
	}

	fseek(f, 0, SEEK_SET);
	return rc;
}

void	users_config_new() {

	FILE *f;
	users_info_t info;

	if (!users_config_prompt(&info, 1))
		return;
	
	f = fopen(serv_options.users_file, "a+");
	if (f == NULL) {
		fprintf(stderr, "Cannot open users file: %s\n", serv_options.users_file);
		return;
	}

	if (users_config_scan_user(f, &info)) {
		fprintf(stderr, "User '%s' already exists!\n", info.user);
		fclose(f);
		return;
	}

	fclose(f);
	

}

void	users_config_rem() {

}

int	auth_user(const char *user, const char *pass) {

	if (strcmp(user, "test"))
		return 0;
	if (strcmp(pass, "1234"))
		return 0;
	return 1;
}

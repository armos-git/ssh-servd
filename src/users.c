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

static	int	segid;

/* Creates a shared memory for the users. Should call this once from the main thread
* Returns newly allocated mem */
void	*users_create() {

	key_t memkey;

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

/* Destroys the  users shared memory segment */
void	users_destroy() {

	shmctl(segid, IPC_RMID, NULL);
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


/* Reads input directly from process tty
* Returns -1 on error */
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

/* Prompts user for username, password and security level
* Returns 0 on error */
static	int	users_config_prompt(users_info_t *info, int verify) {

	int fd, rc, rc2;
	char *ver;

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
		if (ver == NULL) {
			close(fd);
			return 0;
		}

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
			free(ver);
			close(fd);
			return 0;
		}
	}

	close(fd);

	printf("Enter user security level number: ");
	fflush(stdout);
	scanf("%u", &info->level);

	return 1;
}

/* Searches for username info.user in the users config file and files out struct info if found.
* Returns 0 if not found, 1 if found, 2 on syntax error */
static	int	users_config_scan_user(FILE *f, users_info_t *info) {

	char *name, *pass_str;
	unsigned int level;
	int rc;

	name = NULL;
	pass_str = NULL;

	while (!feof(f)) {
		rc = fscanf(f, "%ms%u%ms", &name, &level, &pass_str);
		if (rc == EOF)
			break;
		if (rc < 3) {
			free(name);
			free(pass_str);
			return 2;
		}

		if (!strcmp(name, info->user)) {
			strncpy(info->pass, pass_str, USERS_MAX_PASS - 1);
			info->level = level;
			free(name);
			free(pass_str);
			return 1;
		}
		free(name);
		free(pass_str);
	}

	return 0;
}

/* Generates random salt from the set [a–zA–Z0–9./] with the specified len
* Returns 0 on error */
static	int	users_gen_salt(char *salt, unsigned int len) {

	int i, rc, fd;
	unsigned char c;
	const char salt_set[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	const int salt_set_len = strlen(salt_set) - 1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening /dev/urandom!\n");
		return 0;
	}

	rc = read(fd, salt, len);
	if (rc < 0) {
		fprintf(stderr, "Error reading from /dev/urandom!\n");
		close(fd);
		return 0;
	}

	close(fd);

	for (i = 0; i < len - 1; i++) {
		c = salt[i];
		salt[i] = salt_set[ c % salt_set_len ];
	}
	salt[i] = 0;

	return 1;
}

/* Adds a new user in the users config file */
void	users_config_new() {

	FILE *f;
	int len, rc;
	char *cr_pass, *salt;
	users_info_t info;

	/* default level */
	memset(&info, 0, sizeof(info));
	info.level = 1;

	if (!users_config_prompt(&info, 1))
		return;
	
	f = fopen(serv_options.users_file, "a+");
	if (f == NULL) {
		fprintf(stderr, "Cannot open users file: %s\n", serv_options.users_file);
		return;
	}

	rc = users_config_scan_user(f, &info);
	switch (rc) {
	  case 0:
		break;
	  case 1:
		fprintf(stderr, "User '%s' already exists!\n", info.user);
		fclose(f);
		return;
	  case 2:
		fprintf(stderr, "Syntax error in users file %s\n", serv_options.users_file);
		fclose(f);
		return;
	}

	if (!users_gen_salt(info.salt, USERS_MAX_SALT)) {
		fclose(f);
		return;
	}

	len = strlen(info.salt) + 4;
	salt = malloc(len);
	if (salt == NULL) {
		fclose(f);
		return;
	}

	snprintf(salt, len, "$6$%s", info.salt);
	cr_pass = crypt(info.pass, salt);
	free(salt);

	fprintf(f, "%s %u %s\n", info.user, info.level, cr_pass);
	fclose(f);

	printf("User '%s' added to %s\n", info.user, serv_options.users_file);
}

void	users_config_rem() {

}

/* auths user
* Returns 1 on success */
int	users_auth(const char *user, const char *pass) {

	int rc, i, j, s;
	FILE *f;
	users_info_t info;
	char salt[USERS_MAX_SALT];
	char *enc_pass;

	f = fopen(serv_options.users_file, "r");
	if (f == NULL) {
		serv_log_error("Cannot open users file: fopen(): %s", strerror(errno));
		return 0;
	}
	
	memset(&info, 0, sizeof(info));
	strncpy(info.user, user, USERS_MAX_NAME - 1);

	rc = users_config_scan_user(f, &info);
	switch (rc) {
	  case 0:
		fclose(f);
		return 0;
	  case 1:
		/* found */
		break;
	  case 2:
		serv_log_warning("Syntax error in users file %s while searching for user %s", serv_options.users_file, user);
		fclose(f);
		return 0;
	}

	fclose(f);

	/* Separates the salt from the password string */
	s = strlen(info.pass);
	j = 0;
	for (i = 0; i < s; i++) {
		if (info.pass[i] == '$') {
			j++;
			if (j == 3) {
				info.pass[i] = 0;
				break;
			}
		}
	}

	/* check for syntax error */
	if (j != 3) {
		serv_log_warning("Syntax error in users file %s. Invalid password string!", serv_options.users_file);
		return 0;
	}

	/* save the salt */
	strncpy(salt, info.pass, USERS_MAX_SALT - 1);

	/* restores the original string */
	info.pass[i] = '$';

	/* test for valid password */
	enc_pass = crypt(pass, salt);
	if (strcmp(enc_pass, info.pass))
		return 0;

	/* Success! */
	return 1;
}

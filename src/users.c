/* This file contains all ssh-servd user managment functions */

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


void	users_close(ssh_session ses) {

	if (ses == NULL)
		return;

	ssh_disconnect(ses);
	ssh_free(ses);
}

/* Converts a user connected socket to ip address
* Returns the ip address string */
char	*users_resolve_ip(ssh_session ses) {

	struct sockaddr_in sockaddr;
	socklen_t len;

	len = sizeof(sockaddr);
	if (getpeername(ssh_get_fd(ses), (struct sockaddr *)&sockaddr, &len) < 0)
		return NULL;

	return inet_ntoa(sockaddr.sin_addr);
}


/* Reads input directly from process tty
* Returns -1 on error */
int	read_tty(void *data, size_t len, int noecho) {

	int rc, fd;
	struct termios oldt, newt;

	fd = open("/dev/tty", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error opening /dev/tty!\n");
		return -1;
	}

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

	close(fd);
	return rc;
}

/* Prompts user for username, password and security level
* Returns 0 on error */
static	int	users_config_prompt(users_info_t *info, int verify) {

	int rc, rc2;
	int slen;
	char *ver;


	printf("Username: ");
	fflush(stdout);
	rc = read_tty(info->user, USERS_MAX_NAME - 1, 0);
	if (rc < 0)
		return 0;
	info->user[rc-1] = 0;

	printf("Password: ");
	fflush(stdout);
	rc = read_tty(info->pass, USERS_MAX_PASS - 1, 1);
	if (rc < 0)
		return 0;
	info->pass[rc-1] = 0;

	if (verify) {
		ver = malloc(rc);
		if (ver == NULL)
			return 0;

		printf("Verify Password: ");
		fflush(stdout);

		rc2 = read_tty(ver, rc, 1);
		if (rc < 0) {
			memfree(ver);
			return 0;
		}
		rc--;
		rc2--;
		ver[rc2] = 0;

		if ((rc != rc2) || (strcmp(info->pass, ver))) {
			printf("\nPasswords don't match!\n");
			memfree(ver);
			return 0;
		}

		memfree(ver);
	}


	printf("Enter user's shell module: ");
	fflush(stdout);
	fgets(info->module, MAXFILE - 1, stdin);
	slen = strlen(info->module);
	info->module[ slen - 1 ] = 0;

	printf("Enter user's security level number: ");
	fflush(stdout);
	scanf("%u", &info->level);

	return 1;
}

/* Searches for username info.user in the users config file and files out struct info if found.
* Returns 0 if not found, 1 if found, 2 on syntax error */
int	users_config_scan_user(FILE *f, users_info_t *info) {

	char *name, *pass_str, *module;
	unsigned int level;
	int rc, ret;

	ret = 0;

	while (!feof(f)) {
		name = NULL;
		pass_str = NULL;
		module = NULL;

		rc = fscanf(f, "%ms%ms%u%ms", &name, &module, &level, &pass_str);
		if (rc == EOF)
			break;
		if (rc < 4) {
			ret = 2;
			goto terminate;
		}

		if (!strcmp(name, info->user)) {
			strncpy(info->pass, pass_str, USERS_MAX_PASS - 1);
			strncpy(info->module, module, MAXFILE - 1);
			info->level = level;
			ret = 1;
			goto terminate;
		} else {
			memfree(name);
			memfree(pass_str);
			memfree(module);
		}
	}

terminate:
	memfree(name);
	memfree(pass_str);
	memfree(module);
	return ret;
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
		fprintf(stderr, "Cannot open users file %s: fopen(): %s\n", serv_options.users_file, strerror(errno));
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
	memfree(salt);

	fprintf(f, "%s %s %u %s\n", info.user, info.module, info.level, cr_pass);
	fclose(f);

	printf("User '%s' added to %s\n", info.user, serv_options.users_file);
}

void	users_config_rem() {

}

/* auths user
* Returns 0 on fail or the user level from the config  */
unsigned int	users_auth(const char *user, const char *pass, char *module) {

	int rc, i, j, s;
	FILE *f;
	users_info_t info;
	char salt[USERS_MAX_SALT];
	char *enc_pass;

	f = fopen(serv_options.users_file, "r");
	if (f == NULL) {
		serv_log_error("Cannot open users file %s: fopen(): %s\n", serv_options.users_file, strerror(errno));
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
	strncpy(module, info.module, MAXFILE - 1);
	return info.level;
}

/* This file contains ssh-server functions to handle newly conencted users */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define	LOG_MODULE_NAME		"SSH Server"

#include "log.h"
#include "users.h"

static ssh_channel chan;

/* Clean server child termination */
void	handle_user_terminate(users_t *users, int x) {

	users_close(users[x]);
	users_detach(users);
	_exit(EXIT_FAILURE);
}

/* Server child to handle a newly connected user */
void	handle_user(int x) {

	users_t *users;
	ssh_message sshmsg;
	ssh_session session;
	int auth, shell, retry;
	const char *usr, *pass;
	const char *ip;

	users = users_attach();
	session = users_get_session(users[x]);
	ip = users_get_ip(users[x]);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		serv_log_error("ssh_handle_key_exchange(): %s", ssh_get_error(session));
		handle_user_terminate(users, x);
	}

	/* authenticate client */
	auth = 0;
	retry = 0;
	do {
		if (retry == 3)
			break;

		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL)
			break;

		switch (ssh_message_type(sshmsg)) {
		  case SSH_REQUEST_AUTH:
			switch (ssh_message_subtype(sshmsg)) {

			  case SSH_AUTH_METHOD_PASSWORD:
				usr = ssh_message_auth_user(sshmsg);
				pass = ssh_message_auth_password(sshmsg);
				if (auth_user(usr, pass)) {
					auth = 1;
					ssh_message_auth_reply_success(sshmsg, 0);
					serv_log("%s loged in with username %s", ip, usr);
				} else {
					serv_log_warning("%s login failed with username %s", ip, usr);
					ssh_message_reply_default(sshmsg);
				}
				retry++;
				break;

			  default:
				ssh_message_auth_set_methods(sshmsg, SSH_AUTH_METHOD_PASSWORD);
				ssh_message_reply_default(sshmsg);
				break;
			}
			break;
		  default:
			ssh_message_reply_default(sshmsg);
			break;
		}
		ssh_message_free(sshmsg);
	} while (!auth);

	if (!auth) {
		serv_log_warning("%s login failed", ip);
		handle_user_terminate(users, x);
	}


	/* wait for channel request from client */
	chan = 0;
	do {
		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL)
			continue;

		switch (ssh_message_type(sshmsg)) {

		  case SSH_REQUEST_CHANNEL_OPEN:
			if (ssh_message_subtype(sshmsg) == SSH_CHANNEL_SESSION)
				chan = ssh_message_channel_request_open_reply_accept(sshmsg);
			break;
		  default:
			ssh_message_reply_default(sshmsg);
			break;
		}

		ssh_message_free(sshmsg);

	} while ((sshmsg != NULL) && !chan);
	if (!chan) {
		serv_log_error("Error waiting for channel request from %s: %s", ip, ssh_get_error(session));
		handle_user_terminate(users, x);
	}

	/* wait for shell request from client */
	shell = 0;
	do {
		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL)
			continue;

		if (ssh_message_type(sshmsg) == SSH_REQUEST_CHANNEL &&
			(ssh_message_subtype(sshmsg) == SSH_CHANNEL_REQUEST_SHELL ||
			 ssh_message_subtype(sshmsg) == SSH_CHANNEL_REQUEST_PTY))
		{
			shell = 1;
			ssh_message_channel_request_reply_success(sshmsg);
		} else {
			ssh_message_reply_default(sshmsg);
		}

		ssh_message_free(sshmsg);
	
	} while ((sshmsg != NULL) && !shell);
	if (!shell) {
		serv_log_error("Error waiting for shell request from %s: %s", ip, ssh_get_error(session));
		handle_user_terminate(users, x);
	}
	
	/* load shell module */

	int rc;
	char buf[1024];
	const char color[] = "\x1b[0m";
	ssh_channel_write(chan, color, strlen(color));
	while (1) {
		rc = ssh_channel_read(chan, buf, 1024, 0);
		switch (rc) {
			case 0:
			case SSH_AGAIN:
				continue;
			case SSH_ERROR:
				continue;
		}
		if (buf[0] == 'q') {
			ssh_disconnect(session);
			ssh_free(session);
			_exit(EXIT_SUCCESS);
		}
		ssh_channel_write(chan, buf, rc);
		//write(1, buf, rc);
	}


	handle_user_terminate(users, x);
}

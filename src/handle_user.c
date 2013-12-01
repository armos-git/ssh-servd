/* This file contains ssh-server functions to handle newly conencted users */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#define	LOG_MODULE_NAME		"SSH Server"
#define	SERV_POLL_TIMEOUT	60000 // ms
#define SERV_READ_BUF		2048

#include "server.h"
#include "log.h"
#include "mem.h"
#include "users.h"
#include "shell_module.h"

static ssh_channel		handle_user_chan;
static users_t			*handle_user_users;
static int 			handle_user_index;
static char			*handle_user_buf;
static void			*handle_user_hndl;
static shell_callbacks_t	shell_cb;




void	handle_user_unload_shell() {

	dlclose(handle_user_hndl);
}

/* Clean server child termination */
void	handle_user_terminate() {

	users_close(handle_user_users[handle_user_index]);
	users_detach(handle_user_users);
	_exit(EXIT_FAILURE);
}

void	handle_user_terminate_shell() {

	free(handle_user_buf);
	handle_user_unload_shell();
	handle_user_terminate();
}

void	handle_user_write(void *data, uint32_t len) {

	int rc;

	rc = ssh_channel_write(handle_user_chan, data, len);
	if (rc == SSH_ERROR) {
		serv_log_error("%s channel write failed. ssh_channel_write(): %s", handle_user_users[handle_user_index].ip, ssh_get_error(handle_user_users[handle_user_index].ses));
		handle_user_terminate_shell();
	}
}


void	handle_user_load_shell() {

	char *module_name;
	int slen;


	slen = strlen(serv_options.modules_dir) + strlen(serv_options.shell) + 2;
	module_name = memalloc(slen);
	snprintf(module_name, slen, "%s/%s", serv_options.modules_dir, serv_options.shell);
	
	handle_user_hndl = dlopen(module_name, RTLD_LAZY);
	if (handle_user_hndl == NULL) {
		serv_log_error("Cannot load shell module %s", module_name);
		free(module_name);
		handle_user_terminate();
	}

	void (*shell_init)(shell_callbacks_t *a) = dlsym(handle_user_hndl, "shell_init");
	if (shell_init == NULL) {
		serv_log_error("Cannot load 'shell_init()' frome module %s", module_name);
		free(module_name);
		handle_user_terminate();
	}	

	shell_cb.ip_addr = handle_user_users[handle_user_index].ip;
	shell_cb.shell_read = NULL;
	shell_cb.shell_write = &handle_user_write;
	shell_cb.shell_log = &__serv_log;
	shell_cb.shell_exit = &handle_user_terminate_shell;
	shell_init(&shell_cb);

	free(module_name);
}

/* Server child to handle a newly connected user */
void	handle_user(int x) {

	ssh_message sshmsg;
	ssh_session session;
	int auth, shell, retry;
	int rc;
	const char *usr, *pass;
	const char *ip;

	handle_user_index = x;
	handle_user_users = users_attach();
	session = users_get_session(handle_user_users[x]);
	ip = users_get_ip(handle_user_users[x]);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		serv_log_error("ssh_handle_key_exchange(): %s", ssh_get_error(session));
		handle_user_terminate();
	}

	/* authenticate client */
	auth = 0;
	retry = 0;
	do {
		if (retry == 3)
			break;

		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL) {
			serv_log_error("handle_user loop 1 ssh_message_get() faile: ", ssh_get_error(session));
			break;
		}

		switch (ssh_message_type(sshmsg)) {
		  case SSH_REQUEST_AUTH:
			switch (ssh_message_subtype(sshmsg)) {

			  case SSH_AUTH_METHOD_PASSWORD:
				usr = ssh_message_auth_user(sshmsg);
				pass = ssh_message_auth_password(sshmsg);
				if (users_auth(usr, pass)) {
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
		handle_user_terminate();
	}


	/* wait for channel request from client */
	handle_user_chan = 0;
	do {
		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL)
			continue;

		switch (ssh_message_type(sshmsg)) {

		  case SSH_REQUEST_CHANNEL_OPEN:
			if (ssh_message_subtype(sshmsg) == SSH_CHANNEL_SESSION)
				handle_user_chan = ssh_message_channel_request_open_reply_accept(sshmsg);
			break;
		  default:
			ssh_message_reply_default(sshmsg);
			break;
		}

		ssh_message_free(sshmsg);

	} while ((sshmsg != NULL) && !handle_user_chan);
	if (!handle_user_chan) {
		serv_log_error("Error waiting for channel request from %s: %s", ip, ssh_get_error(session));
		handle_user_terminate();
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
		handle_user_terminate();
	}
	
	/* load shell module */
	handle_user_load_shell();

	/* setup a read buffer */
	handle_user_buf = memalloc(SERV_READ_BUF);
	if (handle_user_buf == NULL) {
		handle_user_unload_shell();
		handle_user_terminate();
	}

	while (1) {
		rc = ssh_channel_read(handle_user_chan, handle_user_buf, SERV_READ_BUF, 0);
		switch (rc) {
		  case SSH_OK:
			break;
		  case SSH_AGAIN:
			continue;
		  case SSH_ERROR: {
			serv_log_error("%s read channel failed. ssh_channel_read(): %s", handle_user_users[handle_user_index].ip, ssh_get_error(session));
			handle_user_terminate_shell();
		  }
		}

		if (shell_cb.shell_read != NULL)
			shell_cb.shell_read(handle_user_buf, rc);
	}

	
	handle_user_terminate_shell();
}

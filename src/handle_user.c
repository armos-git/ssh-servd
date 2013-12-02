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
#define USER_READ_BUF		2048

#include "server.h"
#include "log.h"
#include "mem.h"
#include "users.h"
#include "shell_module.h"

static int			user_running;
static ssh_session		user_session;
static ssh_channel		user_chan;
static char			*user_buf;
static void			*user_hndl;
static shell_callbacks_t	shell_cb;

static char		*user_ip;
static char		*user_uname;
static unsigned	int	user_level;


void	handle_user_unload_shell() {

	dlclose(user_hndl);
}

/* Clean server child termination */
void	handle_user_terminate() {

	if (user_uname != NULL)
		free(user_uname);
	if (user_ip != NULL)
		free(user_ip);

	users_close(user_session);
	_exit(EXIT_FAILURE);
}

void	handle_user_terminate_shell() {

	free(user_buf);
	handle_user_unload_shell();
	handle_user_terminate();
}

void	handle_user_write(void *data, uint32_t len) {

	int rc;

	rc = ssh_channel_write(user_chan, data, len);
	if (rc == SSH_ERROR) {
		serv_log_error("%s channel write failed. ssh_channel_write(): %s", user_ip, ssh_get_error(user_session));
		handle_user_terminate_shell();
	}
}


void	handle_user_exit() {

	serv_log("User %s (%s) has logged out", user_uname, user_ip);
	handle_user_terminate_shell();
}


void	handle_user_load_shell() {

	char *module_name;
	int slen;


	slen = strlen(serv_options.modules_dir) + strlen(serv_options.shell) + 2;
	module_name = memalloc(slen);
	if (module_name == NULL)
		handle_user_terminate();

	snprintf(module_name, slen, "%s/%s", serv_options.modules_dir, serv_options.shell);
	
	user_hndl = dlopen(module_name, RTLD_LAZY);
	if (user_hndl == NULL) {
		serv_log_error("User %s (%s): Cannot load shell module %s", user_uname, user_ip, module_name);
		free(module_name);
		handle_user_terminate();
	}

	void (*shell_init)(shell_callbacks_t *a) = dlsym(user_hndl, "shell_init");
	if (shell_init == NULL) {
		serv_log_error("User %s (%s): Cannot load 'shell_init()' frome module %s", user_uname, user_ip, module_name);
		free(module_name);
		handle_user_terminate();
	}	

	shell_cb.ip_addr = user_ip;
	shell_cb.uname = user_uname;
	shell_cb.level = user_level;
	shell_cb.shell_read = NULL;
	shell_cb.shell_write = &handle_user_write;
	shell_cb.shell_log = &__serv_log;
	shell_cb.shell_exit = &handle_user_exit;
	shell_init(&shell_cb);

	free(module_name);
}

/* Server child to handle a newly connected user */
void	handle_user(ssh_session session) {

	ssh_message sshmsg;
	int auth, shell, retry;
	int rc;
	const char *usr, *pass, *ip;

	user_uname = NULL;
	user_ip = NULL;
	user_session = session;
	ip = users_resolve_ip(session);

	user_ip = memalloc(strlen(ip) + 1);
	if (user_ip == NULL)
		handle_user_terminate();

	strcpy(user_ip, ip);
	
	if (ssh_handle_key_exchange(session) != SSH_OK) {
		serv_log_error("%s: Error while exchanging keys. ssh_handle_key_exchange(): %s", user_ip, ssh_get_error(session));
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
			serv_log_error("%s: handle_user() authenticate loop ssh_message_get() failed: ", user_ip, ssh_get_error(session));
			break;
		}

		switch (ssh_message_type(sshmsg)) {
		  case SSH_REQUEST_AUTH:
			switch (ssh_message_subtype(sshmsg)) {

			  case SSH_AUTH_METHOD_PASSWORD:
				usr = ssh_message_auth_user(sshmsg);
				pass = ssh_message_auth_password(sshmsg);
				if ((user_level = users_auth(usr, pass))) {
					auth = 1;
					user_uname = memalloc(strlen(usr) + 1);
					if (user_uname == NULL)
						handle_user_terminate();
					strcpy(user_uname, usr);

					ssh_message_auth_reply_success(sshmsg, 0);
					serv_log("%s loged in with username '%s'", user_ip, user_uname);
				} else {
					serv_log_warning("%s login failed with username '%s'", user_ip, user_uname);
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
		serv_log_warning("%s login failed. Disconnecting...", user_ip);
		handle_user_terminate();
	}


	/* wait for channel request from client */
	user_chan = 0;
	do {
		sshmsg = ssh_message_get(session);
		if (sshmsg == NULL)
			continue;

		switch (ssh_message_type(sshmsg)) {

		  case SSH_REQUEST_CHANNEL_OPEN:
			if (ssh_message_subtype(sshmsg) == SSH_CHANNEL_SESSION)
				user_chan = ssh_message_channel_request_open_reply_accept(sshmsg);
			break;
		  default:
			ssh_message_reply_default(sshmsg);
			break;
		}

		ssh_message_free(sshmsg);

	} while ((sshmsg != NULL) && !user_chan);
	if (!user_chan) {
		serv_log_error("Error waiting for channel request from %s: %s", user_ip, ssh_get_error(session));
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
		serv_log_error("Error waiting for shell request from %s: %s", user_ip, ssh_get_error(session));
		handle_user_terminate();
	}
	
	/* load shell module */
	handle_user_load_shell();

	/* setup a read buffer */
	user_buf = memalloc(USER_READ_BUF);
	if (user_buf == NULL) {
		handle_user_unload_shell();
		handle_user_terminate();
	}

	user_running = 1;
	while (user_running) {
		rc = ssh_channel_read(user_chan, user_buf, USER_READ_BUF, 0);
		switch (rc) {
		  case SSH_OK:
			break;
		  case SSH_AGAIN:
			if (!ssh_is_connected(session))
				user_running = 0;
			continue;
		  case SSH_ERROR: {
			serv_log_error("%s read channel failed. ssh_channel_read(): %s", user_ip, ssh_get_error(session));
			handle_user_terminate_shell();
		  }
		}

		if (shell_cb.shell_read != NULL)
			shell_cb.shell_read(user_buf, rc);
	}

	serv_log("%s has disconnected.", user_ip);
	handle_user_terminate_shell();
}

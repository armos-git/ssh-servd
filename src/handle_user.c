/* This file contains ssh-servd functions to handle newly conencted users */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#define	LOG_MODULE_NAME		"SSH Server"

#include "server.h"
#include "log.h"
#include "mem.h"
#include "users.h"
#include "handle_user.h"
#include "shell_module.h"

static int			user_running;
static ssh_session		user_session;
static ssh_channel		user_chan;
static char			*user_buf;
static void			*user_hndl;
static shell_callbacks_t	shell_cb;

static int		auth;
static char		*user_uname;
static char		user_ip[INET_ADDRSTRLEN+1];
static char		module[MAXFILE];
static unsigned	int	user_level;


void	handle_user_unload_shell() {

	dlclose(user_hndl);
}

/* Clean server child termination */
void	handle_user_terminate() {

	if (user_uname != NULL)
		free(user_uname);

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

	char path[MAXFILE];

	if (serv_options.modules_dir[0])
		snprintf(path, MAXFILE - 1, "%s/%s", serv_options.modules_dir, module);
	else
		snprintf(path, MAXFILE - 1, "%s/%s", default_file(DEFAULT_MODDIR), module);

	user_hndl = dlopen(path, RTLD_LAZY);
	if (user_hndl == NULL) {
		serv_log_error("User %s (%s): Cannot load shell module %s", user_uname, user_ip, path);
		handle_user_terminate();
	}

	void (*shell_init)(shell_callbacks_t *a) = dlsym(user_hndl, "shell_init");
	if (shell_init == NULL) {
		serv_log_error("User %s (%s): Cannot load 'shell_init()' frome module %s", user_uname, user_ip, path);
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
}


static	int	login_pubkey(ssh_session session, const char *usr, struct ssh_key_struct *upub,
				char signature_state, void *user_data) {
	char keypath[MAXFILE];
	char *pubkey;
	int rc, ret;
	ssh_key spub;
	users_info_t info;
	FILE *fd;

	switch (signature_state) {
	  case SSH_PUBLICKEY_STATE_NONE:
		break;
	  case SSH_PUBLICKEY_STATE_VALID:
		serv_log("%s logged in with username '%s' (pubkey)", user_ip, usr);
		return SSH_AUTH_SUCCESS;
	  default:
		serv_log_warning("%s login failed with username '%s' (pubkey)", user_ip, usr);
		return SSH_AUTH_DENIED;
	}

	memset(keypath, 0, sizeof(keypath));

	if (serv_options.pubdir[0])
		snprintf(keypath, MAXFILE - 1, "%s/%s.pub", serv_options.pubdir, usr);
	else
		snprintf(keypath, MAXFILE - 1, "%s/%s.pub", default_file(DEFAULT_PUBDIR), usr);

	fd = fopen(serv_options.users_file, "r");
	if (fd == NULL) {
		serv_log_error("Cannot open users file %s: fopen(): %s", serv_options.users_file, strerror(errno));
		return SSH_AUTH_DENIED;
	}
	
	memset(&info, 0, sizeof(info));
	strncpy(info.user, usr, USERS_MAX_NAME - 1);

	rc = users_config_scan_user(fd, &info);
	switch (rc) {
	  case 1:
		user_uname = memalloc(strlen(usr) + 1);
		if (user_uname == NULL)
			handle_user_terminate();
		strcpy(user_uname, usr);
		strncpy(module, info.module, MAXFILE - 1);
		user_level = info.level;

		break;
	  case 2:
		serv_log_warning("Syntax error in users file %s while searching for user %s", serv_options.users_file, usr);
	  default:
		fclose(fd);
		return SSH_AUTH_DENIED;
	}
	fclose(fd);

	fd = fopen(keypath, "r");
	if (fd == NULL) {
		serv_log_error("%s cannot open pubkey file %s", user_ip, keypath);
		goto terminate;
	}

	while (!feof(fd)) {
		rc = fscanf(fd, "%ms", &pubkey);
		if (rc != 1)
			break;

		if (ssh_pki_import_pubkey_base64(pubkey, ssh_key_type(upub), &spub) != SSH_OK) {
			free(pubkey);
			continue;
		}

		if (!ssh_key_cmp(spub, upub, SSH_KEY_CMP_PUBLIC)) {
			auth = 1;
			free(pubkey);
			ssh_key_free(spub);
			break;
		}

		free(pubkey);
		ssh_key_free(spub);
	}


terminate:
	fclose(fd);

	if (auth) {
		ret = SSH_AUTH_SUCCESS;
	} else {
		ret = SSH_AUTH_DENIED;
		serv_log_warning("%s no valid pubkey found for username '%s'", user_ip, usr);
	}

	return ret;

}



static	int	shell_request(ssh_session session, ssh_channel channel, void *userdata) {

	/* load shell module */
	fprintf(stderr, "shell\n");
	handle_user_load_shell();
	return 0;
}

static	int	pty_request(ssh_session session, ssh_channel channel, const char *term, 
				int x,int y, int px, int py, void *userdata) {

	fprintf(stderr, "terminal x: %i. y: %i\n", x, y);
	return 0;
}



static	int	login_password(ssh_session session, const char *usr, const char *pass, void *userdata) {

	int ret;

	if ((user_level = users_auth(usr, pass, module))) {
		auth = 1;
		user_uname = memalloc(strlen(usr) + 1);
		if (user_uname == NULL)
			handle_user_terminate();
		strcpy(user_uname, usr);

		ret = SSH_AUTH_SUCCESS;
		serv_log("%s logged in with username '%s'", user_ip, user_uname);
	} else {
		ret = SSH_AUTH_DENIED;
		serv_log_warning("%s login failed with username '%s'", user_ip, usr);
	}

	return ret;
}


static struct 	ssh_channel_callbacks_struct channel_cb = {

	.channel_pty_request_function = pty_request,
	.channel_shell_request_function = shell_request
};

static	ssh_channel new_channel(ssh_session session, void *userdata) {

	if (user_chan != NULL)
		return NULL;

	user_chan = ssh_channel_new(session);
	if (user_chan == NULL) {
		serv_log_error("%s failed to create channel: ssh_channel_new(): %s", user_ip, ssh_get_error(session));
		handle_user_terminate();
	}

	ssh_callbacks_init(&channel_cb);
	ssh_set_channel_callbacks(user_chan, &channel_cb);
	return user_chan;
}	

/* Server child to handle a newly connected user */
void	handle_user(ssh_session session) {

	ssh_event eventloop;
	int rc;
	char keypath[MAXFILE];
	const char *ip;

	struct ssh_server_callbacks_struct serv_cb =  {
		.userdata = NULL,
		.auth_password_function = login_password,
		.auth_pubkey_function = login_pubkey,
		.channel_open_request_session_function = new_channel
	};

	auth = 0;
	user_chan = NULL;
	user_uname = NULL;
	user_session = session;
	memset(keypath, 0, sizeof(keypath));
	memset(module, 0, sizeof(module));

	ip = users_resolve_ip(session);
	strncpy(user_ip, ip, INET_ADDRSTRLEN);
	
	ssh_callbacks_init(&serv_cb);
	ssh_set_server_callbacks(session, &serv_cb);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		serv_log_error("%s: Error while exchanging keys. ssh_handle_key_exchange(): %s", user_ip, ssh_get_error(session));
		handle_user_terminate();
	}

	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
	eventloop = ssh_event_new();
	if (eventloop == NULL) {
		serv_log_error("%s failed to create an event context.", user_ip);
		handle_user_terminate();
	}

	ssh_event_add_session(eventloop, session);

	/* wait for auth and channel */
	while (!(auth && user_chan != NULL)) {
		rc = ssh_event_dopoll(eventloop, USER_POLL_TIMEOUT);
		switch (rc) {
		  case SSH_ERROR:
			serv_log_error("%s ssh_event_dopoll(): %s", user_ip, ssh_get_error(session));
			goto break_auth;
		  case SSH_AGAIN:
			/* timeout */
			if (!ssh_is_connected(session))
				goto break_auth;
			break;
		}
	}
break_auth:
	if (!auth) {
		serv_log_warning("%s login failed. Disconnecting...", user_ip);
		handle_user_terminate();
	}


	/*
				usr = ssh_message_auth_user(sshmsg);
				if (serv_options.pubdir[0])
					snprintf(keypath, MAXFILE - 1, "%s/%s.pub", serv_options.pubdir, usr);
				else
					snprintf(keypath, MAXFILE - 1, "%s/%s.pub", default_file(DEFAULT_PUBDIR), usr);

				if (!access(keypath, F_OK))
					ssh_message_auth_set_methods(sshmsg, SSH_AUTH_METHOD_PUBLICKEY);
				else
					ssh_message_auth_set_methods(sshmsg, SSH_AUTH_METHOD_PASSWORD);
				
				ssh_message_reply_default(sshmsg);
				break;
	*/

	/*
	*/


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

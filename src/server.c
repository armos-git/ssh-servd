#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include "log.h"


static	void	fatal(const char *msg, int err) {

	fprintf(stderr, "FATAL: %s: %s\n", strerror(err));
	_exit(EXIT_FAILURE);
}

/* Daemonize! */
static	void	daemonize() {

	pid_t pid, sid;

       	/* Fork off the parent process */
       	pid = fork();
       	if (pid < 0) 
		fatal("fork()", errno);

	/* Terminate parrent */
       	if (pid > 0)
		exit(EXIT_SUCCESS);

       	/* Change the file mode mask */
       	umask(0);

       	/* Create a new SID for the child process */
       	sid = setsid();
       	if (sid < 0)
		fatal("setsid()", errno);
        
       	/* Change the current working directory */
       	if ((chdir("/")) < 0)
		fatal("chdir()", errno);
        
       	/* Close out the standard file descriptors */
       	close(STDIN_FILENO);
       	close(STDOUT_FILENO);
       	close(STDERR_FILENO);	

	/* record server pid */
/*
	mypid = getpid();


	pidfile = fopen(PID_FILE, "w");
	if (pidfile != NULL) {
		fprintf(pidfile, "%u", mypid);
		fclose(pidfile);
	}
*/
}


int	handle_client(ssh_session session) {

	ssh_message sshmsg;
	ssh_channel chan;
	int auth, shell, retry;

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		fprintf(stderr, "ssh_bind_accept(): %s\n", ssh_get_error(session));
		exit(EXIT_FAILURE);
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
				if (auth_user(ssh_message_auth_user(sshmsg), ssh_message_auth_password(sshmsg))) {
					auth = 1;
					ssh_message_auth_reply_success(sshmsg, 0);
				} else {
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
		fprintf(stderr, "login failed!\n");
		ssh_disconnect(session);
		ssh_free(session);
		exit(EXIT_FAILURE);
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
		fprintf(stderr, "error: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		exit(EXIT_FAILURE);
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
		fprintf(stderr, "error: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		exit(EXIT_FAILURE);
	}
	
	int rc;
	char buf[1024];
	const char color[] = "\x1b[0m";
	ssh_channel_write(chan, color, strlen(color));
	while (1) {
		rc = ssh_channel_read(chan, buf, 1024, 0);
		ssh_channel_write(chan, buf, rc);
		write(1, buf, rc);
	}

	return 1;
}



int	main(int argc, char **argv) {

	return 0;

	ssh_session session;
	ssh_bind sshbind;
	unsigned int port = 50000;
	pid_t p;

	ssh_init();



	sshbind = ssh_bind_new();
	if (sshbind == NULL) {
		fprintf(stderr, "ssh_bind_new() failed1\n");
		exit(EXIT_FAILURE);
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "./ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "./ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "127.0.0.1");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);

	if (ssh_bind_listen(sshbind) < 0) {
		fprintf(stderr, "ssh_bind_listen(): %s\n", ssh_get_error(sshbind));
		exit(EXIT_FAILURE);
	}


	while (1) {
		session = ssh_new();
		if (session == NULL) {
			fprintf(stderr, "ssh_new() failed1\n");
			exit(EXIT_FAILURE);
		}

		if (ssh_bind_accept(sshbind, session) != SSH_OK) {
			fprintf(stderr, "ssh_bind_accept(): %s\n", ssh_get_error(sshbind));
			exit(EXIT_FAILURE);
		}

		p = fork();

		if (!p) {
			ssh_bind_free(sshbind);
			handle_client(session);
		}
	}

	return 0;
}


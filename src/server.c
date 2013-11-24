#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include "log.h"
#include "users.h"

static void		*bad_addr;
static sigjmp_buf	env;

/* Prints a fatal message to stderr */
static	void	fatal(const char *msg, int err) {

	if (err)
		fprintf(stderr, "FATAL: %s: %s\n", msg, strerror(err));
	else
		fprintf(stderr, "FATAL: %s\n", msg);

	_exit(EXIT_FAILURE);
}

/* SIGSEGV handler */
static	int	sigsegv_handler(int sig, siginfo_t *info, void *cont) {

	bad_addr = info->si_addr;
	siglongjmp(env, 0);
}


/* Saves execution state in case of a crash from SIGSEGV */
static	void	serv_save_state() {

	if (!sigsetjmp(env, 0))
		return;

	/* Returning from setlongjmp() here */

	/* Log the crash */
	serv_log_fatal("SSH Server", "Received SIGSEGV when trying to access memory address %p", bad_addr);

	/* Execute recovery code (quit for now)*/
	exit(EXIT_FAILURE);
}


/* Setup SIGSEGV, SIGPIPE, SIGCHLD
* Returns 0 on fail */
static	int	serv_setup_signals() {

	struct sigaction sighandle;

	/* Install SIGSEGV handler */
	memset(&sighandle, 0, sizeof(sighandle));
	sighandle.sa_flags = SA_SIGINFO;
	sighandle.sa_sigaction = (void *)&sigsegv_handler;
	if (sigaction(SIGSEGV, &sighandle, NULL) < 0)
		return 0;

	/* Ignore SIGPIPE */
	memset(&sighandle, 0, sizeof(sighandle));
	sighandle.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sighandle, NULL) < 0)
		return 0;

	/* Ignore SIGCHLD */
	memset(&sighandle, 0, sizeof(sighandle));
	sighandle.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &sighandle, NULL) < 0)
		return 0;

	return 1;
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


/* Clean server child termination */
static	void	handle_user_terminate(users_t *users, int x) {

	users_close(users[x]);
	users_detach(users);
	_exit(EXIT_FAILURE);
}

/* Server child to handle a newly connected user */
static	void	handle_user(int x) {

	users_t *users;
	ssh_message sshmsg;
	ssh_channel chan;
	ssh_session session;
	int auth, shell, retry;
	const char *usr, *pass;
	const char *ip;

	users = users_attach();
	session = users_get_session(users[x]);
	ip = users_get_ip(users[x]);

	if (ssh_handle_key_exchange(session) != SSH_OK) {
		serv_log_error("SSH Server", "ssh_handle_key_exchange(): %s", ssh_get_error(session));
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
					serv_log("SSH Server", "%s loged in with username %s", ip, usr);
				} else {
					serv_log_warning("SSH Server", "%s login failed with username %s", ip, usr);
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
		serv_log_warning("SSH Server", "%s login failed", ip);
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
		serv_log_error("SSH Server", "Error waiting for channel request from %s: %s", ip, ssh_get_error(session));
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
		serv_log_error("SSH Server", "Error waiting for shell request from %s: %s", ip, ssh_get_error(session));
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





int	main(int argc, char **argv) {

	users_t	*users;
	pid_t new_user;
	ssh_bind sshbind;
	ssh_session session;
	int index;

	bad_addr = NULL;
	serv_set_logfile("/home/vlad/Code/C/ssh-server/log");
	serv_log("SSH Server", "Boot");

	if (!serv_setup_signals())
		fatal("serv_setup_signals()", errno);

	daemonize();

	serv_save_state();

	users = users_create();
	users_init(users);
	ssh_init();

	sshbind = ssh_bind_new();
	if (sshbind == NULL) {
		serv_log_fatal("SSH Server", "ssh_bind_new() failed");
		exit(EXIT_FAILURE);
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "/home/vlad/Code/C/ssh-server/ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/home/vlad/Code/C/ssh-server/ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
	unsigned int port = 8000;
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);

	if (ssh_bind_listen(sshbind) < 0) {
		serv_log_fatal("SSH Server", "ssh_bind_listen(): %s", ssh_get_error(sshbind));
		exit(EXIT_FAILURE);
	}


	/* Server main loop */

	while (1) {
		session = ssh_new();
		if (session == NULL) {
			serv_log_fatal("SSH Server", "ssh_new() failed");
			exit(EXIT_FAILURE);
		}

		if (ssh_bind_accept(sshbind, session) != SSH_OK) {
			serv_log_error("SSH Server", "Error accepting ssh connection: ssh_bind_accept(): %s", ssh_get_error(sshbind));
			ssh_free(session);
			continue;
		}

		index = users_add(users, session);
		if (index == USERS_FULL) {
			serv_log_warning("SSH Server", "No more users allowd! Dropping ssh connection.");
			ssh_disconnect(session);
			ssh_free(session);
			continue;
		}

		serv_log("SSH Server", "%s established connection", users[index].ip);

		/* fork the new user */
		new_user = fork();
		if (new_user < 0) {
			serv_log_error("SSH Server", "Forking new user failed: fork(): %s", strerror(errno));
			users_close(users[index]);
			continue;
		}

		if (!new_user) {
			/* child */
			ssh_bind_free(sshbind); // close server in child
			handle_user(index); // will never return
		}

		/* parrent */
		users[index].pid = new_user;

		/* free resources in parent */
		users_free(users[index]);
	}

	return 0;
}


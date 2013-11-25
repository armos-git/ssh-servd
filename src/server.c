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
#include <getopt.h>
#include <sys/stat.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define	LOG_MODULE_NAME		"SSH Server"

#include "config_tool.h"
#include "log.h"
#include "users.h"
#include "handle_user.h"
#include "server.h"

static void		*bad_addr;
static sigjmp_buf	env;

/* Config options */
static char		listen_addr[INET_ADDRSTRLEN];
static int		listen_port;
static char		log_file[PATH_MAX];
static char		users_file[PATH_MAX];
static char		modules_dir[PATH_MAX];
static char		shell[PATH_MAX];
static char		modules[MODULES][PATH_MAX];


static	void	print_usage() {

	fprintf(stderr, "Usage:\n");
	exit(EXIT_FAILURE);
}

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
	serv_log_fatal("Received SIGSEGV when trying to access memory address %p", bad_addr);

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

static	int	load_config(const char *filename) {

	config_t conf;
	void *ptr;
	int i;

	/* sets up default values */
	strcpy(listen_addr, "0.0.0.0");
	listen_port = 8000;
	strcpy(log_file, "/var/log/ssh-server.log");
	memset(users_file, 0, sizeof(users_file));
	memset(modules_dir, 0, sizeof(modules_dir));
	memset(shell, 0, sizeof(shell));
	memset(modules, 0, sizeof(modules));

	if (config_init(&conf, filename) != CONFIG_OK) {
		fprintf(stderr, "Config: cannot load config file: %s\n", config_get_error(&conf));
		config_close(&conf);
		return 0;
	}

	config_set_filesize(&conf, CONFIG_TINY);
	config_set_string_buffer(&conf, PATH_MAX);

	config_bind_var(&conf, "listen", "%s", listen_addr);
	config_bind_var(&conf, "port", "%i", &listen_port);
	config_bind_var(&conf, "log", "%s", log_file);
	config_bind_var(&conf, "users", "%s", users_file);
	config_bind_var(&conf, "modules_dir", "%s", modules_dir);
	config_bind_var(&conf, "shell", "%s", shell);
	ptr = config_bind_var(&conf, "modules", "%s", NULL);
	for (i = 0; i < MODULES; i++)
		ptr = config_addto_var(ptr, &modules[i]);

	if (config_parse(&conf) != CONFIG_OK) {
		fprintf(stderr, "Config error: %s\n", config_get_error(&conf));
		config_close(&conf);
		return 0;
	}

	config_close(&conf);
	return 1;
}

void	manage_users(const char *cmd) {

	printf("%s\n", cmd);
	exit(EXIT_SUCCESS);
}

int	main(int argc, char **argv) {

	users_t	*users;
	pid_t new_user;
	ssh_bind sshbind;
	ssh_session session;
	int index;
	char c, *u_cmd;
	const char opts[] = "f:Du:";
	int opt_conf, opt_daemon, opt_users;


	/* parse options */
	if (argc == 1)
		print_usage();

	opt_conf = 0;
	opt_daemon = 0;
	opt_users = 0;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		  case 'f':
			opt_conf = 1;
			if (!load_config(optarg))
				exit(EXIT_FAILURE);
		  case 'D':
			opt_daemon = 1;
			break;
		  case 'u':
			opt_users = 1;
			u_cmd = optarg;
			break;
		  default:
			exit(EXIT_FAILURE);
		}
	}

	if (opt_users)
		manage_users(u_cmd);
	if (!opt_conf)
		fatal("No config file specified!", 0);

	bad_addr = NULL;
	serv_set_logfile("/home/vlad/Code/C/ssh-server/log");
	serv_log("Boot");

	if (!serv_setup_signals())
		fatal("serv_setup_signals()", errno);

	if (opt_daemon)
		daemonize();

	serv_save_state();

	users = users_create();
	users_init(users);
	ssh_init();

	sshbind = ssh_bind_new();
	if (sshbind == NULL) {
		serv_log_fatal("ssh_bind_new() failed");
		exit(EXIT_FAILURE);
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "/home/vlad/Code/C/ssh-server/ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/home/vlad/Code/C/ssh-server/ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
	unsigned int port = 8000;
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);

	if (ssh_bind_listen(sshbind) < 0) {
		serv_log_fatal("ssh_bind_listen(): %s", ssh_get_error(sshbind));
		exit(EXIT_FAILURE);
	}


	/* Server main loop */

	while (1) {
		session = ssh_new();
		if (session == NULL) {
			serv_log_fatal("ssh_new() failed");
			exit(EXIT_FAILURE);
		}

		if (ssh_bind_accept(sshbind, session) != SSH_OK) {
			serv_log_error("Error accepting ssh connection: ssh_bind_accept(): %s", ssh_get_error(sshbind));
			ssh_free(session);
			continue;
		}

		index = users_add(users, session);
		if (index == USERS_FULL) {
			serv_log_warning("No more users allowd! Dropping ssh connection.");
			ssh_disconnect(session);
			ssh_free(session);
			continue;
		}

		serv_log("%s established connection", users[index].ip);

		/* fork the new user */
		new_user = fork();
		if (new_user < 0) {
			serv_log_error("Forking new user failed: fork(): %s", strerror(errno));
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


#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <getopt.h>
#include <sys/stat.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define	LOG_MODULE_NAME		"SSH Server"
#define PHRASE_MAX		50

#include "config_tool.h"
#include "server.h"
#include "mem.h"
#include "log.h"
#include "users.h"
#include "handle_user.h"

/* Server configuration options */
serv_options_t		serv_options;

static void		*bad_addr;
static sigjmp_buf	env;

int			serv_running;
int			serv_term_sig;

static	void	print_usage() {

	fprintf(stderr, "Usage: ssh-servd [-fDku]\n\n");
	fprintf(stderr, "  -h         : prints this\n");
	fprintf(stderr, "  -f         : config file\n");
	fprintf(stderr, "  -D         : run as daemon\n");
	fprintf(stderr, "  -k rsa,dsa : generate rsa or dsa private keys\n");
	fprintf(stderr, "  -u add     : adds new users\n\n");
	exit(EXIT_FAILURE);
}

/* Prints a fatal message to stderr */
static	void	fatal(int abort, const char *msg, ...) {

	va_list ap;

	fprintf(stderr, "FATAL: ");

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	
	fprintf(stderr, "\n");

	if (abort)
		_exit(EXIT_FAILURE);
}

/* SIGSEGV handler */
static	int	sigsegv_handler(int sig, siginfo_t *info, void *cont) {

	bad_addr = info->si_addr;
	siglongjmp(env, 0);
}


/* SIGTERM and SIGINT handler */
static	void	sigterm_handler(int sig) {

	serv_running = 0;
	serv_term_sig = sig;
}


/* Saves execution state in case of a crash from SIGSEGV */
static	void	serv_save_state() {

	if (!sigsetjmp(env, 0))
		return;

	/* Returning from setlongjmp() here */

	/* Log the crash */
	serv_log_fatal("[pid %u] Received SIGSEGV when trying to access memory address %p", getpid(), bad_addr);

	/* Execute recovery code (quit for now)*/
	_exit(EXIT_FAILURE);
}


/* Setup SIGSEGV, SIGPIPE, SIGTERM, SIGINT, SIGCHLD
* Returns 0 on fail */
static	int	serv_setup_signals() {

	struct sigaction sighandle;

	/* Install SIGSEGV handler */
	memset(&sighandle, 0, sizeof(sighandle));
	sighandle.sa_flags = SA_SIGINFO;
	sighandle.sa_sigaction = (void *)&sigsegv_handler;
	if (sigaction(SIGSEGV, &sighandle, NULL) < 0)
		return 0;

	/* Install SIGTERM and SIGINT handler */
	memset(&sighandle, 0, sizeof(sighandle));
	sighandle.sa_handler = &sigterm_handler;
	if (sigaction(SIGTERM, &sighandle, NULL) < 0)
		return 0;
	if (sigaction(SIGINT, &sighandle, NULL) < 0)
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

	pid_t mypid, pid, sid;
	FILE *pidfile;

       	/* Fork off the parent process */
       	pid = fork();
       	if (pid < 0) 
		fatal(1, "fork(): %s", strerror(errno));

	/* Terminate parrent */
       	if (pid > 0)
		exit(EXIT_SUCCESS);

       	/* Change the file mode mask */
       	umask(0);

       	/* Create a new SID for the child process */
       	sid = setsid();
       	if (sid < 0)
		fatal(1, "setsid(): %s", strerror(errno));
        
       	/* Change the current working directory */
       	if ((chdir("/")) < 0)
		fatal(1, "chdir(): %s", strerror(errno));
        
       	/* Close out the standard file descriptors */
       	close(STDIN_FILENO);
       	close(STDOUT_FILENO);
#ifndef SERV_DEBUG
       	close(STDERR_FILENO);	
#endif

	/* record server pid */
	mypid = getpid();

	pidfile = fopen(PID_FILE, "w");
	if (pidfile != NULL) {
		fprintf(pidfile, "%u", mypid);
		fclose(pidfile);
	}
}

static	int	load_config(const char *filename) {

	config_t conf;


	if (config_init(&conf, filename) != CONFIG_OK) {
		fprintf(stderr, "Config error: cannot load config file: %s\n", config_get_error(&conf));
		config_close(&conf);
		return 0;
	}

	config_set_filesize(&conf, CONFIG_TINY);
	config_set_string_buffer(&conf, MAXFILE);

	config_bind_var(&conf, "listen", "%s", serv_options.listen_addr);
	config_bind_var(&conf, "port", "%i", &serv_options.listen_port);
	config_bind_var(&conf, "dsa_key", "%s", serv_options.dsakey);
	config_bind_var(&conf, "rsa_key", "%s", serv_options.rsakey);
	config_bind_var(&conf, "log", "%s", serv_options.log_file);
	config_bind_var(&conf, "users", "%s", serv_options.users_file);
	config_bind_var(&conf, "modules_dir", "%s", serv_options.modules_dir);
	config_bind_var(&conf, "pubkeys_dir", "%s", serv_options.pubdir);

	if (config_parse(&conf) != CONFIG_OK) {
		fprintf(stderr, "Config error: %s\n", config_get_error(&conf));
		config_close(&conf);
		return 0;
	}

	config_close(&conf);

	/* check for required options */
	if (!serv_options.listen_addr[0]) {
		fprintf(stderr, "Config error: please specify listen address!\n");
		return 0;
	}

	if (!serv_options.listen_port) {
		fprintf(stderr, "Config error: please specify listen port!\n");
		return 0;
	}


	if (!serv_options.log_file[0]) {
		fprintf(stderr, "Config error: please specify log file!\n");
		return 0;
	}

	if (!serv_options.users_file[0])
		strncpy(serv_options.users_file, default_file(DEFAULT_USERS), sizeof(serv_options.users_file) - 1);


	return 1;
}

static	void	manage_users(const char *cmd) {

	if (!strcmp(cmd, "add")) {
		users_config_new();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(cmd, "del") || !strcmp(cmd, "rem")) {
		users_config_rem();
		exit(EXIT_SUCCESS);
	}

	fprintf(stderr, "Unrecognized command '%s'\n", cmd);
	exit(EXIT_SUCCESS);
}

/* Generate server private keys */
static	void	generate_keys(const char *type) {

	char valid_rsa_bitlen[] = "RSA: 1024, 2048, 4096";
	char valid_dsa_bitlen[] = "DSA: 1024, 2048, 3072";
	char *phrase, *outfile, *valid_bitlen;
	ssh_key key;
	int len, rc;
	int key_type = SSH_KEYTYPE_UNKNOWN;

	ssh_init();

	phrase = NULL;
	outfile = NULL;
	phrase = malloc(USERS_MAX_PASS);
	if (phrase == NULL) {
		fatal(0, "Cannot allocate memory! malloc() failed: %s\n", strerror(errno));
		goto terminate;
	}

	if (!strcmp(type, "rsa")) {
		key_type = SSH_KEYTYPE_RSA;
		valid_bitlen = valid_rsa_bitlen;
	}
	if (!strcmp(type, "dsa")) {
		key_type = SSH_KEYTYPE_DSS;
		valid_bitlen = valid_dsa_bitlen;
	}
	if (key_type == SSH_KEYTYPE_UNKNOWN) {
		printf("Unknown key type: %s\n", type);
		goto terminate;
	}

	printf("Enter bit length (%s): ", valid_bitlen);
	fflush(stdout);
	scanf("%i", &len);

	printf("Enter passphrase: ");
	fflush(stdout);
	rc = read_tty(phrase, USERS_MAX_PASS - 1, 1);
	if (rc < 0)
		goto terminate;
	phrase[rc - 1] = 0;

	printf("Ouput file: ");
	fflush(stdout);
	scanf("%ms", &outfile);

	printf("Generating...");
	fflush(stdout);

	if (ssh_pki_generate(key_type, len, &key) != SSH_OK)
		goto terminate;

	if (ssh_pki_export_privkey_file(key, phrase[0] ? phrase : NULL, NULL, NULL, outfile) != SSH_OK) {
		ssh_key_free(key);
		goto terminate;
	}

	memset(phrase, 0, PHRASE_MAX);
	ssh_key_free(key);
	if (phrase != NULL)
		memset(phrase, 0, USERS_MAX_PASS);
	printf("Done. Private key saved to file: %s\n", outfile);

terminate:
	free(phrase);
	free(outfile);

	ssh_finalize();

	exit(EXIT_SUCCESS);
}


int	main(int argc, char **argv) {

	pid_t new_user;
	ssh_bind sshbind;
	ssh_session session;
	char c, *cmd;
	const char opts[] = "f:Du:k:h";
	int opt_config, opt_daemon, opt_users, opt_keygen;


	if (ssh_version(SSH_VERSION_INT(0,6,0)) == NULL)
		fatal(1, "Required at least libssh version 0.6.0!");

	bad_addr = NULL;
	opt_daemon = 0;
	opt_users = 0;
	opt_keygen = 0;
	opt_config = 0;
	memset(&serv_options, 0, sizeof(serv_options));

	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		  case 'f':
			opt_config = 1;
			if (!load_config(optarg))
				exit(EXIT_FAILURE);
			break;
		  case 'D':
			opt_daemon = 1;
			break;
		  case 'u':
			opt_users = 1;
			cmd = optarg;
			break;
		  case 'k':
			opt_keygen = 1;
			cmd = optarg;
			break;
		  case 'h':
			print_usage();
		  default:
			exit(EXIT_FAILURE);
		}
	}

	if (!opt_config) {
		if (!load_config(default_file(DEFAULT_CONFIG)))
			exit(EXIT_FAILURE);
	}
	
	if (opt_keygen)
		generate_keys(cmd);

	if (opt_users)
		manage_users(cmd);

	serv_set_logfile(serv_options.log_file);
	serv_log("Boot");


	if (!serv_setup_signals())
		fatal(1, "serv_setup_signals(): %s", strerror(errno));

	if (opt_daemon)
		daemonize();

	serv_save_state();

	ssh_init();

	sshbind = ssh_bind_new();
	if (sshbind == NULL) {
		serv_log_fatal("ssh_bind_new() failed");
		fatal(0, "ssh_bind_new() failed");
		goto serv_terminate;
	}

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, serv_options.dsakey[0] ? serv_options.dsakey : default_file(DEFAULT_DSAKEY));
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, serv_options.rsakey[0] ? serv_options.rsakey : default_file(DEFAULT_RSAKEY));
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, serv_options.listen_addr);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &serv_options.listen_port);

	if (ssh_bind_listen(sshbind) < 0) {
		serv_log_fatal("ssh_bind_listen(): %s", ssh_get_error(sshbind));
		fatal(0, "ssh_bind_listen(): %s", ssh_get_error(sshbind));
		goto serv_terminate;
	}


	/* Server main loop */

	serv_running = 1;
	serv_term_sig = 0;
	while (serv_running) {
		session = ssh_new();
		if (session == NULL) {
			serv_log_fatal("ssh_new() failed");
			fatal(0, "ssh_new() failed");
			break;
		}

		ssh_set_blocking(session, 1);

		if (ssh_bind_accept(sshbind, session) != SSH_OK) {
			serv_log_error("Error accepting ssh connection: ssh_bind_accept(): %s", ssh_get_error(sshbind));
			fatal(0, "Error accepting ssh connection: ssh_bind_accept(): %s", ssh_get_error(sshbind));
			ssh_free(session);
			continue;
		}


		serv_log("%s established connection", users_resolve_ip(session));

		/* fork the new user */
		new_user = fork();
		if (new_user < 0) {
			serv_log_error("Forking new user failed: fork(): %s", strerror(errno));
			fatal(0, "Forking new user failed: fork(): %s", strerror(errno));
			users_close(session);
			continue;
		}

		if (!new_user) {
			/* child */
			ssh_bind_free(sshbind); // close server in child
			handle_user(session); // will never return
		}

		/* parrent */

		/* free resources in parent */
		ssh_free(session);
	}

	if (serv_term_sig)
		serv_log_warning("Received signal %i", serv_term_sig);

serv_terminate:
	serv_log("Shutdown!");

	ssh_bind_free(sshbind);
	serv_free_log();

	ssh_finalize();

	exit(EXIT_FAILURE);
}


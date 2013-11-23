/* This file contains the ssh server logging functions */

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"

static char *log_file;

/* Sets up the log file name
 * returns 0 if malloc() failes!
*/
int	serv_set_logfile(const char *filename) {

	log_file = malloc(strlen(filename) + 1);
	if (log_file == NULL)
		return 0;

	strcpy(log_file, filename);

	return 1;
}

/* Logs "[time_string][module] type: msg"
 * returns 0 if fopen() fails.
 * Use macro functions form log.h
*/
int	__serv_log(int type, const char *module, const char *msg, ...) {

	FILE *f;
	char time_string[20];
	struct timeval tv;
	struct tm *ptm;
	va_list ap;

	f = fopen(log_file, "a");
	if (f == NULL)
		return 0;

	gettimeofday(&tv, NULL);
	ptm = localtime(&tv.tv_sec);
	strftime(time_string, sizeof(time_string), "%d.%m.%Y %H:%M:%S", ptm);

	fprintf(f, "[%s][%s] ", time_string, module);

	switch (type) {
	  case LOG_WARNING:
		fprintf(f, "WARNING: ");
		break;
	  case LOG_ERROR:
		fprintf(f, "ERROR: ");
		break;
	  case LOG_FATAL:
		fprintf(f, "FATAL: ");
		break;
	  case LOG_MSG:
	  default:
		break;
	}

	va_start(ap, msg);
	vfprintf(f, msg, ap);
	va_end(ap);

	fprintf(f, "\n");
	
	fflush(f);
	fclose(f);
	return 1;
}

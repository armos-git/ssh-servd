/*
*	 Versatile configuration file parser. Check the README and the header file
*			Written by Vlad - octal.s@gmail.com
*/

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "llist.h"
#include "hash.h"
#include "config_tool.h"



/* Check for system */
#ifdef	__OpenBSD__

  #ifdef NULL
    #undef NULL
    #define NULL	((void *)0)
  #endif
  #define	Strcpy(a, b, c)	strlcpy(a, b, c);
  #define	Strcat(a, b, c) strlcat(a, b, c);

#else

  #include "../src/_strlcpy.c"
  #define	Strcpy(a, b, c)	_strlcpy(a, b, c);
  #define	Strcat(a, b, c) strncat(a, b, c);

#endif


/* Tester macros */
#define is_valid_char(c)	( (c > 0x40 && c < 0x5b) || (c > 0x60 && c < 0x7b) || (c > 0x2f && c < 0x3a) || c == '_' )
#define is_valid_number(c)	(c > 0x2f && c < 0x3a)
#define is_valid_ascii(c)	(c > 0x1f && c < 0x7f)

/* memory allocation wraper calls */
#define	_memalloc(size)		__memalloc(size, __LINE__)
static	void	*__memalloc(size_t size, unsigned int line) {

	void *p;

	p = malloc(size);
	if (p == NULL) {
		fprintf(stderr, "%s:%d - %s\n", __FILE__, line, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return p;
}


/* helper macro */
#define	con	conf->config_file

/* read a single char and return from the function on error
 * ret_value - code to return (int) */
#define	read_char(c, ret_value) \
\
	if (config_read(conf, &c) < 0) { \
		set_error(conf, CONFIG_IO, "Read error !"); \
		return ret_value; \
	} \


/* tests the config file for EOF */
#define	config_eof(conf)	(conf->config_file.pos >= conf->config_file.size ? 1 : 0)

/* seeks in the config */
#define	config_seek(conf, offset, where) \
	switch(where) { \
		case SEEK_SET: \
			conf->config_file.pos = offset; \
			break; \
		case SEEK_CUR: \
			conf->config_file.pos += offset; \
			break; \
		case SEEK_END: \
			conf->config_file.pos = conf->config_file.size - 1; \
			break; \
	} \


/* returns the current confige file position */
#define	config_pos(conf)	conf->config_file.pos;


/* internal
 * reads a character from the mapped confige file */
static	int	config_read(config_t *conf, char *c) {

	if (con.pos < 0 || con.pos >= con.size)
		return -1;

	con.pos++;
	*c = con.config[con.pos - 1];
	return 0;

}


/* internal
 * opens and maps the config file in memory */
static	int	config_open(config_t *conf, const char *filename) {

	int fd;
	unsigned long size;
	struct stat st;
	size_t len;

	len = strlen(filename) + 1;
	con.file = _memalloc(len);
	Strcpy(con.file, filename, len);

	if (stat(filename, &st) < 0)
		return -1;

	size = st.st_size;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return -1;

	con.config = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (con.config == MAP_FAILED) {
		con.config = NULL;
		return -1;
	}

	close(fd);

	con.size = size;

	return 0;
}




/* internal 
*  sets an error in the config box
*  err - error code from header file
*  text - error message  */
static	void	set_error(config_t *conf, int err, const char *text, ...) {

	va_list args;
	char *temp;

	/* free previous error message if any */
	conf->err = err;
	if (conf->err_msg != NULL)
		free(conf->err_msg);

	conf->err_msg = _memalloc(ERROR_LEN);
	temp = _memalloc(ERROR_LEN);

	snprintf(conf->err_msg, ERROR_LEN, "%s:%i: ", conf->config_file.file, conf->line);

	va_start(args, text);
        vsnprintf(temp, ERROR_LEN, text, args);
        va_end(args);

	Strcat(conf->err_msg, temp, ERROR_LEN);
	free(temp);
	
}


/* internal 
* Checks if var is on the var list 
* Returns NULL if not present */
static	void	*check_in_varlist(config_t *conf, const char *var, size_t len) {

	llist_t *ptr, *next;
	config_var_t bind_var;


	ptr = __hash_find(conf->var_table, conf->hash_size, var);
	if (ptr == NULL)
		return NULL;
	if (ptr->data == NULL)
		return NULL;
	
	while (ptr != NULL) {
		next = llist_get(ptr, (void *)&bind_var);
		if (!strncmp(bind_var.name, var, len))
			return (void *)ptr;
		ptr = next;
	}

	return NULL;
}



/* internal
* simple layout var binder */
static	void	*simple_bind_var(config_t *conf, const char *name, const char *type, void *var) {

	config_var_t _var;
	void *ret = NULL;
	size_t len;

	/* mark the var as invalidated yet */
	_var.valid = 0;

	/* mark the var to be a single value */
	_var.opt = 0;

	len = strlen(type) + 1;
	_var.type = _memalloc(len);
	Strcpy(_var.type, type, len);

	len = strlen(name) + 1;
	_var.name = _memalloc(len);
	Strcpy(_var.name, name, len);

	/* is this var a list ? */
	if (var == NULL) {
		_var.var_sublist = _memalloc(sizeof(llist_t));
		_var.opt = 1;
		llist_init(_var.var_sublist);
		ret = _var.var_sublist;
	} else {

		/* store the actual var's address */
		_var.var_sublist = var;
	}

	/* add to the main list */
	__hash_add(conf->var_table, conf->hash_size, name, &_var, sizeof(_var));

	return ret;
}

/* internal
 * subject layout var binder */
static void	*subject_bind_var(config_t *conf, const char *name, const char *type, void *var) {

	config_var_t _var;
	config_var_t *subject;
	void *ret = NULL;
	size_t len;

	if (!strncmp(type, VAR_SUBJECT, sizeof(VAR_SUBJECT))) {
		Strcpy(conf->cur_subject, name, IDENT_LEN);

		len = strlen(name) + 1;
		_var.name = _memalloc(len);
		Strcpy(_var.name, name, len);

		_var.opt = 0;
		_var.valid = 0;
		_var.type = NULL;

		/* init a subject private hash table */
		__hash_init((void ***)&_var.var_sublist, CONFIG_SUB_HASH);

		__hash_add(conf->var_table, conf->hash_size, name, &_var, sizeof(_var));

		return NULL;
	}

	/* check if we are declaring var outside of a subject */
	if (!strlen(conf->cur_subject))
		return NULL;

	subject = check_in_varlist(conf, conf->cur_subject, IDENT_LEN);
	if (subject == NULL)
		return NULL;

	subject = llist_get_data((llist_t *)subject);

	len = strlen(type) + 1;
	_var.type = _memalloc(len);
	Strcpy(_var.type, type, len);

	len = strlen(name) + 1;
	_var.name = _memalloc(len);
	Strcpy(_var.name, name, len);

	_var.var_sublist = var;
	_var.opt = 0;
	_var.valid = 0;
	
	if (var == NULL) {
		_var.var_sublist = _memalloc(sizeof(llist_t));
		_var.opt = 1;
		llist_init(_var.var_sublist);
		ret = _var.var_sublist;
	} else {

		/* store the actual var's address */
		_var.var_sublist = var;
	}

	__hash_add((void **)subject->var_sublist, CONFIG_SUB_HASH, name, &_var, sizeof(_var));

	return ret;
}


/* internal
* free simple layout resources */
static	void	free_simple(config_t *conf) {

	llist_t *ptr;
	config_var_t _var;
	unsigned int i;

	for (i = 0; i < conf->hash_size; i++) {
	  ptr = conf->var_table[i];

	  while (ptr != NULL) {
		ptr = llist_get(ptr, &_var);
		if (_var.opt) {
			llist_destroy(_var.var_sublist);
			free(_var.var_sublist);
		}
		free(_var.name);
		free(_var.type);
	  }
	  llist_destroy(conf->var_table[i]);
	  free(conf->var_table[i]);
	}

}


/* internal
* free subject layout resources */
static	void	free_subject(config_t *conf) {

	unsigned int i, old_hash_size;
	void **old_hash;
	config_var_t var;
	llist_t *ptr;

	old_hash_size = conf->hash_size;
	old_hash = conf->var_table;

	for (i = 0; i < old_hash_size; i++) {
		ptr = conf->var_table[i];
		if (ptr == NULL)
			continue;

		while (ptr != NULL) {
			ptr = llist_get(ptr, &var);

			conf->var_table = (void **)var.var_sublist;
			conf->hash_size = CONFIG_SUB_HASH;

			free_simple(conf);

			conf->var_table = old_hash;

			free(var.name);
			__hash_destroy((void **)var.var_sublist);
			
		}
	  	llist_destroy(conf->var_table[i]);
	  	free(conf->var_table[i]);
	}

	conf->var_table = old_hash;
	conf->hash_size = old_hash_size;

	if (conf->cur_subject != NULL)
		free(conf->cur_subject);
}


/* internal
* Scans until end of line */
static	void	trim_line(config_t *conf) {

	char c;

	c = 0;
	while (c != '\n')
		if (config_read(conf, &c) < 0)
			break;
	conf->line++;
}


/* internal
 * validates a char with syntax 'c' */
static	int	validate_char(const char *src) {

	if (strlen(src) > 3)
		return 0;

	if (src[0] != '\'' || src[2] != '\'')
		return 0;

	return 1;
}


/* internal
* Checks for a valid identifier
* Returns: 1 - valid, 0 - invalid */
static	int	validate_identifier(const char *word) {

	int i;

	if (is_valid_number(word[0]) || strlen(word) == 0)
		return 0;

	for (i = 0; i < strlen(word); i++) {
		if (!is_valid_char(word[i]))
			return 0;
	}

	return 1;
}


/* internal
* Read a char with syntax 'c'
* Returns 1 - valid, 0 - invalid */ 
static	int	get_char(config_t *conf, char *dst) {

	int i;
	char c, p;

	for (i = 0; i < 2; i++) {

		read_char(c, 0);

		switch (i) {
			case 0:
				p = c;
				break;
			case 1:
				if (c != '\'') {
					set_error(conf, CONFIG_CHAR, "expected ' after char %c", p);
					return 0;
				}
				break;
		}
	}

	snprintf(dst, 4, "'%c'", p);

	return 1;
}


/* internal
 * Reads a string terminating with "
 * Returns 1 - valid, 0 - invalid */
static	int	get_string(config_t *conf, char *dst) {

	char c;
	int j;

	j = 0;
	while (1) {
		if (j == conf->textbuf_len) {
			set_error(conf, CONFIG_LONG, "string is too long... increase text buffer");
			return 0;
		}

		read_char(c, 0);

		switch (c) {
			case '\n':
			case '\r':
				set_error(conf, CONFIG_NEWLINE, "unexpected new line before end of string");
				return 0;
			case '\\':
				read_char(c, 0);

				/* add special chars here */
				switch (c) {
				  case '\r':
				  case '\n':
					conf->line++;
				        continue;
				  case 'n':
				  	c = '\n';
				  case '"':
				  case '\\':
					goto store;
				  default:
				        /* expected new line or special char */
					dst[j] = '\\';
					dst[j+1] = 0;
					set_error(conf, CONFIG_NEWLINE, "expected new line or special char after %s", dst);
					return 0;
				}
				continue;
			case '"':
				dst[j] = 0;
				return 1;
			default:
			store:
				dst[j] = c;
				j++;
				break;
		}
		
	}
	return 1;
}


/* Reads delimiter d
 * Returns 1 - found, 0 - not found */
static	int	get_delim(config_t *conf, char d) {

	char c;

	while (1) {
		read_char(c, 0);

		switch (c) {
			case ' ':
			case '\t':
				continue;
			case '\n':
			case '\r':
				conf->line++;
				return 0;
		}
		if (c == d) {
			return 1;
		} else {
			/* align */
			config_seek(conf, -1, SEEK_CUR);
			return 0;
		}
	}

	return 0;
}


/* internal
 * Checks for an assinger
 * Returns 1 - ok, 0 - not found */
static	int	get_assigner(config_t *conf) {

	char c;

	while (1) {

		read_char(c, 0);

		switch (c) {
			case '\n':
			case '\r':
				set_error(conf, CONFIG_NEWLINE, "expected '%c' after variable", conf->assigner);
				return 0;
			case ' ':
			case '\t':
				continue;
			default:
				if (c == conf->assigner) {
					return 1;
				} else {
					set_error(conf, CONFIG_ASSIGNER, "expected assigner %c", conf->assigner);
					return 0;
				}
		}

	}

	/* we should never get here */
	return 0;
}



/* internal
 * get the left value and store it in lvalue
 * Returns 1 - ok, 0 - error */
static	int	get_lvalue(config_t *conf, char *lvalue) {

	char c, p;
	int i, j;

	/* p is the previous char */
	p = 0;
	j = 0;
	i = 0;
	while (1) {
		if (j == IDENT_LEN) {
			set_error(conf, CONFIG_LONG, "left value too long");
			return 0;
		}

		read_char(c, 0);

		switch (c) {
			case ' ':
			case '\t':
				if (!p)
					continue;
				else
					goto validate;
			case '\n':
			case '\r':
				if (!p) {
					conf->line++;
					continue;
				}

				lvalue[j] = 0;
				set_error(conf, CONFIG_NEWLINE, "unexpected new line after %s", lvalue);
				return 0;

			default:
				if (c == conf->comment) {
					trim_line(conf);
					continue;
				}

				if (c == conf->assigner) {
					/* align before assigner */
					config_seek(conf, -1, SEEK_CUR);
					goto validate;
				}
				lvalue[j] = c;
				j++;
				p = c;
				break;
		}
		i++;
	}

	/* we should never get here */
	return 0;
validate:
	lvalue[j] = 0;
	return 1;
}


/* internal
 * Get the right value (one of multiple if any) and store it rvalue
 * Returns 1 - ok, 0 - error */
static	int	get_rvalue(config_t *conf, char *rvalue) {

	char c, p;
	unsigned int i, j;
	int ignore;
	int rc;

	/* p is the previous char */
	p = 0;
	j = 0;
	i = 0;
	ignore = 0;
	while (1) {
		if (j == conf->textbuf_len) {
			set_error(conf, CONFIG_LONG, "right value too long");
			return 0;
		}

		read_char(c, 0);

		switch (c) {
			case '\n':
			case '\r':
				if (!p) {
					set_error(conf, CONFIG_NEWLINE, "unexpected new line after variable");
					return 0;
				} else {
					conf->line++;
					goto validate;
				}
			case ' ':
			case '\t':
				if (p && i > 0) {
					ignore = 1;
					continue;
				} else {
					continue;
				}

			case '\\':
				read_char(c, 0);

				if (c == '\n' || c == '\r') {
					conf->line++;
					continue;
				}

				set_error(conf, CONFIG_NEWLINE, "expected new line after \\");
				return 0;
			case '"':
				if (!p) {
					rc = get_string(conf, rvalue);
					if (rc)
						rc += get_delim(conf, ',');
					return rc;
				} else {
					rvalue[j] = 0;
					set_error(conf, CONFIG_PARSE, "parse error after %s", rvalue);
 					return 0;
				}

			case '\'':
				if (!p) {
					rc = get_char(conf, rvalue);
					if (rc)
						rc += get_delim(conf, ',');
					return rc;
				} else {
					rvalue[j] = 0;
					set_error(conf, CONFIG_PARSE, "parse error after %s", rvalue);
					return 0;
				}

			case ',':
				if (!p) {
					set_error(conf, CONFIG_DELIM, "unexpected delimiter '%c'", c);
					return 0;
				}

				rvalue[j] = 0;
				/* return special value to indicate there are more values */
				return 2;
				break;

			default:
				if (c == conf->comment || ignore) {
					config_seek(conf, -1, SEEK_CUR);
					goto validate;
				}

				rvalue[j] = c;
				j++;
				p = c;
				
		}
		i++;
	}

	/* we should never get here */
	return 0;
validate:
	rvalue[j] = 0;
	return 1;
}


/* internal
 * This function will do actual store in the real variable if all conditions are met
 * The value n is used for multiple (list) values, otherwise 0 for single value
 * Returns 1 - ok, 0 - error */
static	int	validate_rvalue(config_t *conf, void *lvalue, const char *rvalue, unsigned long n) {


	int rc;
	config_var_t *node;
	void *dst = NULL;
	void *ptr = NULL;

	node = (config_var_t *)lvalue;


	/* check for multiple values */
	if (node->opt) {
		if (!conf->temp_list)
			return 1;

		ptr = conf->temp_list;
		ptr = llist_get(ptr, &dst);
		conf->temp_list = ptr;
	} else {
		dst = node->var_sublist;
	}

	if (!dst) {
		set_error(conf, CONFIG_ARRAY, "no more space in array '%s'", node->name);
		return 0;
	}

	/* is string ? */
	if (!strncmp(node->type, "%s", 3)) {
		Strcpy(dst, rvalue, conf->textbuf_len);
		return 1;
	}

	/* is char ? */
	if (!strncmp(node->type, "%c", 3)) {
		if (!validate_char(rvalue)) {
			set_error(conf, CONFIG_VALUE, "expected \'<char>\' after %s", node->name);
			return 0;
		}
		memcpy(dst, &rvalue[1], sizeof(char));
		return 1;
	}

	rc = 1;
	if (!sscanf(rvalue, node->type, dst)) {
		set_error(conf, CONFIG_PARSE, "invalid value for varibale %s", node->name);
		rc = 0;
	}


	return rc;

}

/* internal
* Validates a subject
* Returns 1 - ok, 0 - error */
static	int	get_subject(config_t *conf, char *subject) {

	int x, j;
	unsigned long l;
	char c, p;

	l = config_pos(conf);
	if (l)
		config_seek(conf, -1, SEEK_CUR);


	/* p is the previous char */
	/* x is a flag to test if we found the begining of the subject */ 
	j = 0;
	p = 0;
	x = 0;
	while (1) {
		if (j == IDENT_LEN) {
			set_error(conf, CONFIG_LONG, "subject too long");
			return 0;
		}
		read_char(c, 0);

		switch (c) {
			case '\n':
			case '\r':
				if (!p)
					continue;
				else
					goto quit_subject;
			case '[':
				if (!p) {
					x = 1;
					continue;
				} else {
					goto quit_subject;
				}
			case ']':
				if (p && x) {
					subject[j] = 0;
					return 1;
				}
			default:
				subject[j] = c;
				p = c;
				j++;

		}
	}


quit_subject:
	config_seek(conf, l, SEEK_SET);
	return 0;

}




/* internal
* This is the simple parser layout call. For details about syntax checkout the README
* Returns 1 - ok, 0 - error */
static	int	parse_simple(config_t *conf) {

	/* bunch of stupid vars :) */
	char var[IDENT_LEN];
	config_var_t *bind_var;
	int rc;
	unsigned long i;


	if (!get_lvalue(conf, var))
		return 0;

	if (!validate_identifier(var)) {
		set_error(conf, CONFIG_IDENT, "invalid identifier %s", var);
		return 0;
	}


	/* checks if the identifier is knowns to us */

	bind_var = check_in_varlist(conf, var, IDENT_LEN);
	if (!bind_var) {
		set_error(conf, CONFIG_UNDEFINED, "'%s' is not defined for this config", var);
		return 0;
	}

	bind_var = llist_get_data((llist_t *)bind_var);

	/* check for duplicate identifiers */
	if (bind_var->valid) {
		set_error(conf, CONFIG_DEFINED, "'%s' is already defined", var);
		return 0;
	}

	/* check for assigner */
	if (conf->assigner) {
		if (!get_assigner(conf))
			return 0;
	}


	/* array values */
	if (bind_var->opt) {

		rc = 2;
		i = 1;
		conf->temp_list = bind_var->var_sublist;
		while (rc == 2) {
			rc = get_rvalue(conf, conf->textbuf);
			if (!rc)
				return 0;
			if (!validate_rvalue(conf, bind_var, conf->textbuf, i))
				return 0;

			i++;
			
		}

		bind_var->valid = 1;
		return 1;
	}

	

	/* single value */
	if (!get_rvalue(conf, conf->textbuf))
		return 0;


	if (!validate_rvalue(conf, bind_var, conf->textbuf, 0))
		return 0;

	bind_var->valid = 1;

	return 1;
}



/* internal
 * subject parser */
static	int	parse_subject(config_t *conf) {

	int rc;
	char _subject[IDENT_LEN];
	config_var_t *subject;
	void **old_hash;
	unsigned int old_hash_size;


	/* check for subject */
	memset(_subject, 0, IDENT_LEN);
	rc = get_subject(conf, _subject);
	if (rc) {
		subject = check_in_varlist(conf, _subject, IDENT_LEN);
		if (subject == NULL) {
			set_error(conf, CONFIG_UNDEFINED, "subject '%s' is not defined for this config", _subject);
			return 0;
		}

		subject = llist_get_data((llist_t *)subject);

		if (subject->valid) {
			set_error(conf, CONFIG_DEFINED, "subject '%s' is already defined", _subject);
			return 0;
		}

		subject->valid = 1;

		Strcpy(conf->cur_subject, _subject, IDENT_LEN);
		conf->cur_subject_var = subject;
	}
	

	/* check if we are declaring vars out of a subject */
	if (conf->cur_subject_var == NULL) {
		set_error(conf, CONFIG_SCOPE, "declaring variable out of a subject");
		return 0;
	}

	subject = conf->cur_subject_var;

	old_hash = conf->var_table;
	old_hash_size = conf->hash_size;

	/* set the var table to point to the subject private hash table */
	conf->var_table = subject->var_sublist;
	conf->hash_size = CONFIG_SUB_HASH;
	rc = parse_simple(conf);

	/* restore the original hash table */
	conf->var_table = old_hash;
	conf->hash_size = old_hash_size;

	return rc;
}

/* future work */
static	int	parse_group(config_t *conf) {

	return CONFIG_OK;
}



/* Returns the last error msg string */
char	*config_get_error(config_t *conf) {

	return conf->err_msg;
}


/* sets the comment char to indiacte the start of comment. NOTE: no checking is done here */
void	config_set_comment(config_t *conf, char comment) {

	conf->comment = comment;
}


/* sets the assigner, 0 for none */
void	config_set_assigner(config_t *conf, char assigner) {

	conf->assigner = assigner;
}



/* sets the desired layout */
void	config_set_layout(config_t *conf, int layout) {

	if (layout == CONFIG_SUBJECT) {
		conf->cur_subject = _memalloc(IDENT_LEN + 1);
		memset(conf->cur_subject, 0, IDENT_LEN);
	}
	conf->layout = layout;
}


/* sets the text buffer length */
void	config_set_string_buffer(config_t *conf, unsigned int len) {

	conf->textbuf_len = len + 1;
	conf->textbuf = realloc(conf->textbuf, len + 1);
}


void	config_set_filesize(config_t *conf, unsigned int size_model) {

	conf->hash_size = size_model;

	__hash_destroy(conf->var_table);
	__hash_init(&conf->var_table, size_model);
}


/* Inits the config box 
* Returns != CONFIG_OK on error */
int	config_init(config_t *conf, const char *file) {

	con.file = NULL;
	con.config = NULL;
	con.size = 0;
	con.pos = 0;


	conf->line = 1;
	conf->cur_subject = NULL;
	conf->cur_subject_var = NULL;
	conf->layout = DEFAULT_LAYOUT;
	conf->comment = DEFAULT_COMMENT;
	conf->assigner = DEFAULT_ASSIGNER;
	conf->textbuf_len = DEFAULT_TEXTBUF;
	conf->hash_size = DEFAULT_HASH_SIZE;

	conf->err_msg = NULL;
	conf->err = CONFIG_OK;

	if (config_open(conf, file) < 0) {
		conf->line = 0;
		set_error(conf, CONFIG_OPEN, "Cannot open input file !");
		return conf->err;
	}

	conf->textbuf = _memalloc(conf->textbuf_len);
	__hash_init(&conf->var_table, conf->hash_size);

	return CONFIG_OK;
}


/* bind a var name to a physical place in memory
*  name - the var name
*  type - the var type
*  var - the physical var
*  Returns: NULL or pointer to node if the var is an array */
void	*config_bind_var(config_t *conf, const char *name, const char *type, void *var) {

	void *ret = NULL;

	/* check for duplicate declarations */
	if (check_in_varlist(conf, name, strlen(name)))
		return NULL;

	switch (conf->layout) {
		case CONFIG_SIMPLE:
			ret = simple_bind_var(conf, name, type, var);
			break;
		case CONFIG_SUBJECT:
			ret = subject_bind_var(conf, name, type, var);
			break;
	}

	return ret;
}


/* adds a value to an array
 * binded_var - pointer to a node returned by config_bind_var
 * var - the physical var */
void	*config_addto_var(void *binded_var, void *var) {

	void *data, *new;

	if (!binded_var || !var)
		return NULL;

	data = var;
	
	new = llist_add(binded_var, &data, sizeof(data));
	return new;
}



/* Parse the config file with the selected layout
* Returns != CONFIG_OK on error  */
int	config_parse(config_t *conf) {

	char c;
	int rc = 0;

	/* main parse loop, reads the whole config */
	while (!config_eof(conf)) {

		/* read a char */
		if (config_read(conf, &c) < 0)
			break;

		/* Skip comment lines */
		if (c == conf->comment) {
			trim_line(conf);
			continue;
		}

		/* Skip empty lines and white spaces*/
		switch (c) {
			case '\n':
			case '\r':
				conf->line++;
			case ' ':
				continue;
			case ',':
			case '\'':
			case '"':
				set_error(conf, CONFIG_PARSE, "parse error at '%c'", c);
				return conf->err;
		}

		/* Parse line */
		/* Go back one char so we are aligned */
		config_seek(conf, -1, SEEK_CUR);


		/* select the layout to parse */
		switch (conf->layout) {
			case CONFIG_SIMPLE:
				rc = parse_simple(conf);
				if (rc <= 0)
					return conf->err;
				break;
			case CONFIG_SUBJECT:
				rc = parse_subject(conf);
				if (rc <= 0)
					return conf->err;
				break;
			case CONFIG_GROUP:
				rc = parse_group(conf);
				if (rc <= 0)
					return conf->err;
				break;
			default:
				return CONFIG_ERR;
		}

	}


	return CONFIG_OK;
}

/* Close the config and free all resources */
void	config_close(config_t *conf) {


	/* check if file was opened and free proper memory only */
	if (con.config == NULL) {
		free(con.file);
		if (conf->err_msg != NULL)
			free(conf->err_msg);
		return;
	}

	/* free all binded vars attributes */
	switch (conf->layout) {
		case CONFIG_SIMPLE:
			free_simple(conf);
			break;
		case CONFIG_SUBJECT:
			free_subject(conf);
			break;
	}


	munmap(con.config, con.size);
	free(con.file);

	free(conf->textbuf);
	if (conf->err_msg != NULL) {
		free(conf->err_msg);
		conf->err_msg = NULL;
	}

	__hash_destroy(conf->var_table);
}

/* returns the config tool version */
const char      *config_version(int req_ver) {

        if (!req_ver || req_ver <= CONFIG_VERSION_NUM)
                return CONFIG_VERSION_STRING(CONFIG_VERSION_STR);

        return NULL;
}


#ifdef CONFIG_DEBUG

void	__debug_print_varlist(config_t *conf) {

	unsigned int i;
	config_var_t var;
	llist_t *ptr;

	for (i = 0; i < conf->hash_size; i++) {
		ptr = conf->var_table[i];
		if (ptr == NULL) {
			printf("%i -- n/a\n", i);
			continue;
		}

		printf("%i -- ", i);
		while (ptr != NULL) {
			ptr = llist_get(ptr, &var);
			printf("%s -> ", var.name);
		}

		printf("\n");
		
	}
}

#endif

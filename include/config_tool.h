/*				Config Tool
*
*	Check the README for instalation and usage. It is not tested with threads so
*	use it at your own risk. You can check the example programs provided.
*			Vlad - octal.s@gmail.com
*/

#ifndef	_CONFIG_TOOL_H
#define	_CONFIG_TOOL_H


#define CONFIG_VERSION_MAJOR     2   
#define CONFIG_VERSION_MINOR     4   

/* version control macros */
#define CONFIG_TO_STRING(s)      #s  
#define CONFIG_VERSION_NUM       CONFIG_VERSION(CONFIG_VERSION_MAJOR, CONFIG_VERSION_MINOR)
#define CONFIG_VERSION_DOT(a, b) a.b 

#define CONFIG_VERSION(a, b)     (a << 8 | b)    
#define CONFIG_VERSION_STR       CONFIG_VERSION_DOT(CONFIG_VERSION_MAJOR, CONFIG_VERSION_MINOR)
#define CONFIG_VERSION_STRING(a) CONFIG_TO_STRING(a)


/* Max identifier name length */
#define IDENT_LEN		1024
#define ERROR_LEN		IDENT_LEN + 255

#define	VAR_SUBJECT		"subject"

#define DEFAULT_LAYOUT		CONFIG_SIMPLE
#define DEFAULT_COMMENT		'#'
#define DEFAULT_ASSIGNER	0
#define DEFAULT_TEXTBUF		1025
#define DEFAULT_HASH_SIZE	CONFIG_SMALL

/* Config layouts */
enum config_layouts {
	CONFIG_SIMPLE = 1,
	CONFIG_SUBJECT,
	CONFIG_GROUP
};


/* Hash sizes for different config file sizes */
#define	CONFIG_TINY		10
#define	CONFIG_SMALL		100
#define CONFIG_MEDIUM		1000
#define CONFIG_LARGE		10000
#define CONFIG_HUGE		100000


/* Sub hash table size (used for the subject layout) */
#define CONFIG_SUB_HASH		10

/* error codes. Do not change used by internal calls */
enum config_error_codes {
	CONFIG_ERR = -1,
	CONFIG_OK,
	CONFIG_OPEN,
	CONFIG_IO,
	CONFIG_PARSE,
	CONFIG_IDENT,
	CONFIG_UNDEFINED,
	CONFIG_DEFINED,
	CONFIG_LONG,
	CONFIG_NEWLINE,
	CONFIG_ASSIGNER,
	CONFIG_CHAR,
	CONFIG_TYPE,
	CONFIG_VALUE,
	CONFIG_DELIM,
	CONFIG_ARRAY,
	CONFIG_SCOPE
};


/* configuratoin variable type */
typedef struct {

	void *var_sublist;
	char *name;
	int valid;
	char *type;
	unsigned int opt;

} config_var_t;



typedef struct {

	char *file;
	char *config;
	unsigned long size;
	unsigned long pos;

} config_file_t;



/* configuration box type */
typedef struct {

	config_file_t config_file;
	int layout, err;
	unsigned int textbuf_len;
	unsigned int line;
	unsigned int hash_size;
	char assigner, comment;
	void **var_table;
	char *cur_subject;
	void *cur_subject_var;
	char *textbuf;
	char *err_msg;
	void *temp_list;

} config_t;


/* Returns the last error msg string 
*
*  conf - a config box
*   
*  Return:
*	pointer to null terminated string with the error. NULL on no error. */

extern	char    *config_get_error(config_t *conf);


/* Sets the desired comment char to be used for starting a comment
*
*  conf - a config box
*  comment - the comment char
*
*  Return
*	void */

extern	void    config_set_comment(config_t *conf, char comment);


/* Sets the desired assigner char. The most commin is '='.
*
*  conf - a config box
*  assigner - the assigner char
*
*  Return
*  	void */
extern	void    config_set_assigner(config_t *conf, char assigner);


/* Selects which layout to use when parsing. For info about layouts checkout the README
*
*  conf - a config box
*  layout - the desired layout code (see top of header)
*
*  Return
*	void */

extern	void    config_set_layout(config_t *conf, int layout);


/* Sets the length of the text buffer which is used to store the data for strings.
* You should set the length big enough to hold your biggest string in your config.
*
*  conf - a config box
*  len - the desired length of the buffer
*
*  Return:
*	void */

extern	void    config_set_string_buffer(config_t *conf, unsigned int len);


/* Selects which file size layout to use when parsing. For info about file size layouts checkout the README
*
*  conf - a config box
*  size_model - the desired file size layout code (see top of header)
*
*  Return
*	void */
extern	void    config_set_filesize(config_t *conf, unsigned int size_model);


/* Inits the config box. Use after you set all the config attributes.
*
*  conf - a config box
*
*  Return:
*	!= CONFIG_OK on error */

extern	int     config_init(config_t *conf, const char *file);


/* Binds a var name to the actual var in your program. The values from the file will be converted and written to the binder var.
*
*  conf - a config box
*  name - the corresponding var name
*  type - the type of the variable. Used so it knows how to read the value.
*  var - pointer to the var in your program or NULL to indicate that the var is an array
*
*  Return:
*	NULL or pointer to a node if the var is an array */

extern	void    *config_bind_var(config_t *conf, const char *name, const char *type, void *var);



/* Adds a variable to an array.
*
*  binded_var - pointer to an array node returned by config_bind_var() with var == NULL
*
*  Return:
*  	void */

extern	void	*config_addto_var(void *binded_var, void *var);


/* Reads and parse the config file. This is where all the magic happens. If your box is setup correctly, you should see your
* vars filled with values :)
*
*  conf - a config box
*
*  Return:
*	!= CONFIG_OK on error */

extern	int	config_parse(config_t *conf);


/* Closes the config file and free all allocated memroy
*
*  conf - a config box
*
*  Return:
*	void */

extern	void    config_close(config_t *conf);


/* Checks for config tool version.
*
*  req_version - requiered version to check. Use macro CONFIG_VERSION(major,minor)
*                passing 0 will make it return the current verion
*
* Return:
*       version string or NULL if req_version > current versio */
extern const char       *config_version(int req_version);


#endif

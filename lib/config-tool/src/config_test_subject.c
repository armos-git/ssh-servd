#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include "config_tool.h"

int	main() {

	int i;
	char client_name[20];
	char stuff[50];
	int status;
	int count[5];
	int age;
	void *ptr;
	config_t myconf;

        if (config_version(CONFIG_VERSION(2,3)) == NULL) {
                fprintf(stderr, "This example requiers at least config tool version 2.3 !\n");
                return 0;
        }   

        printf("Running with config tool version %s\n", config_version(0));

        if (config_init(&myconf, "test_subject.conf") != CONFIG_OK) {
                printf("\nConfig file error -  %s\n\n", config_get_error(&myconf));
                config_close(&myconf);
                return 0;
        }   

	config_set_layout(&myconf, CONFIG_SUBJECT);
	config_set_filesize(&myconf, CONFIG_TINY);

	config_set_assigner(&myconf, ':');
	config_set_comment(&myconf, '$');


	/* When you define a subject all vars defined after it
		will belong to that subject */

	config_bind_var(&myconf, "clients", VAR_SUBJECT, NULL);
	config_bind_var(&myconf, "name", "%s", &client_name);
	config_bind_var(&myconf, "age", "%i", &age);

	config_bind_var(&myconf, "stuff", VAR_SUBJECT, NULL);
	config_bind_var(&myconf, "name", "%s", &stuff);
	config_bind_var(&myconf, "status", "%i", &status);

	ptr = config_bind_var(&myconf, "count", "%i", NULL);
	for (i = 0; i < 4; i++)
		ptr = config_addto_var(ptr, &count[i]);

	if (config_parse(&myconf) != CONFIG_OK) {
		printf("\nConfig file error -  %s\n\n", config_get_error(&myconf));
		config_close(&myconf);
		return 0;
	}

	config_close(&myconf);


	printf("\n\nclient name = %s\n", client_name);
	printf("client age = %i\n", age);
	printf("stuff = %s\n", stuff);
	printf("status = %i\n", status);

	for (i = 0; i < 4; i++)
		printf("count[%i] = %i\n", i, count[i]);

	printf("\n\n");

	return 0;
}

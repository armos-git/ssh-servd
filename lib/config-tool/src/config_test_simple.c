#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include "config_tool.h"

int	main() {

	int x, y, i;
	char letter;
	char clients[3][20];
	float pi;
	void *ptr;
	config_t myconf;
	
	if (config_version(CONFIG_VERSION(2,3)) == NULL) {
		fprintf(stderr, "This example requiers at least config tool version 2.3 !\n");
		return 0;
	}

	printf("Running with config tool version %s\n", config_version(0));

	if (config_init(&myconf, "test_simple.conf") != CONFIG_OK) {
		printf("\nConfig file error -  %s\n\n", config_get_error(&myconf));
		config_close(&myconf);
		return 0;
	}

	config_set_assigner(&myconf, '=');
	config_set_filesize(&myconf, CONFIG_TINY);

	config_bind_var(&myconf, "x", "%i", &x);
	config_bind_var(&myconf, "y", "%i", &y);
	config_bind_var(&myconf, "letter", "%c", &letter);
	config_bind_var(&myconf, "pi", "%f", &pi);

	ptr = config_bind_var(&myconf, "clients", "%s", NULL);
	for (i = 0; i < 3; i++)
		ptr = config_addto_var(ptr, &clients[i]);

	
	if (config_parse(&myconf) != CONFIG_OK) {
		printf("\nConfig file error -  %s\n\n", config_get_error(&myconf));
		config_close(&myconf);
		return 0;
	}

	config_close(&myconf);


	printf("\n\n");
	printf("x, y = %i, %i\n", x, y);
	printf("pi = %f\n", pi);
	printf("letter = %c\n", letter);

	for (i = 0; i < 3; i++)
		printf("clients[%i] = %s\n", i, clients[i]);

	printf("\n");

	return 0;
}

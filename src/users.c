#include <string.h>

int	auth_user(const char *user, const char *pass) {

	if (strcmp(user, "vlad"))
		return 0;
	if (strcmp(pass, "1234"))
		return 0;
	return 1;
}

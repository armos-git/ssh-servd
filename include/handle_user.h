#ifndef HANDLE_USER_H
#define HANDLE_USER_H

#define USER_READ_BUF		2048
#define	USER_POLL_TIMEOUT	20000 // ms

extern	void	handle_user(ssh_session session);

#endif /* HANDLE_USER_H */

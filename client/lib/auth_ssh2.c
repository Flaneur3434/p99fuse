#include <libssh2.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "9pfs.h"

// connect to ssh server and authenticate
// direct forwarding method
void
auth_ssh2(FFid *f) {
	char buf[46 + 6 + 1];
	_9pread(f, buf, sizeof buf);
	/* if (_9pread(f, buf, sizeof buf) < sizeof buf) { */
	/* 	DPRINT("Failed to get ssh auth server info\n"); */
	/* } */

	DPRINT("read back %s\n", buf);
}

#include <libssh2.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "9pfs.h"

void
auth_ssh2(FFid *f) {
	char buf[30];
	if (_9pread(f, buf, 13) < 13) {
		DPRINT("Failed to get ssh auth server info\n");
		return;
	}
	DPRINT("read back %s\n", buf);
}

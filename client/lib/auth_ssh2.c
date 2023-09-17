#include <libssh2.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "9pfs.h"

/*
 * afd contents
 * hostname (of client)
 * uname (of client)
 * pubkey location
 * port (of client)
 */

typedef struct SSH2Info SSH2Info;
struct SSH2Info
{
	char	*cuid;		/* caller id */
	char	*suid;		/* server id */
	char	*cap;		/* capability (only valid on server side) */
	int	nsecret;	    /* length of secret */
	uchar	*secret;	/* secret */
};

void
auth_ssh2(FFid *f) {
	char buf[1024];
	if (_9pread(f, buf, 4) <= 0) {
		DPRINT("test 9pread\n");
	}

	DPRINT("read back %s\n", buf);
}

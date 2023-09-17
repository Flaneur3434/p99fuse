#pragma once

#include <libssh2.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>

#include "plan9.h"
#include "fcall.h"
#include "u9fs.h"

extern int chatty9p;

enum ClientMessageStatus {
	ServerInfo = 24,
	ServerStatus = 54,
};

enum SshServerStatus {
	SUCC = 0,
	FAIL = -1,
};

typedef struct Ssh2Session Ssh2Session;
struct Ssh2Session {
	enum ClientMessageStatus cli_mesg_state;
	enum SshServerStatus server_status_mesg; // if cli_mesg_state is ServerInfo, this field is un-used
	char server_ip[13];
	char server_port[6];
};
/*
 * 1) send a Rauth message with information about the ssh server (port, address,
 *    ect.)
 * 2) Block until a message from ssh server reporting if authentication
 *    succeeded or failed
 * 3) 9write auth successed response
 */

static void
seterror(Fcall *f, char *error)
{
	f->type = Rerror;
	f->ename = error ? error : "programmer error";
}

/* open a connection with sshd to recieve direct forwarded messages */
static void
ssh2init() {
	return;
}

// Rauth message that contains information about the ssh server (port, address,
// ect.)
static char*
ssh2auth(Fcall *rx, Fcall *tx) {
	char *ep;
	Ssh2Session *sp = malloc(sizeof(Ssh2Session));
	Fid *auth_fid = newauthfid(rx->afid, sp, &ep);
	if (auth_fid == nil) {
		free(sp);
		return ep;
	}
	if (chatty9p) {
		fprint(2, "ssh2auth: afid %d\n", rx->afid);
	}

	sp->cli_mesg_state = ServerInfo;

	tx->aqid.type = QTAUTH;
	tx->aqid.path = 1;
	tx->aqid.vers = 0;
	return 0;
}

static int
readstr(Fcall *rx, Fcall *tx, char *s, int len)
{
	if (rx->offset >= len) {
		return 0;
	}

	tx->count = len - rx->offset;
	if (tx->count > rx->count) {
		tx->count = rx->count;
	}
	memcpy(tx->data, s + rx->offset, tx->count);
	return tx->count;
}

static char *
ssh2read(Fcall *rx, Fcall *tx) {
	Ssh2Session *sp;
	char *ep;

	Fid *f;
	f = oldauthfid(rx->fid, (void **)&sp, &ep);
	if (f == nil) {
		return ep;
	}
	if (chatty9p) {
		fprint(2, "ssh2read: afid %d state %d\n", rx->fid, sp->cli_mesg_state);
	}


	// test data
	char *ip = "192.168.1.43";
	char *port = "5640";
	// atad tset

	switch(sp->cli_mesg_state) {
	case ServerInfo:
			memcpy(sp->server_ip, ip, strlen(ip) + 1);
			memcpy(sp->server_port, port, strlen(port) + 1);

			// send ip and port as one string
			// sprintf

			readstr(rx, tx, sp->server_ip, strlen(sp->server_ip) + 1);

			sp->cli_mesg_state = ServerStatus;
			break;
	default:
		return "invalid state detected when returning server info";
	}

	return 0;
}

static char*
ssh2attach(Fcall *rx, Fcall *tx)
{
	Ssh2Session *sp;
	char *ep;

	Fid *f;
	f = oldauthfid(rx->afid, (void **)&sp, &ep);
	if (f == nil) {
		return ep;
	}

	if (chatty9p) {
		fprint(2, "ssh2attach: afid %d state %d\n", rx->fid, sp->cli_mesg_state);
	}

	switch(sp->cli_mesg_state) {
	case ServerStatus:
			// block until ssh server responses

			// test
			sp->server_status_mesg = FAIL;
			// tset

			if (sp->server_status_mesg == FAIL) {
				return "ssh authentication failed";
			}

			break;
	default:
		return "invalid state detected when returning authentication status";
	}

	return 0;
}

Auth authssh2 = {
	"ssh2",
	ssh2auth,
	ssh2attach,
	ssh2init,
	ssh2read,
};

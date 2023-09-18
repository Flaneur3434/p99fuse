#pragma once

#include <libssh2.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
 #include <netdb.h>

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
	char ssh_server_ip[INET6_ADDRSTRLEN];
	char ssh_server_port[6];
	char server_ip[INET6_ADDRSTRLEN];
	char server_port[6];
	int ssh_auth_sockfd;
};


Ssh2Session *sp;

static void
seterror(Fcall *f, char *error)
{
	f->type = Rerror;
	f->ename = error ? error : "programmer error";
}

/* open a connection with sshd to recieve direct forwarded messages */
static void
ssh2init() {
	sp = malloc(sizeof(Ssh2Session));

	int status;
	int yes = 1;

	struct addrinfo hints;
	struct addrinfo *servinfo;  // will point to the results

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	memset(sp, 0, sizeof (Ssh2Session)); // make sure the struct is empty
	hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
	memcpy(sp->server_port, "22000", 5); // port for communication
	// might want to read -A for arguments

	if ((status = getaddrinfo(nil, sp->server_port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}


	// loop through all the results and bind to the first we can
    for(struct addrinfo *p = servinfo; p != NULL; p = p->ai_next) {
		void *addr;

		// need to cast to different structs for IPv4 and IPv6
		// to convert binary IP address to string with inet_ntop
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        // convert the IP to a string
        inet_ntop(p->ai_family, addr, sp->server_ip, p->ai_addrlen);

        if ((sp->ssh_auth_sockfd = socket(p->ai_family, p->ai_socktype,
							 p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

		// check if socket is re-usable
        if (setsockopt(sp->ssh_auth_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
					   sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sp->ssh_auth_sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sp->ssh_auth_sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

	freeaddrinfo(servinfo); // free the linked-list
	return;
}

// return new auth_fid
// set data in global Ssh2Session
static char*
ssh2auth(Fcall *rx, Fcall *tx) {
	char *ep;
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

// change wat to write according to state
// ServerInfo - write server info to afid
// ServerStatus - listen to ssh_auth_sockfd and write if succeeded or failed to afid
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

// check up after your self
// free globabl state and such here cause client doesnt call tclunk after
// attatch
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

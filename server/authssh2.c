#pragma once

#include "u9fs.h"
#include "u9fsauth.h"

#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

extern int chatty9p;

static AuthArgs auth_args;

static SSH2_Config sshc;
static SSH2_Server server;
static RemoteClient client;

static void shutdown_ssh(void) {

}

static void
parse_args(void) {
	size_t arg_len = strlen(autharg); //ssh arguments
	size_t i = 0;

	/* get listening port */
	auth_args = nil;
}

static void
ssh2init(void) {
	/*
	 * autharg should contain information about:
	 *
	 * authentication type: NONE, PASSWORD, PUBLICKEY
	 * listening port
	 *
	 */
	int rc; /* error code */
	rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return;
    }

	struct addrinfo hints;
	struct addrinfo *servinfo;                // Pointer to linked list

	memset(&hints, 0, sizeof hints);   // make sure the struct is empty
	hints.ai_family = AF_UNSPEC;              // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;          // TCP stream sockets
	hints.ai_flags = AI_PASSIVE;              // fill in localhost IP

	if (auth_args.listening_port == nil) {
		auth_args.listening_port = "5640";
	}

	rc = getaddrinfo(nil, auth_args.listening_port, &hints, &servinfo);
	if (rc != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(rc));
		exit(1);
	}

    // loop through all the results returned by getaddrinfo and bind to the
	// first we can

	struct addrinfo *p;
	int yes = 1;        // used to check if socket is available for re-use

    for(p = servinfo; p != nil; p = p->ai_next) {
		libssh2_socket_t sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
        if (sock == LIBSSH2_INVALID_SOCKET) {
            fprintf(stderr, "failed to open socket.\n");
			continue;
        }
		rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (rc == -1) {
            perror("setsockopt");
            exit(1);
        }

		rc = bind(sock, p->ai_addr, p->ai_addrlen);
        if (rc == -1) {
            close(sock);
            perror("server: bind");
            continue;
        }

        break;
    }

	// check if socket binding was un-successful
	if (p == nil) {
		shutdown();
	}

	freeaddrinfo(servinfo);
}

/*
 * Fcall fields:
 * size[4] Tauth tag[2] afid[4] uname[s] aname[s]
 * size[4] Rauth tag[2] aqid[13]
 *
 * If return is non-nil, indicates error
 */
static char*
ssh2auth(Fcall *rx, Fcall *tx)
{
	USED(tx);
	USED(rx);
	if (chatty9p) {
		fprint(2, "ssh2auth: afid %d\n", rx->afid);
	}

	return 0;
}

/*
 * Fcall fields:
 * size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
 * size[4] Rattach tag[2] aqid[13]
 */
static char*
ssh2attach(Fcall *rx, Fcall *tx)
{
	USED(rx);
	USED(tx);
	return 0;
}

Auth authssh2 = {
	"ssh2",
	ssh2auth,
	ssh2attach,
	ssh2init,
	ssh2read,
	ssh2write,
	ssh2clunk,
};

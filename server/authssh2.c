#pragma once

#include "plan9.h"
#include "fcall.h"
#include "9fs.h"

#include <libssh2.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

extern int chatty9p;
uint32_t hostaddr;
const char *username;
libssh2_socket_t sock;
struct sockaddr_in sin_;
const char *fingerprint;
char *userauthlist;
int rc;
LIBSSH2_SESSION *session = NULL;
LIBSSH2_CHANNEL *channel;
LIBSSH2_AGENT *agent = NULL;
struct libssh2_agent_publickey *identity, *prev_identity = NULL;

static void shutdown_ssh2(void);

/*
 * Parse autharg
 * Ex: john@192.168.1.43:/mnt/9
 */
struct Username {
	const char *uname;
	uint8_t len;
};

struct Address {
	const char *addr;
	uint8_t len;
};

struct MountPoint {
	const char *mtpt;
	uint8_t len;
};

struct Username uname;
struct Address addr;
struct MountPoint mtpt;

static void
ssh2init(void) {
	size_t arg_len = strlen(autharg); //ssh arguments
	size_t i = 0;

	/* get username */
	uname.uname = autharg;
	for(; i < arg_len; ++i) {
		if (autharg[i] == '@') {
			uname.len = i;
			break;
		}
	}

	/* get address */
	i += 1; // move to next char
	addr.addr = autharg + i;
	for(; i < arg_len; ++i){
		if (autharg[i] == ':') {
			addr.len = i - uname.len - 1; // dont count '@'
			break;
		}
	}

	/* get mount point */
	i += 1; // move to next char
	mtpt.mtpt = autharg + i;
	mtpt.len = arg_len - (uname.len + addr.len) - 2; // dont count '@' and ':'
}

/*
 * Fcall fields:
 * size[4] Tauth tag[2] afid[4] uname[s] aname[s]
 * size[4] Rauth tag[2] aqid[13]
 */
static char*
ssh2auth(Fcall *rx, Fcall *tx)
{
	USED(tx);
	if (chatty9p) {
		fprint(2, "ssh2auth: afid %d\n", rx->afid);
	}

	char ip_addr[addr.len];
	strncpy(ip_addr, addr.addr, addr.len);
	hostaddr = inet_addr(ip_addr);
	username = rx->uname;
	rc = libssh2_init(0);

	if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
		return "libssh2 initialization failed";
    }

	sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket.\n");
        rc = 1;
        shutdown_ssh2(); return "failed to create socket";
    }

    sin_.sin_family = AF_INET;
    sin_.sin_port = htons(22);
    sin_.sin_addr.s_addr = hostaddr;

    if(connect(sock, (struct sockaddr*)(&sin_), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect.\n");
        shutdown_ssh2(); return "failed to connect";
    }

    /* Create a session instance */
    session = libssh2_session_init();

    if(!session) {
        fprintf(stderr, "Could not initialize SSH session.\n");
        shutdown_ssh2(); return "could not initialize ssh session";
    }

    rc = libssh2_session_handshake(session, sock);

    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        shutdown_ssh2(); return "failure to establish ssh session";
    }

    /* At this point we have not yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");

    for(int i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }

    fprintf(stderr, "\n");

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(session, username,
                                         (unsigned int)strlen(username));

    if(userauthlist) {
        fprintf(stderr, "Authentication methods: %s\n", userauthlist);

        if(!strstr(userauthlist, "publickey")) {
            fprintf(stderr, "'publickey' authentication is not supported\n");
            shutdown_ssh2(); return "publickey authentication is not supported";
        }

        /* Connect to the ssh-agent */
        agent = libssh2_agent_init(session);

        if(!agent) {
            fprintf(stderr, "Failure initializing ssh-agent support\n");
            rc = 1;
            shutdown_ssh2(); return "failure to initialize ssh-agent support";
        }

        if(libssh2_agent_connect(agent)) {
            fprintf(stderr, "Failure connecting to ssh-agent\n");
            rc = 1;
            shutdown_ssh2(); return "failure connecting to ssh-agent";
        }

        if(libssh2_agent_list_identities(agent)) {
            fprintf(stderr, "Failure requesting identities to ssh-agent\n");
            rc = 1;
            shutdown_ssh2(); return "failure requesting identities to ssh-agent";
        }

        for(;;) {
            rc = libssh2_agent_get_identity(agent, &identity, prev_identity);
            if(rc == 1)
                break;
            if(rc < 0) {
                fprintf(stderr,
                        "Failure obtaining identity from ssh-agent support\n");
                rc = 1;
                shutdown_ssh2(); return "Failure obtaining identity from ssh-agent support";
            }
            if(libssh2_agent_userauth(agent, username, identity)) {
                fprintf(stderr, "Authentication with username %s and "
                        "public key %s failed.\n",
                        username, identity->comment);
            }
            else {
                fprintf(stderr, "Authentication with username %s and "
                        "public key %s succeeded.\n",
                        username, identity->comment);
                break;
            }
            prev_identity = identity;
        }

        if(rc) {
            fprintf(stderr, "Could not continue authentication\n");
            shutdown_ssh2(); return "could not continue authentication";
        }
    }

	shutdown_ssh2(); return 0;
}

static inline void shutdown_ssh2(void) {
	if(agent) {
        libssh2_agent_disconnect(agent);
        libssh2_agent_free(agent);
    }

    if(session) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

    if(sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sock, 2);
    }

    fprintf(stderr, "all done\n");

    libssh2_exit();
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
	return "nil";
}

Auth authssh2 = {
	"ssh2",
	ssh2auth,
	ssh2attach,
	ssh2init,
};

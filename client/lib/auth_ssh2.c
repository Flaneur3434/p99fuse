#include <libssh2.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "9pfs.h"

typedef struct SystemInfo SystemInfo;
struct SystemInfo {
	const char *pubkey;
	const char *privkey;
	char username[30];
	char password[30];
};

typedef struct SshServerInfo SshServerInfo;
struct SshServerInfo {
	char *ip;
	int ip_len;
	char *port;
	int port_len;
};

// this makes sense!
static void
parse_ssh_info_mesg(char *buf, SshServerInfo *info) {
	info->ip = buf;
	char *tok = strpbrk(buf, ":");
	info->ip_len = tok - buf;

	info->port = tok+1;
	tok = strpbrk(info->port, ":");
	info->port_len = tok - (info->port);
}

static bool
compare_known_hosts(const char *server_fingerprint) {
	return true;
}

// connect to ssh server and authenticate
// direct forwarding method
void
auth_ssh2(FFid *f) {
	// consolidate system info
	SystemInfo sys_info = {0};
	sys_info.pubkey = ".ssh/id_rsa.pub";
	sys_info.privkey = ".ssh/id_rsa";
	getlogin_r(sys_info.username, 30);

	// big enough to hold IP address and Port number and null terminators
	char buf[INET6_ADDRSTRLEN + 6];
	SshServerInfo info;

	// get server info (ip and port)
	_9pread(f, buf, sizeof buf);
	parse_ssh_info_mesg(buf, &info);

	DPRINT("ip address of ssh server: %.*s %d\nconnection port of ssh server: %.*s %d\n",
		   info.ip_len, info.ip, info.ip_len, info.port_len, info.port, info.port_len);


	// setup variables and such ...
	char server_ip_addr[info.ip_len + 1];
	strncpy(server_ip_addr, info.ip, info.ip_len);
	server_ip_addr[info.ip_len] = '\0';

	char server_port[info.port_len + 1];
	strncpy(server_port, info.port, info.port_len);
	server_port[info.port_len] = '\0';

	int rc = 0; // error value

	LIBSSH2_SESSION *session = NULL;

	struct addrinfo *p = NULL;
	libssh2_socket_t ssh_sock = -1;
	int yes = 1;



	// ssh connection setup
	rc = libssh2_init(0);
	if(rc) {
        DPRINT("libssh2 initialization failed (%d)\n", rc);
        return;
    }

	// boiler plate to set up remote connection
	struct addrinfo hints, *servinfo;
	memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

	// create a new connection to default ssh port
	if ((rc = getaddrinfo(server_ip_addr, "22", &hints, &servinfo)) != 0) {
        DPRINT("getaddrinfo: %s\n", gai_strerror(rc));
        return;
    }

	// loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((ssh_sock = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == LIBSSH2_INVALID_SOCKET) {
            perror("server: socket");
            continue;
        }

        if (connect(ssh_sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(ssh_sock);
            perror("client: connect");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
	servinfo = NULL;

	if (p == NULL)  {
        DPRINT("server: failed to bind\n");
        goto shutdown;
    }

	/* Create a session instance */
    session = libssh2_session_init();
    if(session == NULL) {
        DPRINT("could not initialize SSH session\n");
        goto shutdown;
    }

	/* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
	rc = libssh2_session_handshake(session, ssh_sock);
    if(rc) {
        DPRINT("error when starting up SSH session: %d\n", rc);
        goto shutdown;
    }

	/* At this point we have not yet authenticated. The first thing to do is
     * check the hostkey's fingerprint against our known hosts
	 */
	const char *fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (compare_known_hosts(fingerprint) == false) {
        DPRINT("host fingerprint does not match any hosts in known_hosts\n");
		goto shutdown;
	}

	// check what authentication methods are available
    char *userauthlist = libssh2_userauth_list(session, sys_info.username, (unsigned int)strlen(sys_info.username));
	DPRINT("userauthlist: %s\n", userauthlist);
	return;

  shutdown:;
	if (servinfo != NULL) {
		freeaddrinfo(servinfo);
	}

	if(session != NULL) {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
    }

	close(ssh_sock);
	libssh2_exit();

	return;
}

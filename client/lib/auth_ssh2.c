#include <libssh2.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <termios.h>

#include "9pfs.h"

typedef struct SystemInfo SystemInfo;
struct SystemInfo {
	char pubkey[64];
	char privkey[64];
	char username[30];
	char password[30];
};

typedef struct SshServerInfo SshServerInfo;
struct SshServerInfo {
	char *ip;
	int ip_len;
	char *port;
	int port_len;
	char *auth_method;
	int auth_method_len;
};

// this makes sense!
static void
parse_ssh_info_mesg(char *buf, SshServerInfo *info) {
	info->ip = buf;
	char *tok = strpbrk(buf, ":");
	info->ip_len = tok - buf;

	info->port = tok + 1;
	tok = strpbrk(info->port, ":");
	info->port_len = tok - (info->port);

	info->auth_method = tok + 1;
	tok = strpbrk(info->auth_method, ":");
	info->auth_method_len = tok - (info->auth_method);
}

enum {
    AUTH_NONE = 0,
    AUTH_PASSWORD = 1,
    AUTH_PUBLICKEY = 2
};


static bool
compare_known_hosts(const char *server_fingerprint) {
	return true;
}

static void
get_password(char *password)
{
    static struct termios old_terminal;
    static struct termios new_terminal;

    //get settings of the actual terminal
    tcgetattr(STDIN_FILENO, &old_terminal);

    // do not echo the characters
    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    // set this as the new terminal options
    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

    // get the password
    // the user can add chars and delete if he puts it wrong
    // the input process is done when he hits the enter
    // the \n is stored, we replace it with \0
    if (fgets(password, BUFSIZ, stdin) == NULL) {
		password[0] = '\0';
	}
    else {
		password[strlen(password)-1] = '\0';
	}

    // go back to the old settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

static void
sys_info_init(SystemInfo *this) {
	getlogin_r(this->username, 30);

	const int pubkey_size = 64;
	const int privkey_size = 64;

	snprintf(this->pubkey, pubkey_size, "/home/%s/.ssh/id_rsa.pub", this->username);
	snprintf(this->privkey, privkey_size, "/home/%s/.ssh/id_rsa", this->username);
}

static void
server_info_init(SshServerInfo *this, char *ip_addr, char *port, char *auth_method) {
	strncpy(ip_addr, this->ip, this->ip_len);
	ip_addr[this->ip_len] = '\0';

	strncpy(port, this->port, this->port_len);
	port[this->port_len] = '\0';

	strncpy(auth_method, this->auth_method, this->auth_method_len);
	auth_method[this->auth_method_len] = '\0';
}

// connect to ssh server and authenticate
// direct forwarding method
void
auth_ssh2(FFid *f) {
	// consolidate system info
	SystemInfo sys_info = {0};
	sys_info_init(&sys_info);

	char buf[128];
	SshServerInfo info;

	// get server info (ip and port)
	_9pread(f, buf, sizeof buf);
	parse_ssh_info_mesg(buf, &info);

	DPRINT("ip address of ssh server: %.*s %d\nconnection port of ssh server: %.*s %d\nauth method: %.*s\n",
		   info.ip_len, info.ip, info.ip_len, info.port_len, info.port, info.port_len, info.auth_method_len, info.auth_method);


	// setup variables and such ...
	char server_ip_addr[info.ip_len + 1];
	char server_port[info.port_len + 1];
	char auth_method[info.auth_method_len + 1];
	server_info_init(&info, server_ip_addr, server_port, auth_method);

	int rc = 0; // error value

	LIBSSH2_SESSION *session = NULL;
	LIBSSH2_LISTENER *listener = NULL;
    LIBSSH2_CHANNEL *channel = NULL;

	struct addrinfo *p = NULL;
	libssh2_socket_t ssh_sock = -1;
	int yes = 1;

	libssh2_socket_t remote_ssh_bound_port = LIBSSH2_INVALID_SOCKET;
	libssh2_socket_t forwarding_sock = LIBSSH2_INVALID_SOCKET;

	// ----

	// ssh connection setup
	rc = libssh2_init(0);
	if(rc) {
        DPRINT("libssh2 initialization failed (%d)\n", rc);
        return;
    }

	// boiler plate to set up remote connection to ssh server
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
	if(userauthlist == NULL) {
		DPRINT("No authentication method found\n");
		goto shutdown;
	}

	DPRINT("Authentication methods: %s\n", userauthlist);

	// set available auth methods
	int auth = AUTH_NONE;
	if(strstr(userauthlist, "password")) {
		auth |= AUTH_PASSWORD;
	}
	if(strstr(userauthlist, "publickey")) {
		auth |= AUTH_PUBLICKEY;
	}

	// set auth method to the one server requested
	if(((auth & AUTH_PASSWORD) == AUTH_PASSWORD) && (strcmp(auth_method, "pass") == 0)) {
		auth = AUTH_PASSWORD;
	} else if(((auth & AUTH_PUBLICKEY) == AUTH_PUBLICKEY) && (strcmp(auth_method, "key") == 0)) {
		auth = AUTH_PUBLICKEY;
	} else {
		auth = AUTH_NONE;
	}

	if((auth & AUTH_PASSWORD) == AUTH_PASSWORD) {
		puts("Insert ssh login password:");
		get_password(sys_info.password);
		if(libssh2_userauth_password(session, sys_info.username, sys_info.password)) {
			DPRINT("Authentication by password failed.\n");
			goto shutdown;
		} else {
			DPRINT("Authentication by paswword succeeded.\n");
		}
	} else if((auth & AUTH_PUBLICKEY) == AUTH_PUBLICKEY) {
		if(libssh2_userauth_publickey_fromfile(session, sys_info.username, sys_info.pubkey, sys_info.privkey, NULL)) {
			DPRINT("Authentication by public key failed.\n");
			goto shutdown;
		} else {
			DPRINT("Authentication by public key succeeded.\n");
		}
	} else {
		DPRINT("No supported authentication methods found.\n");
		goto shutdown;
	}

	// send listening channel information to u9fs server
	sprintf(buf, "%d", remote_ssh_bound_port);
	_9pwrite(f, buf, sizeof(char) * strlen(buf));

	// boiler plate to set up port used for direct forwarding
	char shost[INET6_ADDRSTRLEN];
	unsigned int sport = -1;

	memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(server_ip_addr, NULL, &hints, &servinfo)) != 0) {
        DPRINT("getaddrinfo: %s\n", gai_strerror(rc));
        return;
    }

	// loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
		struct sockaddr *addr = p->ai_addr;
		if (p->ai_family == AF_INET) {
			inet_ntop(p->ai_family, &((struct sockaddr_in *)addr)->sin_addr, shost, sizeof shost);
		} else {
			inet_ntop(p->ai_family, &((struct sockaddr_in6 *)addr)->sin6_addr, shost, sizeof shost);
		}

		sport = htons(p->ai_family == AF_INET ?
					  ((struct sockaddr_in *)addr)->sin_port:
					  ((struct sockaddr_in6 *)addr)->sin6_port);

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
	servinfo = NULL;

	if (p == NULL)  {
        DPRINT("server: failed to bind\n");
        goto shutdown;
    }

	channel = libssh2_channel_direct_tcpip_ex(session, server_ip_addr, atoi(server_port), shost, sport);
	if (channel == NULL) {
		DPRINT("Could not open the direct-tcpip channel.\n"
			   "(Note that this can be a problem at the server."
			   " Please review the server logs.)\n");
		goto shutdown;
	}

	// Must use non-blocking IO hereafter due to the current libssh2 API
    // libssh2_session_set_blocking(session, 0);



	// TEST

	const char *signal = "SUCC";
	libssh2_channel_write(channel, signal, strlen(signal));


	// TSET

  shutdown:;
	if (servinfo != NULL) {
		freeaddrinfo(servinfo);
	}

	if(channel != NULL) {
		libssh2_channel_free(channel);
	}

	if (listener != NULL) {
		libssh2_channel_forward_cancel(listener);
	}

	if(session != NULL) {
		libssh2_session_disconnect(session, "Normal Shutdown");
		libssh2_session_free(session);
	}

	if (ssh_sock != LIBSSH2_INVALID_SOCKET) {
		shutdown(ssh_sock, 2);
		close(ssh_sock);
	}

	if (forwarding_sock != LIBSSH2_INVALID_SOCKET) {
		shutdown(forwarding_sock, 2);
		close(forwarding_sock);
	}

	libssh2_exit();
	return;
}

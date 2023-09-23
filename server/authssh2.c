#pragma once

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

#include <termios.h>

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
	char server_ip[INET6_ADDRSTRLEN];

	// for u9fs server
	int listening_sock;
	char ssh_channel_listening_port[6];

	// for ssh server
	int ssh_writing_sock;
	char ssh_channel_writing_port[6];

	char username[30];
	char password[30];
	char pubkey[64];
	char privkey[64];
};
Ssh2Session *sp;

static void
seterror(Fcall *f, char *error)
{
	f->type = Rerror;
	f->ename = error ? error : "programmer error";
}

/*
 * Open a connection with sshd to recieve direct forwarded messages
 * Prepare the server for incoming client requests by calling listen
 */
static void
ssh2init() {
	sp = malloc(sizeof(Ssh2Session));
	memset(sp, 0, sizeof (Ssh2Session)); // make sure the struct is empty

	// loop interfaces and get ip address
	struct ifaddrs *ifaddr;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(1);
	}

	struct ifaddrs *ifa = ifaddr;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (((ifa->ifa_flags & IFF_RUNNING) != IFF_RUNNING)
			|| ((ifa->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)) {
			continue;
		}

		int family = ifa->ifa_addr->sa_family;
		size_t addr_struct_size = 0;
		if (family == AF_INET) {
			addr_struct_size = sizeof(struct sockaddr_in);
		} else if (family == AF_INET6) {
			addr_struct_size = sizeof(struct sockaddr_in6);
		} else if (family == AF_PACKET){
			// i dont care
			continue;
		}

		getnameinfo(ifa->ifa_addr,
					addr_struct_size,
					sp->server_ip,
					NI_MAXHOST,
					NULL,
					0,
					NI_NUMERICHOST);
		break;
	}

	// create socket and bind to ip address
	int status;
	int yes = 1;
	struct addrinfo hints;
	struct addrinfo *servinfo;  // will point to the results

	memset(&hints, 0, sizeof hints); // make sure the struct is empty for defaults of getaddrinfo
	hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	if ((status = getaddrinfo(sp->server_ip, NULL, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}

	// loop through all the results and bind to the first we can
	struct addrinfo *p;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sp->listening_sock = socket(p->ai_family, p->ai_socktype,
							 p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }

		// set socket option so it is re-usable
        if (setsockopt(sp->listening_sock, SOL_SOCKET, SO_REUSEADDR, &yes,
					   sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sp->listening_sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sp->listening_sock);
            perror("bind");
            continue;
        }

		// need to cast to different structs for IPv4 and IPv6
		// to convert binary IP address to string with inet_ntop
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			socklen_t len = sizeof (struct sockaddr_in);
			if (getsockname(sp->listening_sock, (struct sockaddr *)ipv4, &len) == -1) {
				perror("getsockname");
			} else {
				snprintf(sp->ssh_channel_listening_port, 6, "%d", ntohs(ipv4->sin_port));
			}
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			socklen_t len = sizeof (struct sockaddr_in6);
			if (getsockname(sp->listening_sock, (struct sockaddr *)ipv6, &len) == -1) {
				perror("getsockname");
			} else {
				fprint(2, "ipv6 port: %d\n", ntohs(ipv6->sin6_port));
				snprintf(sp->ssh_channel_listening_port, 6, "%d", ntohs(ipv6->sin6_port));
			}
        }

        break;
    }

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
        exit(1);
	}

	// free the linked-lists
	freeaddrinfo(servinfo);
	freeifaddrs(ifaddr);

	const int BACKLOG = 5;
	if (listen(sp->listening_sock, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

	sp->cli_mesg_state = ServerInfo; // set flag

	return;
}

/*
 * return new auth_fid
 * set data in global Ssh2Session
 */
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

/*
 * change wat to write according to state
 * ServerInfo - write server info to afid
 */
static char *
ssh2read(Fcall *rx, Fcall *tx) {
	char *ep;
	Ssh2Session *session;

	Fid *f = oldauthfid(rx->afid, (void **)&session, &ep);
	if (f == nil) {
		return ep;
	}
	if (chatty9p) {
		fprint(2, "ssh2read: afid %d state %d\n", rx->afid, session->cli_mesg_state);
	}

	switch(session->cli_mesg_state) {
	case ServerInfo: {
		// send ip and port as one string
		const int max_mesg_len = 128;
		char mesg[max_mesg_len];
		/*
		 * message structure
		 * [1] ip
		 * [2] port
		 * [3] authentication method
		 *     key   - publickey
		 *     pass  - password
		 *     none  - none
		 */
		snprintf(mesg, max_mesg_len, "%s:%s:%s:", session->server_ip, session->ssh_channel_listening_port, "key");

		readstr(rx, tx, mesg, strnlen(mesg, max_mesg_len));

		session->cli_mesg_state = ServerStatus;
		break;
	}
	default:
		return "ssh2read: Invalid state detected when returning server info";
	}

	return 0;
}

static char *
ssh2write(Fcall *rx, Fcall *tx)
{
	char *ep;
	Ssh2Session *session;

	Fid *f = oldauthfid(rx->afid, (void **)&session, &ep);
	if (f == nil) {
		return ep;
	}
	if (chatty9p) {
		fprint(2, "ssh2write: afid %d\n", rx->afid);
	}

	// read afd for ssh direct forwarding port
	strncpy(session->ssh_channel_writing_port, rx->data, rx->count);
	tx->count = rx->count;

	session->ssh_channel_writing_port[5] = '\0';

	if (chatty9p) {
		fprint(2, "ssh listening port: %s\n", session->ssh_channel_writing_port);
	}

	return 0;
}

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
server_ssh_session_init(Ssh2Session *this) {
	getlogin_r(this->username, 30);

	const int pubkey_size = 64;
	const int privkey_size = 64;

	snprintf(this->pubkey, pubkey_size, "/home/%s/.ssh/id_rsa.pub", this->username);
	snprintf(this->privkey, privkey_size, "/home/%s/.ssh/id_rsa", this->username);
}


/*
 * Accept new connection from ssh server and comfirm authentication
 * Clean up after your self
 * free globabl state and such here cause client doesnt call tclunk after attach
 */
static char*
ssh2attach(Fcall *rx, Fcall *tx)
{
	Ssh2Session *sp;
	char *auth_error_mesg = NULL;
	int ssh_auth_fd = -1;


	// setup ssh forwarding listener
	int rc = 0; // error value

	LIBSSH2_SESSION *ssh_session = NULL;
	LIBSSH2_LISTENER *listener = NULL;
    LIBSSH2_CHANNEL *channel = NULL;

	struct addrinfo *p = NULL;
	int yes = 1;

	libssh2_socket_t ssh_sock = -1; // ssh handshake socket

	enum {
		AUTH_NONE = 0,
		AUTH_PASSWORD = 1,
		AUTH_PUBLICKEY = 2
	};

	const char *auth_method = "key";

	char *ep;
	Fid *f = oldauthfid(rx->afid, (void **)&sp, &ep);
	if (f == nil) {
		auth_error_mesg = ep;
		goto shutdown;
	}

	if (chatty9p) {
		fprint(2, "ssh2attach: afid %d state %d\n", rx->afid, sp->cli_mesg_state);
	}

	rc = libssh2_init(0);
	if(rc) {
        fprint(2, "libssh2 initialization failed (%d)\n", rc);
        return "libssh2 initialization failed";
    }

	/* Connect to SSH server */
    ssh_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(ssh_sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to open socket.\n");
        goto shutdown;
    }

    struct sockaddr_in sin;
	sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(sp->server_ip);
    if(INADDR_NONE == sin.sin_addr.s_addr) {
        fprintf(stderr, "inet_addr: Invalid IP address '%s'\n", sp->server_ip);
        goto shutdown;
    }

	// connect to ssh server port 22
    sin.sin_port = htons(22);
    if(connect(ssh_sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "Failed to connect to %s.\n", inet_ntoa(sin.sin_addr));
        goto shutdown;
    }

	// Create a session instance
	ssh_session = libssh2_session_init();
    if(ssh_session == NULL) {
        fprint(2, "could not initialize SSH session\n");
        goto shutdown;
    }

	/* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
	rc = libssh2_session_handshake(ssh_session, ssh_sock);
    if(rc) {
        fprint(2, "error when starting up SSH session: %d\n", rc);
        goto shutdown;
    }

	/* At this point we have not yet authenticated. The first thing to do is
     * check the hostkey's fingerprint against our known hosts
	 */
	const char *fingerprint = libssh2_hostkey_hash(ssh_session, LIBSSH2_HOSTKEY_HASH_SHA1);
	if (compare_known_hosts(fingerprint) == false) {
        fprint(2, "host fingerprint does not match any hosts in known_hosts\n");
		goto shutdown;
	}

	server_ssh_session_init(sp);

	// check what authentication methods are available
    char *userauthlist = libssh2_userauth_list(ssh_session, sp->username, (unsigned int)strlen(sp->username));
	if(userauthlist == NULL) {
		fprint(2, "No authentication method found\n");
		goto shutdown;
	}

	// set available auth methods
	int auth = AUTH_NONE;
	if(strstr(userauthlist, "password")) {
		auth |= AUTH_PASSWORD;
	}
	if(strstr(userauthlist, "publickey")) {
		auth |= AUTH_PUBLICKEY;
	}

	// set auth method to the one server requested
	if(((auth & AUTH_PASSWORD) == AUTH_PASSWORD) && (strcmp(auth_method, "int") == 0)) {
		auth = AUTH_PASSWORD;
	} else if(((auth & AUTH_PUBLICKEY) == AUTH_PUBLICKEY) && (strcmp(auth_method, "key") == 0)) {
		auth = AUTH_PUBLICKEY;
	} else {
		auth = AUTH_NONE;
	}

	if((auth & AUTH_PASSWORD) == AUTH_PASSWORD) {
		puts("Insert ssh login password:");
		get_password(sp->password);
		if(libssh2_userauth_password(ssh_session, sp->username, sp->password)) {
			fprint(2, "Authentication by password failed.\n");
			goto shutdown;
		} else {
			fprint(2, "Authentication by paswword succeeded.\n");
		}
	} else if((auth & AUTH_PUBLICKEY) == AUTH_PUBLICKEY) {
		if(libssh2_userauth_publickey_fromfile(ssh_session, sp->username, sp->pubkey, sp->privkey, NULL)) {
			fprint(2, "Authentication by public key failed.\n");
			goto shutdown;
		} else {
			fprint(2, "Authentication by public key succeeded.\n");
		}
	} else {
		fprint(2, "No supported authentication methods found.\n");
		goto shutdown;
	}

	return nil;

	// Create a channel that connects to the ssh server using the port opened by client for forwarding
	libssh2_socket_t listening_port = atoi(sp->ssh_channel_writing_port);
	listener = libssh2_channel_forward_listen_ex(ssh_session, sp->server_ip, listening_port, 0, 1);
	if(listener == NULL) {
        fprint(2, "Could not start the tcpip-forward listener.\n"
                        "(Note that this can be a problem at the server."
                        " Please review the server logs.)\n");
        goto shutdown;
    }

	// Accept a queued connection
	channel = libssh2_channel_forward_accept(listener);
	if(channel == NULL) {
        fprint(2, "Could not accept connection.\n"
                        "(Note that this can be a problem at the server."
                        " Please review the server logs.)\n");
        goto shutdown;
    }

	// Must use non-blocking IO hereafter due to the current libssh2 API
	libssh2_session_set_blocking(ssh_session, 0);









	char auth_buffer[20];
	switch(sp->cli_mesg_state) {
	case ServerStatus: {
		struct sockaddr_storage ssh_server_addr;
		socklen_t ssh_server_addr_size = sizeof ssh_server_addr;
		ssh_auth_fd = accept(sp->listening_sock, (struct sockaddr *)&ssh_server_addr, &ssh_server_addr_size);
		if (ssh_auth_fd == -1) {
			auth_error_mesg = strerror(errno);
            goto shutdown;
        }

		rc = recv(ssh_auth_fd, auth_buffer, sizeof auth_buffer, 0);

		if (rc == -1) {
			auth_error_mesg = strerror(errno);
			goto shutdown;
		} else if (rc == 0) {
			auth_error_mesg = strdup("ssh2attach: ssh server closed connection, could not authenticate");
			goto shutdown;
		}

		if (strncmp(auth_buffer, "SUCC", 20) == 0) {
			sp->server_status_mesg = SUCC;
		} else if (strncmp(auth_buffer, "FAIL", 20) == 0) {
			sp->server_status_mesg = FAIL;
			auth_error_mesg = strdup("ssh2attach: ssh authentication failed");
		} else {
			auth_error_mesg = strndup(auth_buffer, sizeof auth_buffer);
			goto shutdown;
		}

		break;
	}
	default:
		auth_error_mesg = strdup("ssh2attach: Invalid state detected when returning authentication status");
		goto shutdown;
	}

  shutdown:; // empty statement cause C is wack yo

	if(channel != NULL) {
		libssh2_channel_free(channel);
	}

	if (listener != NULL) {
		libssh2_channel_forward_cancel(listener);
	}

	if(ssh_session != NULL) {
		libssh2_session_disconnect(ssh_session, "Normal Shutdown");
		libssh2_session_free(ssh_session);
	}

	if (sp->listening_sock != -1) {
		close(sp->listening_sock);
	}

	if (ssh_auth_fd != -1) {
		close(ssh_auth_fd);
	}

	// TODO: probably missing more socks to close ....

	free(sp);
	libssh2_exit();
	return auth_error_mesg;
}

Auth authssh2 = {
	"ssh2",
	ssh2auth,
	ssh2attach,
	ssh2init,
	ssh2read,
	ssh2write,
};

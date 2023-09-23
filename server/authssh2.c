#pragma once

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

/*
 * Accept new connection from ssh server and comfirm authentication
 * Clean up after your self
 * free globabl state and such here cause client doesnt call tclunk after attach
 */
static char*
ssh2attach(Fcall *rx, Fcall *tx)
{
	Ssh2Session *sp;
	char *ep;

	char *auth_error_mesg = NULL;
	int forward_sock = -1;

	Fid *f = oldauthfid(rx->afid, (void **)&sp, &ep);
	if (f == nil) {
		auth_error_mesg = ep;
		goto shutdown;
	}

	if (chatty9p) {
		fprint(2, "ssh2attach: afid %d state %d\n", rx->afid, sp->cli_mesg_state);
	}

	char auth_buffer[20];
	switch(sp->cli_mesg_state) {
	case ServerStatus: {
		struct sockaddr_storage ssh_server_addr;
		socklen_t ssh_server_addr_size = sizeof ssh_server_addr;
		forward_sock = accept(sp->listening_sock, (struct sockaddr *)&ssh_server_addr, &ssh_server_addr_size);
		if (forward_sock == -1) {
			auth_error_mesg = strerror(errno);
            goto shutdown;
        }

		int rc = recv(forward_sock, auth_buffer, sizeof auth_buffer, 0);

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
	if (sp->listening_sock != -1) {
		close(sp->listening_sock);
	}

	if (forward_sock != -1) {
		close(forward_sock);
	}

	// TODO_: probably missing more socks to close ....

	free(sp);
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

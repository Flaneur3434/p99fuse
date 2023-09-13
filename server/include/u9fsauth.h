#pragma once

#include <libssh2.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>

typedef struct RemoteClient RemoteClient;
struct RemoteClient {
	const char *remote_listenhost;
	int remote_wantport;
	int remote_listenport;
};

typedef struct SSH2_Server SSH2_Server;
struct SSH2_Server {
	const char *server_ip;
	const char *local_destip;
	int local_destport;
};

typedef enum SSH2_AuthType SSH2_AuthType;
enum SSH2_AuthType {
    NONE = 0,
    PASSWORD = 1,
    PUBLICKEY = 2
};

typedef struct SSH2_Config SSH2_Config;
struct SSH2_Config {
	char *pubkey;
	char *privkey;
	char *username;
	char *password;

	SSH2_AuthType auth;
	socklen_t sinlen;
	const char * fingerprint;
	char *userauthlist;
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener;
	LIBSSH2_CHANNEL *channel;
	fd_set fds;
	struct timeval tv;
	ssize_t len;
	ssize_t wr;
	char buf[16384];
    libssh2_socket_t forwardsock;
};

typedef struct AuthArgs AuthArgs;
struct AuthArgs {
	char *listening_port;
};

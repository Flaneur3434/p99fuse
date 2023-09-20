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

// connect to ssh server and authenticate
// direct forwarding method
void
auth_ssh2(FFid *f) {
	// big enough to hold IP address and Port number and null terminators
	char buf[INET6_ADDRSTRLEN + 6];
	SshServerInfo info;

	_9pread(f, buf, sizeof buf);
	parse_ssh_info_mesg(buf, &info);

	DPRINT("ip address of ssh server: %.*s %d\nconnection port of ssh server: %.*s %d\n",
		   info.ip_len, info.ip, info.ip_len, info.port_len, info.port, info.port_len);
}

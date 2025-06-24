// SPDX-License-Identifier: Apache-2.0
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_kmod.h"

#define MAX_PAYLOAD 1024 // maximum payload size
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr   *nlh = NULL;
struct iovec       iov;
int                sock_fd;
struct msghdr      msg;

char *OPTION_CMD_TEST    = "-t";
char *OPTION_CMD_REQUEST = "-r";

void usage()
{
	printf("Usage: ./test_kmod_user [cmd]\n");
	printf("\t%s: %s\n", OPTION_CMD_TEST, CMD_TEST);
	printf("\t%s: %s\n", OPTION_CMD_REQUEST, CMD_REQUEST_MODULE);
}

char *parse_args(int argc, char *argv[])
{
	// check # of arguments
	char *cmd = NULL;
	if (argc == 1) {
		cmd = CMD_TEST; // default command is CMD_TEST
	} else if (argc > 2) {
		printf("Error: expected 0 or 1 arguments, but got %d\n", argc - 1);
		usage();
		return NULL;
	}

	// check len of first argument
	char *option = argv[1];
	int   len    = strlen(option);
	if (len != 2) {
		printf("Error: command '%s' not recognized\n", option);
		usage();
		return NULL;
	}

	// match option with cmd
	if (strncmp(option, OPTION_CMD_TEST, 2) == 0) {
		cmd = CMD_TEST;
	} else if (strncmp(option, OPTION_CMD_REQUEST, 2) == 0) {
		cmd = CMD_REQUEST_MODULE;
	} else {
		printf("Error: command '%s' not recognized\n", option);
		usage();
	}
	return cmd;
}

// initialize sock_fd
int create_netlink_socket()
{
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (sock_fd < 0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid    = getpid(); // self pid

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
}

// initialize msg
void prepare_netlink_message(char *cmd)
{
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid    = 0; // For Linux Kernel
	dest_addr.nl_groups = 0; // unicast

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len   = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_flags = 0;

	strncpy(NLMSG_DATA(nlh), cmd, strlen(cmd) + 1);

	iov.iov_base    = (void *)nlh;
	iov.iov_len     = nlh->nlmsg_len;
	msg.msg_name    = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov     = &iov;
	msg.msg_iovlen  = 1;
}

int main(int argc, char *argv[])
{
	// get cmd
	char *cmd = parse_args(argc, argv);
	printf("Using command: '%s'\n", cmd);
	if (!cmd) {
		return -1;
	}

	// send message to kernel module
	printf("Sending message to kernel\n");
	int err = create_netlink_socket();
	if (err) {
		return err;
	}
	prepare_netlink_message(cmd);
	sendmsg(sock_fd, &msg, 0);

	// read message from kernel
	printf("Waiting for message from kernel\n");
	recvmsg(sock_fd, &msg, 0);
	printf("Received message payload: %s\n", NLMSG_DATA(nlh));
	close(sock_fd);
}

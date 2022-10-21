/* CC0 license (public domain) - see LICENSE file for details */
#include <ccan/fdpass/fdpass.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define MAGIC_ACK_NUMBER 85

bool fdpass_send(int sockout, int fd)
{
	/* From the cmsg(3) manpage: */
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char c = 0, ack;
	bool result;
	int read_res;
	union {         /* Ancillary data buffer, wrapped in a union
			   in order to ensure it is suitably aligned */
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} u;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	memset(&u, 0, sizeof(u));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	/* Keith Packard reports that 0-length sends don't work, so we
	 * always send 1 byte. */
	iov.iov_base = &c;
	iov.iov_len = 1;

	result = sendmsg(sockout, &msg, 0) == 1;

	/* Wait for explicit ACK of socket send */
	while(result) {
		read_res = read(sockout, &ack, 1);

		if(read_res == 1 && ack == MAGIC_ACK_NUMBER)
			break;

		if(read_res != -1 || errno != EAGAIN)
			result = false;
	}

	return result;
}

int fdpass_recv(int sockin)
{
	/* From the cmsg(3) manpage: */
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	int fd;
	char c, ack;
	union {         /* Ancillary data buffer, wrapped in a union
			   in order to ensure it is suitably aligned */
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} u;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	iov.iov_base = &c;
	iov.iov_len = 1;

	if (recvmsg(sockin, &msg, 0) < 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg
	    || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = -EINVAL;
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

	/* Send an explicit ack of the socket being received */
	ack = MAGIC_ACK_NUMBER;
	if(write(sockin, &ack, 1) != 1) {
		close(fd);
		return -1;
	}
	
	return fd;
}

#include "config.h"
#include <arpa/inet.h>
#include <assert.h>
#include <common/ecdh.h>
#include <common/ecdh_hsmd.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <wire/wire_sync.h>

static int stashed_hsm_fd = -1;
static void (*stashed_failed)(enum status_failreason, const char *fmt, ...);

/* Temporary diagnosis (macOS flake): a subdaemon reads EOF on its HSM fd
 * while hsmd's client is still alive and never received the request, which
 * looks like the fd being aliased rather than a streaming error.  Print the
 * socket identity so we can tell whether it is still hsmd's socketpair
 * (AF_UNIX) or was recycled as, say, a peer TCP connection (AF_INET:port). */
static void ecdh_diag_fd(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if (getsockname(fd, (struct sockaddr *)&ss, &len) == 0) {
		if (ss.ss_family == AF_UNIX)
			status_debug("ecdh: fd %i local addr is AF_UNIX", fd);
		else if (ss.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
			status_debug("ecdh: fd %i local addr is AF_INET:%u",
				     fd, ntohs(sin->sin_port));
		} else
			status_debug("ecdh: fd %i local addr family %u",
				     fd, ss.ss_family);
	} else
		status_debug("ecdh: fd %i getsockname failed: %s",
			     fd, strerror(errno));

	len = sizeof(ss);
	if (getpeername(fd, (struct sockaddr *)&ss, &len) == 0) {
		if (ss.ss_family == AF_UNIX)
			status_debug("ecdh: fd %i peer addr is AF_UNIX", fd);
		else if (ss.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
			status_debug("ecdh: fd %i peer addr is AF_INET:%u",
				     fd, ntohs(sin->sin_port));
		} else
			status_debug("ecdh: fd %i peer addr family %u",
				     fd, ss.ss_family);
	} else if (errno == ENOTCONN)
		status_debug("ecdh: fd %i peer addr: not connected", fd);
	else
		status_debug("ecdh: fd %i getpeername failed: %s",
			     fd, strerror(errno));
}

void ecdh(const struct pubkey *point, struct secret *ss)
{
	const u8 *msg = towire_hsmd_ecdh_req(NULL, point);
	u8 *resp;

	assert(stashed_hsm_fd >= 0);
	assert(stashed_failed != NULL);

	/* Report errno and fd so a failure is diagnosable from the daemon log
	 * (macOS CI flake: intermittent "No hsmd ECDH response", errno 0 =
	 * EOF). */
	if (!wire_sync_write(stashed_hsm_fd, take(msg))) {
		ecdh_diag_fd(stashed_hsm_fd);
		stashed_failed(STATUS_FAIL_HSM_IO,
			       "Write ECDH to hsmd failed (fd %i): %s",
			       stashed_hsm_fd, strerror(errno));
	}

	resp = wire_sync_read(tmpctx, stashed_hsm_fd);
	if (!resp) {
		ecdh_diag_fd(stashed_hsm_fd);
		stashed_failed(STATUS_FAIL_HSM_IO,
			       "No hsmd ECDH response (fd %i): %s",
			       stashed_hsm_fd, strerror(errno));
	}

	/* Temporary diagnosis of the macOS flake: if hsmd's reply won't parse,
	 * dump exactly what we read so we can tell garbage apart from a real
	 * response (a parse failure that also corrupts the tal header shows up
	 * as a SIGABRT here rather than this log line). */
	if (!fromwire_hsmd_ecdh_resp(resp, ss)) {
		status_debug("ecdh: bad HSM reply (%zu bytes): %s",
			     tal_bytelen(resp),
			     tal_hexstr(tmpctx, resp, tal_bytelen(resp)));
		stashed_failed(STATUS_FAIL_HSM_IO,
			       "Invalid hsmd ECDH response");
	}
}

void ecdh_hsmd_setup(int hsm_fd,
		     void (*failed)(enum status_failreason,
				    const char *fmt, ...))
{
	stashed_hsm_fd = hsm_fd;
	stashed_failed = failed;
}
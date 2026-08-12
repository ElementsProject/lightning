#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/ecdh.h>
#include <common/ecdh_hsmd.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <wire/wire_sync.h>

static int stashed_hsm_fd = -1;
static void (*stashed_failed)(enum status_failreason, const char *fmt, ...);

void ecdh(const struct pubkey *point, struct secret *ss)
{
	const u8 *msg = towire_hsmd_ecdh_req(NULL, point);
	u8 *resp;

	assert(stashed_hsm_fd >= 0);
	assert(stashed_failed != NULL);

	/* Report errno so a failure is diagnosable from the daemon log
	 * (macOS CI flake: intermittent "No hsmd ECDH response"). */
	if (!wire_sync_write(stashed_hsm_fd, take(msg)))
		stashed_failed(STATUS_FAIL_HSM_IO,
			       "Write ECDH to hsmd failed: %s", strerror(errno));

	resp = wire_sync_read(tmpctx, stashed_hsm_fd);
	if (!resp)
		stashed_failed(STATUS_FAIL_HSM_IO,
			       "No hsmd ECDH response: %s", strerror(errno));

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
	/* Like read_fds in subd.c: don't trust sender's O_NONBLOCK state (issue #9060). */
	io_fd_block(hsm_fd, true);
}

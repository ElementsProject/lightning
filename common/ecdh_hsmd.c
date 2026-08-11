#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/ecdh.h>
#include <common/ecdh_hsmd.h>
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

	/* wire_sync_read/write tolerate a non-blocking fd (the HSM socketpair
	 * can be O_NONBLOCK on macOS), so no blocking toggling is needed here.
	 * Report errno so a failure is diagnosable from the daemon log. */
	if (!wire_sync_write(stashed_hsm_fd, take(msg)))
		stashed_failed(STATUS_FAIL_HSM_IO, "Write ECDH to hsmd failed: %s",
			       strerror(errno));

	resp = wire_sync_read(tmpctx, stashed_hsm_fd);
	if (!resp)
		stashed_failed(STATUS_FAIL_HSM_IO, "No hsmd ECDH response: %s",
			       strerror(errno));

	if (!fromwire_hsmd_ecdh_resp(msg, ss))
		stashed_failed(STATUS_FAIL_HSM_IO, "Invalid hsmd ECDH response");
}

void ecdh_hsmd_setup(int hsm_fd,
		     void (*failed)(enum status_failreason,
				    const char *fmt, ...))
{
	stashed_hsm_fd = hsm_fd;
	stashed_failed = failed;
}

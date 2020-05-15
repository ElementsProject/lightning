#include <common/ecdh_hsmd.h>
#include <common/utils.h>
#include <hsmd/gen_hsm_wire.h>
#include <wire/wire_sync.h>

static int stashed_hsm_fd = -1;
static void (*stashed_failed)(enum status_failreason, const char *fmt, ...);

void ecdh(const struct pubkey *point, struct secret *ss)
{
	const u8 *msg = towire_hsm_ecdh_req(NULL, point);

	if (!wire_sync_write(stashed_hsm_fd, take(msg)))
		stashed_failed(STATUS_FAIL_HSM_IO, "Write ECDH to hsmd failed");

	msg = wire_sync_read(tmpctx, stashed_hsm_fd);
	if (!msg)
		stashed_failed(STATUS_FAIL_HSM_IO, "No hsmd ECDH response");

	if (!fromwire_hsm_ecdh_resp(msg, ss))
		stashed_failed(STATUS_FAIL_HSM_IO, "Invalid hsmd ECDH response");
}

void ecdh_hsmd_setup(int hsm_fd,
		     void (*failed)(enum status_failreason,
				    const char *fmt, ...))
{
	stashed_hsm_fd = hsm_fd;
	stashed_failed = failed;
}

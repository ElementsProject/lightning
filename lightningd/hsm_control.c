#include "hsm_control.h"
#include "lightningd.h"
#include "subd.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/hsm_control.h>
#include <lightningd/log.h>
#include <string.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

u8 *hsm_sync_read(const tal_t *ctx, struct lightningd *ld)
{
	for (;;) {
		u8 *msg = wire_sync_read(ctx, ld->hsm_fd);
		if (!msg)
			fatal("Could not read from HSM: %s", strerror(errno));
		if (fromwire_peektype(msg) != STATUS_TRACE)
			return msg;

		log_debug(ld->log, "HSM TRACE: %.*s",
			  (int)(tal_len(msg) - sizeof(be16)),
			  (char *)msg + sizeof(be16));
		tal_free(msg);
	}
}

void hsm_init(struct lightningd *ld, bool newdir)
{
	const tal_t *tmpctx = tal_tmpctx(ld);
	u8 *msg;
	bool create;

	ld->hsm_fd = subd_raw(ld, "lightning_hsmd");
	if (ld->hsm_fd < 0)
		err(1, "Could not subd hsm");

	if (newdir)
		create = true;
	else
		create = (access("hsm_secret", F_OK) != 0);

	if (!wire_sync_write(ld->hsm_fd, towire_hsm_init(tmpctx, create)))
		err(1, "Writing init msg to hsm");

	ld->wallet->bip32_base = tal(ld->wallet, struct ext_key);
	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_init_reply(msg, NULL,
					&ld->id,
					&ld->peer_seed,
					ld->wallet->bip32_base))
		errx(1, "HSM did not give init reply");

	tal_free(tmpctx);
}

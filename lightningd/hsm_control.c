#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <daemon/log.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/status.h>
#include <string.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

u8 *hsm_sync_read(const tal_t *ctx, struct lightningd *ld)
{
	for (;;) {
		u8 *msg = wire_sync_read(ctx, ld->hsm_fd);
		if (!msg)
			fatal("Could not write from HSM: %s", strerror(errno));
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

	ld->hsm_fd = subd_raw(ld, "lightningd_hsm");
	if (ld->hsm_fd < 0)
		err(1, "Could not subd hsm");

	if (newdir)
		create = true;
	else
		create = (access("hsm_secret", F_OK) != 0);

	if (!wire_sync_write(ld->hsm_fd, towire_hsmctl_init(tmpctx, create)))
		err(1, "Writing init msg to hsm");

	ld->bip32_base = tal(ld, struct ext_key);
	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsmctl_init_reply(msg, NULL,
					&ld->dstate.id,
					&ld->peer_seed,
					ld->bip32_base))
		errx(1, "HSM did not give init reply");

	/* FIXME... */
	ld->wallet->bip32_base = ld->bip32_base;
	tal_free(tmpctx);
}

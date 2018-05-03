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
#include <lightningd/log_status.h>
#include <string.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

u8 *hsm_sync_read(const tal_t *ctx, struct lightningd *ld)
{
	for (;;) {
		u8 *msg = wire_sync_read(ctx, ld->hsm_fd);

		if (!msg)
			fatal("Could not read from HSM: %s", strerror(errno));
		if (log_status_msg(ld->log, msg))
			tal_free(msg);
		else
			return msg;
	}
}

void hsm_init(struct lightningd *ld)
{
	u8 *msg;

	ld->hsm_fd = subd_raw(ld, "lightning_hsmd");
	if (ld->hsm_fd < 0)
		err(1, "Could not subd hsm");

	ld->hsm_log = new_log(ld, ld->log_book, "hsmd:");
	if (!wire_sync_write(ld->hsm_fd, towire_hsm_init(tmpctx)))
		err(1, "Writing init msg to hsm");

	ld->wallet->bip32_base = tal(ld->wallet, struct ext_key);
	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsm_init_reply(msg,
					&ld->id,
					&ld->peer_seed,
					ld->wallet->bip32_base))
		errx(1, "HSM did not give init reply");
}

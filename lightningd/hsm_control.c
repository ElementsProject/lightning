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
	u8 *msg, *serialized_extkey;
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

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsmctl_init_reply(tmpctx, msg, NULL,
					&ld->dstate.id,
					&ld->peer_seed,
					&serialized_extkey))
		errx(1, "HSM did not give init reply");

	log_info_struct(ld->log, "Our ID: %s", struct pubkey, &ld->dstate.id);
	ld->bip32_base = tal(ld, struct ext_key);
	if (bip32_key_unserialize(serialized_extkey, tal_len(serialized_extkey),
				  ld->bip32_base) != WALLY_OK)
		errx(1, "HSM did not give unserializable BIP32 extkey");
	ld->wallet->bip32_base = ld->bip32_base;
}

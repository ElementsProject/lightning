/* Tool we can use to convert our testing gossip_store files */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/gossip_store.h>
#include <common/utils.h>
#include <gossipd/gossip_store_wiregen.h>
#include <unistd.h>
#include <wire/peer_wire.h>

/* Current versions we support */
#define GSTORE_MAJOR 0
#define GSTORE_MINOR 15

/* Obsolete ZOMBIE bit */
#define GOSSIP_STORE_ZOMBIE_BIT_V13 0x1000U

static bool upgrade_field(u8 oldversion,
			  be16 *hdr_flags,
			  u8 **msg)
{
	int type = fromwire_peektype(*msg);

	switch (oldversion) {
	case 10:
		/* Remove old channel_update with no htlc_maximum_msat */
		if (type == WIRE_CHANNEL_UPDATE
		    && tal_bytelen(*msg) == 130) {
			*msg = tal_free(*msg);
			return true;
		}
		/* fall thru */
	case 11:
	case 12:
		/* Remove private entries */
		if (type == WIRE_GOSSIP_STORE_PRIVATE_CHANNEL_OBS) {
			*msg = tal_free(*msg);
			return true;
		} else if (type == WIRE_GOSSIP_STORE_PRIVATE_UPDATE_OBS) {
			*msg = tal_free(*msg);
			return true;
		}
		/* fall thru */
	case 13:
		/* Discard any zombies */
		if (be16_to_cpu(*hdr_flags) & GOSSIP_STORE_ZOMBIE_BIT_V13) {
			*msg = tal_free(*msg);
			return true;
		}
	case 14:
		/* Add completed field */
		*hdr_flags |= CPU_TO_BE16(GOSSIP_STORE_COMPLETED_BIT);
		/* fall thru */
	case 15:
		/* Noop */
		return true;
	}

	return false;
}

int main(int argc, char *argv[])
{
	u8 oldversion, version;
	struct gossip_hdr hdr;

	setup_locale();
	if (!read_all(STDIN_FILENO, &oldversion, sizeof(oldversion)))
		errx(1, "Empty file");

	if (GOSSIP_STORE_MAJOR_VERSION(oldversion) != GSTORE_MAJOR)
		errx(1, "Unsupported major gossip_version %u (expected %u)",
		      GOSSIP_STORE_MAJOR_VERSION(oldversion), GSTORE_MAJOR);

	version = ((GSTORE_MAJOR << 5) | GSTORE_MINOR);
	if (!write_all(STDOUT_FILENO, &version, sizeof(version)))
		err(1, "Write error");

	while (read_all(STDIN_FILENO, &hdr, sizeof(hdr))) {
		u8 *msg;
		msg = tal_arr(NULL, u8, be16_to_cpu(hdr.len));
		if (!read_all(STDIN_FILENO, msg, tal_bytelen(msg)))
			err(1, "truncated file");
		if (!upgrade_field(oldversion, &hdr.flags, &msg))
			errx(1, "Cannot upgrade from version %u", oldversion);
		if (msg) {
			if (!write_all(STDOUT_FILENO, &hdr, sizeof(hdr))
			    || !write_all(STDOUT_FILENO, msg, tal_bytelen(msg)))
				err(1, "Write error");
			tal_free(msg);
		}
	}
	return 0;
}

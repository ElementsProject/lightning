#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <daemon/log.h>
#include <inttypes.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <lightningd/hsm/gen_hsm_status_wire.h>
#include <wally_bip32.h>

static void hsm_init_done(struct subdaemon *hsm, const u8 *msg,
			  struct lightningd *ld)
{
	u8 *serialized_extkey;

	if (!fromwire_hsmctl_init_response(hsm, msg, NULL, &ld->dstate.id,
					   &serialized_extkey))
		errx(1, "HSM did not give init response");

	log_info_struct(ld->log, "Our ID: %s", struct pubkey, &ld->dstate.id);
	ld->bip32_base = tal(ld, struct ext_key);
	if (bip32_key_unserialize(serialized_extkey, tal_len(serialized_extkey),
				  ld->bip32_base) != WALLY_OK)
		errx(1, "HSM did not give unserializable BIP32 extkey");

	io_break(ld->hsm);
}

static void hsm_finished(struct subdaemon *hsm, int status)
{
	if (WIFEXITED(status))
		errx(1, "HSM failed (exit status %i), exiting.",
		     WEXITSTATUS(status));
	errx(1, "HSM failed (signal %u), exiting.", WTERMSIG(status));
}

static enum subdaemon_status hsm_status(struct subdaemon *hsm, const u8 *msg,
					int fd)
{
	enum hsm_status_wire_type t = fromwire_peektype(msg);
	u8 *badmsg;
	struct peer *peer;
	u64 id;

	switch (t) {
	case WIRE_HSMSTATUS_CLIENT_BAD_REQUEST:
		if (!fromwire_hsmstatus_client_bad_request(msg, msg, NULL,
							   &id, &badmsg))
			errx(1, "HSM bad status %s", tal_hex(msg, msg));
		peer = peer_by_unique_id(hsm->ld, id);

		/* "Shouldn't happen" */
		errx(1, "HSM says bad cmd from %"PRIu64" (%s): %s",
		     id,
		     peer ? (peer->id ? type_to_string(msg, struct pubkey,
						       peer->id)
			     : "pubkey not yet known")
		     : "unknown peer",
		     tal_hex(msg, badmsg));

	/* We don't get called for failed status. */
	case WIRE_HSMSTATUS_INIT_FAILED:
	case WIRE_HSMSTATUS_WRITEMSG_FAILED:
	case WIRE_HSMSTATUS_BAD_REQUEST:
	case WIRE_HSMSTATUS_FD_FAILED:
	case WIRE_HSMSTATUS_KEY_FAILED:
		break;
	}
	return STATUS_COMPLETE;
}

void hsm_init(struct lightningd *ld, bool newdir)
{
	bool create;

	ld->hsm = new_subdaemon(ld, ld, "lightningd_hsm",
				hsm_status_wire_type_name,
				hsm_control_wire_type_name,
				hsm_status, hsm_finished, -1);
	if (!ld->hsm)
		err(1, "Could not subdaemon hsm");

	if (newdir)
		create = true;
	else
		create = (access("hsm_secret", F_OK) != 0);

	if (create)
		subdaemon_req(ld->hsm, take(towire_hsmctl_init_new(ld->hsm)),
			      -1, NULL, hsm_init_done, ld);
	else
		subdaemon_req(ld->hsm, take(towire_hsmctl_init_load(ld->hsm)),
			      -1, NULL, hsm_init_done, ld);

	if (io_loop(NULL, NULL) != ld->hsm)
		errx(1, "Unexpected io exit during HSM startup");
}


#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <daemon/log.h>
#include <inttypes.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <wally_bip32.h>

static bool hsm_init_done(struct subd *hsm, const u8 *msg, const int *fds,
			  struct lightningd *ld)
{
	u8 *serialized_extkey;

	if (!fromwire_hsmctl_init_reply(hsm, msg, NULL, &ld->dstate.id,
					&ld->peer_seed,
					&serialized_extkey))
		errx(1, "HSM did not give init reply");

	log_info_struct(ld->log, "Our ID: %s", struct pubkey, &ld->dstate.id);
	ld->bip32_base = tal(ld, struct ext_key);
	if (bip32_key_unserialize(serialized_extkey, tal_len(serialized_extkey),
				  ld->bip32_base) != WALLY_OK)
		errx(1, "HSM did not give unserializable BIP32 extkey");

	io_break(ld->hsm);
	return true;
}

static void hsm_finished(struct subd *hsm, int status)
{
	if (WIFEXITED(status))
		errx(1, "HSM failed (exit status %i), exiting.",
		     WEXITSTATUS(status));
	errx(1, "HSM failed (signal %u), exiting.", WTERMSIG(status));
}

static int hsm_msg(struct subd *hsm, const u8 *msg, const int *fds)
{
	enum hsm_wire_type t = fromwire_peektype(msg);
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

	/* HSM doesn't send these */
	case WIRE_HSMCTL_INIT:
	case WIRE_HSMCTL_HSMFD_ECDH:
	case WIRE_HSMCTL_HSMFD_CHANNELD:
	case WIRE_HSMCTL_SIGN_FUNDING:

	/* Replies should be paired to individual requests. */
	case WIRE_HSMCTL_INIT_REPLY:
	case WIRE_HSMCTL_HSMFD_CHANNELD_REPLY:
	case WIRE_HSMCTL_HSMFD_ECDH_FD_REPLY:
	case WIRE_HSMCTL_SIGN_FUNDING_REPLY:
		errx(1, "HSM gave invalid message %s", hsm_wire_type_name(t));
	}
	return 0;
}

void hsm_init(struct lightningd *ld, bool newdir)
{
	bool create;

	ld->hsm = new_subd(ld, ld, "lightningd_hsm", NULL,
			   hsm_wire_type_name,
			   hsm_msg, hsm_finished, -1);
	if (!ld->hsm)
		err(1, "Could not subd hsm");

	if (newdir)
		create = true;
	else
		create = (access("hsm_secret", F_OK) != 0);

	subd_req(ld->hsm, ld->hsm, take(towire_hsmctl_init(ld->hsm, create)),
		 -1, 0, hsm_init_done, ld);

	if (io_loop(NULL, NULL) != ld->hsm)
		errx(1, "Unexpected io exit during HSM startup");
}


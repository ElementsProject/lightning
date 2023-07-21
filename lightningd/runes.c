#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/rune/rune.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/runes.h>
#include <wallet/wallet.h>

/* This is lightningd->runes */
struct runes {
	struct rune *master;
	u64 next_unique_id;
	struct rune_blacklist *blacklist;
};

struct runes *runes_init(struct lightningd *ld)
{
	const u8 *msg;
	struct runes *runes = tal(ld, struct runes);
	const u8 *data;
	struct secret secret;

	runes->next_unique_id = db_get_intvar(ld->wallet->db, "runes_uniqueid", 0);
	runes->blacklist = wallet_get_runes_blacklist(runes, ld->wallet);

	/* Runes came out of commando, hence the derivation key is 'commando' */
	data = tal_dup_arr(tmpctx, u8, (u8 *)"commando", strlen("commando"), 0);
	msg = hsm_sync_req(tmpctx, ld, towire_hsmd_derive_secret(tmpctx, data));
	if (!fromwire_hsmd_derive_secret_reply(msg, &secret))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	runes->master = rune_new(runes, secret.data, ARRAY_SIZE(secret.data), NULL);

	return runes;
}

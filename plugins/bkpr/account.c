#include "config.h"

#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <plugins/bkpr/account.h>

struct account *new_account(const tal_t *ctx,
			    const char *name,
			    struct node_id *peer_id)
{
	struct account *a = tal(ctx, struct account);

	a->name = tal_strdup(a, name);
	a->peer_id = peer_id;
	a->is_wallet = streq(a->name, WALLET);
	a->we_opened = false;
	a->leased = false;
	a->onchain_resolved_block = 0;
	a->open_event_db_id = NULL;
	a->closed_event_db_id = NULL;
	a->closed_count = 0;

	return a;
}

bool is_channel_account(const struct account *acct)
{
	return !streq(acct->name, WALLET)
	       && !streq(acct->name, "external");
}

bool is_external_account(const struct account *acct)
{
	return streq(acct->name, "external");
}

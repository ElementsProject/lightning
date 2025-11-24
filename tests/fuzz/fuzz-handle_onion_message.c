#include "config.h"
#include <common/daemon_conn.h>
#include <common/ecdh.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/onion_message.h>
#include <fcntl.h>
#include <secp256k1_ecdh.h>
#include <setjmp.h>
#include <tests/fuzz/libfuzz.h>
#include <wire/peer_wiregen.h>

static int lightningd_fd;
static struct privkey priv;
static struct siphash_seed siphashseed;
jmp_buf fuzz_env;

/* MOCKS START */
void inject_peer_msg(struct peer *peer UNNEEDED, const u8 *msg TAKES UNNEEDED)
{ longjmp(fuzz_env, 1); }

u8 *towire_warningfmt(const tal_t *ctx UNNEEDED,
		      const struct channel_id *channel UNNEEDED,
		      const char *fmt UNNEEDED, ...)
{ longjmp(fuzz_env, 1); }

const struct siphash_seed *siphash_seed(void)
{ return &siphashseed; }
/* MOCKS END */

void ecdh(const struct pubkey *point, struct secret *ss)
{
	assert(secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
				priv.secret.data, NULL, NULL) == 1);
}

static struct daemon *new_daemon(const tal_t *ctx)
{
	struct daemon *daemon = talz(ctx, struct daemon);

	daemon->our_features = tal(ctx, struct feature_set);
	daemon->our_features->bits[NODE_ANNOUNCE_FEATURE] = tal_arr(ctx, u8, 0);
	set_feature_bit(&daemon->our_features->bits[NODE_ANNOUNCE_FEATURE], OPT_ONION_MESSAGES);

	daemon->scid_htable = tal(ctx, struct scid_htable);
	scid_htable_init(daemon->scid_htable);

	daemon->peers = tal(ctx, struct peer_htable);
	peer_htable_init(daemon->peers);

	memset(&daemon->mykey, 'a', sizeof(daemon->mykey));
	node_id_from_pubkey(&daemon->id, &daemon->mykey);

	daemon->master = daemon_conn_new(ctx, lightningd_fd, NULL, NULL, daemon);

	return daemon;
}

void init(int *argc, char ***argv)
{
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
	lightningd_fd = open("/dev/null", O_WRONLY);
	status_setup_sync(lightningd_fd);
	chainparams = chainparams_for_network("bitcoin");

	memset(&priv, 'b', sizeof(priv));
	memset(&siphashseed, 1, sizeof(siphashseed));
}

void run(const uint8_t *data, size_t size)
{
	struct daemon *daemon = NULL;
	struct peer *peer;
	struct pubkey dummy_key;

	if (setjmp(fuzz_env) != 0)
		goto cleanup;

	memset(&dummy_key, 'c', sizeof(dummy_key));

	daemon = new_daemon(tmpctx);
	if (!daemon)
		goto cleanup;

	peer = talz(tmpctx, struct peer);

	peer->daemon = daemon;
	node_id_from_pubkey(&peer->id, &dummy_key);
	peer->onionmsg_incoming_tokens = ONION_MSG_MSEC;

	/* Use fuzzer data as payload of the onion message. */
	const u8 *onion_msg = towire_onion_message(tmpctx, &dummy_key,
					tal_dup_arr(tmpctx, u8, data, size, 0));

	handle_onion_message(daemon, peer, onion_msg);

cleanup:
	if (daemon)
		tal_free(daemon->master);
	clean_tmpctx();
}

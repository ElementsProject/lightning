#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/version.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/invoice.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/onchain/onchain_wire.h>
#include <lightningd/options.h>
#include <sys/types.h>
#include <unistd.h>

char *bitcoin_datadir;

#define FIXME_IMPLEMENT() errx(1, "FIXME: Implement %s", __func__)

struct peer *find_peer_by_unique_id(struct lightningd *ld, u64 unique_id)
{
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		if (peer->unique_id == unique_id)
			return peer;
	}
	return NULL;
}

void notify_new_block(struct chain_topology *topo, u32 height);
void notify_new_block(struct chain_topology *topo, u32 height)
{
	/* FIXME */
}

void db_resolve_invoice(struct lightningd *ld,
			const char *label, u64 paid_num);
void db_resolve_invoice(struct lightningd *ld,
			const char *label, u64 paid_num)
{
	/* FIXME */
}

bool db_new_invoice(struct lightningd *ld,
		    u64 msatoshi,
		    const char *label,
		    const struct preimage *r);
bool db_new_invoice(struct lightningd *ld,
		    u64 msatoshi,
		    const char *label,
		    const struct preimage *r)
{
	/* FIXME */
	return true;
}

bool db_remove_invoice(struct lightningd *ld, const char *label);
bool db_remove_invoice(struct lightningd *ld, const char *label)
{
	/* FIXME */
	return true;
}

static struct lightningd *new_lightningd(const tal_t *ctx)
{
	struct lightningd *ld = tal(ctx, struct lightningd);

	list_head_init(&ld->peers);
	ld->peer_counter = 0;
	ld->dev_debug_subdaemon = NULL;
	htlc_in_map_init(&ld->htlcs_in);
	htlc_out_map_init(&ld->htlcs_out);
	ld->dev_disconnect_fd = -1;
	ld->log_book = new_log_book(ld, 20*1024*1024, LOG_INFORM);
	ld->log = new_log(ld, ld->log_book, "lightningd(%u):", (int)getpid());

	list_head_init(&ld->pay_commands);
	ld->portnum = DEFAULT_PORT;
	timers_init(&ld->timers, time_mono());
	ld->topology = new_topology(ld, ld->log);

	/* FIXME: Move into invoice daemon. */
	ld->invoices = invoices_init(ld);
	return ld;
}

static const char *daemons[] = {
	"lightningd",
	"lightningd_channel",
	"lightningd_closing",
	"lightningd_gossip",
	"lightningd_handshake",
	"lightningd_hsm",
	"lightningd_opening"
};

/* Check we can run them, and check their versions */
static void test_daemons(const struct lightningd *ld)
{
	size_t i;
	const tal_t *ctx = tal_tmpctx(ld);

	for (i = 0; i < ARRAY_SIZE(daemons); i++) {
		int outfd;
		const char *dpath = path_join(ctx, ld->daemon_dir, daemons[i]);
		const char *verstring;
		pid_t pid = pipecmd(&outfd, NULL, &outfd,
				    dpath, "--version", NULL);

		log_debug(ld->log, "testing %s", dpath);
		if (pid == -1)
			err(1, "Could not run %s", dpath);
		verstring = grab_fd(ctx, outfd);
		if (!verstring)
			err(1, "Could not get output from %s", dpath);
		if (!strstarts(verstring, version())
		    || verstring[strlen(version())] != '\n')
			errx(1, "%s: bad version '%s'", daemons[i], verstring);
	}
	tal_free(ctx);
}

static const char *find_my_path(const tal_t *ctx, const char *argv0)
{
	char *me = path_canon(ctx, argv0);

	if (access(me, X_OK) != 0)
		errx(1, "I cannot find myself at %s based on my name %s",
		     me, argv0);
	return path_dirname(ctx, take(me));
}

void derive_peer_seed(struct lightningd *ld, struct privkey *peer_seed,
		      const struct pubkey *peer_id, const u64 channel_id)
{
	u8 input[PUBKEY_DER_LEN + sizeof(channel_id)];
	char *info = "per-peer seed";
	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &channel_id, sizeof(channel_id));

	hkdf_sha256(peer_seed, sizeof(*peer_seed),
		    input, sizeof(input),
		    &ld->peer_seed, sizeof(ld->peer_seed),
		    info, strlen(info));
}

static void shutdown_subdaemons(struct lightningd *ld)
{
	struct peer *p;

	/* Let everyone shutdown cleanly. */
	close(ld->hsm_fd);
	subd_shutdown(ld->gossip, 10);

	/* Duplicates are OK: no need to check here. */
	list_for_each(&ld->peers, p, list)
		if (p->owner)
			subd_shutdown(p->owner, 0);
}

struct chainparams *get_chainparams(const struct lightningd *ld)
{
	return cast_const(struct chainparams *,
			  ld->topology->bitcoind->chainparams);
}

int main(int argc, char *argv[])
{
	struct lightningd *ld = new_lightningd(NULL);
	bool newdir;

	err_set_progname(argv[0]);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	/* Figure out where we are first. */
	ld->daemon_dir = find_my_path(ld, argv[0]);

	register_opts(ld);
	opt_register_arg("--dev-debugger=<subdaemon>", opt_subd_debug, NULL,
			 ld, "Wait for gdb attach at start of <subdaemon>");

	opt_register_arg("--dev-broadcast-interval=<ms>", opt_set_uintval,
			 opt_show_uintval, &ld->broadcast_interval,
			 "Time between gossip broadcasts in milliseconds (default: 30000)");

	opt_register_arg("--dev-disconnect=<filename>", opt_subd_dev_disconnect,
			 NULL, ld, "File containing disconnection points");

	/* FIXME: move to option initialization once we drop the
	 * legacy daemon */
	ld->broadcast_interval = 30000;

	/* Handle options and config; move to .lightningd */
	newdir = handle_opts(ld, argc, argv);

	/* Activate crash log now we're in the right place. */
	crashlog_activate(ld->log);

	/* Ignore SIGPIPE: we look at our write return values*/
	signal(SIGPIPE, SIG_IGN);

	/* Make sure we can reach other daemons, and versions match. */
	test_daemons(ld);

	/* Initialize wallet, now that we are in the correct directory */
	ld->wallet = wallet_new(ld, ld->log);

	/* Mark ourselves live. */
	log_info(ld->log, "Hello world from %s!", version());

	/* Set up HSM. */
	hsm_init(ld, newdir);

	/* Set up gossip daemon. */
	gossip_init(ld);

	/* Initialize block topology. */
	setup_topology(ld->topology,
		       &ld->timers,
		       ld->config.poll_time,
		       /* FIXME: Load from peers. */
		       0);

	/* Load peers from database */
	wallet_channels_load_active(ld->wallet, &ld->peers);

	/* TODO(cdecker) Move this into common location for initialization */
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		populate_peer(ld, peer);
		peer->seed = tal(peer, struct privkey);
		derive_peer_seed(ld, peer->seed, &peer->id, peer->channel->id);
		peer->htlcs = tal_arr(peer, struct htlc_stub, 0);
	}

	/* Create RPC socket (if any) */
	setup_jsonrpc(ld, ld->rpc_filename);

	/* Ready for connections from peers. */
	setup_listeners(ld);

#if 0
	/* Load peers from database. */
	db_load_peers(dstate);
#endif

	for (;;) {
		struct timer *expired;
		void *v = io_loop(&ld->timers, &expired);

		/* We use io_break(dstate) to shut down. */
		if (v == ld)
			break;

		if (expired)
			timer_expired(ld, expired);
	}

	shutdown_subdaemons(ld);

	tal_free(ld);
	opt_free_table();
	return 0;
}


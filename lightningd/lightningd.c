#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <backtrace.h>
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
#include <ccan/tal/str/str.h>
#include <common/io_debug.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wireaddr.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/invoice.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <onchaind/onchain_wire.h>
#include <sys/types.h>
#include <unistd.h>

char *bitcoin_datadir;

struct backtrace_state *backtrace_state;

static struct lightningd *new_lightningd(const tal_t *ctx,
					 struct log_book *log_book)
{
	struct lightningd *ld = tal(ctx, struct lightningd);

#if DEVELOPER
	ld->dev_debug_subdaemon = NULL;
	ld->dev_disconnect_fd = -1;
	ld->dev_hsm_seed = NULL;
	ld->dev_subdaemon_fail = false;
	if (getenv("LIGHTNINGD_DEV_MEMLEAK"))
		memleak_init(ld, backtrace_state);
#endif

	list_head_init(&ld->peers);
	htlc_in_map_init(&ld->htlcs_in);
	htlc_out_map_init(&ld->htlcs_out);
	ld->log_book = log_book;
	ld->log = new_log(log_book, log_book, "lightningd(%u):", (int)getpid());
	ld->alias = NULL;
	ld->rgb = NULL;
	list_head_init(&ld->pay_commands);
	list_head_init(&ld->connects);
	ld->wireaddrs = tal_arr(ld, struct wireaddr, 0);
	ld->portnum = DEFAULT_PORT;
	timers_init(&ld->timers, time_mono());
	ld->topology = new_topology(ld, ld->log);

	/* FIXME: Move into invoice daemon. */
	ld->invoices = invoices_init(ld);

	return ld;
}

static const char *daemons[] = {
	"lightning_channeld",
	"lightning_closingd",
	"lightning_gossipd",
	"lightning_hsmd",
	"lightning_onchaind",
	"lightning_openingd"
};

/* Check we can run them, and check their versions */
void test_daemons(const struct lightningd *ld)
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
/* Check if all daemons exist in specified directory. */
static bool has_all_daemons(const char* daemon_dir)
{
	size_t i;
	bool missing_daemon = false;
	const tal_t *tmpctx = tal_tmpctx(NULL);

	for (i = 0; i < ARRAY_SIZE(daemons); ++i) {
		if (!path_is_file(path_join(tmpctx, daemon_dir, daemons[i]))) {
			missing_daemon = true;
			break;
		}
	}

	tal_free(tmpctx);
	return !missing_daemon;
}

static const char *find_my_path(const tal_t *ctx, const char *argv0)
{
	char *me, *tmpctx = tal_tmpctx(ctx);

	/* FIXME: Expose in CCAN! */
#define PATH_SEP_STR "/"
#define PATH_SEP (PATH_SEP_STR[0])

	if (strchr(argv0, PATH_SEP)) {
		const char *path;
		/* Absolute paths are easy. */
		if (strstarts(argv0, PATH_SEP_STR))
			path = argv0;
		/* It contains a '/', it's relative to current dir. */
		else
			path = path_join(tmpctx, path_cwd(tmpctx), argv0);

		me = path_canon(ctx, path);
		if (!me || access(me, X_OK) != 0)
			errx(1, "I cannot find myself at %s based on my name %s",
			     path, argv0);
	} else {
		/* No /, search path */
		char **pathdirs;
		const char *pathenv = getenv("PATH");
		size_t i;

		if (!pathenv)
			errx(1, "Cannot find myself: no $PATH set");

		pathdirs = tal_strsplit(tmpctx, pathenv, ":", STR_NO_EMPTY);
		me = NULL;
		for (i = 0; pathdirs[i]; i++) {
			/* This returns NULL if it doesn't exist. */
			me = path_canon(ctx,
					path_join(tmpctx, pathdirs[i], argv0));
			if (me && access(me, X_OK) == 0)
				break;
			/* Nope, try again. */
			me = tal_free(me);
		}
		if (!me)
			errx(1, "Cannot find %s in $PATH", argv0);
	}

	tal_free(tmpctx);
	return path_dirname(ctx, take(me));
}
static const char *find_my_pkglibexec_path(const tal_t *ctx,
					   const char *my_path TAKES)
{
	const char *pkglibexecdir;
	pkglibexecdir = path_join(ctx, my_path, BINTOPKGLIBEXECDIR);
	return path_simplify(ctx, take(pkglibexecdir));
}
/* Determine the correct daemon dir. */
static const char *find_daemon_dir(const tal_t *ctx, const char *argv0)
{
	const char *my_path = find_my_path(ctx, argv0);
	if (has_all_daemons(my_path))
		return my_path;
	return find_my_pkglibexec_path(ctx, take(my_path));
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

	db_begin_transaction(ld->wallet->db);
	/* Let everyone shutdown cleanly. */
	close(ld->hsm_fd);
	subd_shutdown(ld->gossip, 10);

	free_htlcs(ld, NULL);

	while ((p = list_top(&ld->peers, struct peer, list)) != NULL)
		tal_free(p);
	db_commit_transaction(ld->wallet->db);
}

struct chainparams *get_chainparams(const struct lightningd *ld)
{
	return cast_const(struct chainparams *,
			  ld->topology->bitcoind->chainparams);
}

static void init_txfilter(struct wallet *w, struct txfilter *filter)
{
	struct ext_key ext;
	u64 bip32_max_index;

	bip32_max_index = db_get_intvar(w->db, "bip32_max_index", 0);
	for (u64 i = 0; i <= bip32_max_index; i++) {
		if (bip32_key_from_parent(w->bip32_base, i, BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
			abort();
		}
		txfilter_add_derkey(filter, ext.pub_key);
	}
}

int main(int argc, char *argv[])
{
	struct log_book *log_book;
	struct lightningd *ld;
	bool newdir;
	u32 peer_first_blocknum;

	err_set_progname(argv[0]);

#if DEVELOPER
	/* Suppresses backtrace (breaks valgrind) */
	if (!getenv("LIGHTNINGD_DEV_NO_BACKTRACE"))
#endif
	backtrace_state = backtrace_create_state(argv[0], 0, NULL, NULL);

	/* Things log on shutdown, so we need this to outlive lightningd */
	log_book = new_log_book(NULL, 20*1024*1024, LOG_INFORM);
	ld = new_lightningd(NULL, log_book);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	io_poll_override(debug_poll);

	/* Figure out where our daemons are first. */
	ld->daemon_dir = find_daemon_dir(ld, argv[0]);
	if (!ld->daemon_dir)
		errx(1, "Could not find daemons");

	register_opts(ld);

	/* Handle options and config; move to .lightningd */
	newdir = handle_opts(ld, argc, argv);

	/* Activate crash log now we're in the right place. */
	crashlog_activate(argv[0], ld->log);

	/* Ignore SIGPIPE: we look at our write return values*/
	signal(SIGPIPE, SIG_IGN);

	/* Make sure we can reach other daemons, and versions match. */
	test_daemons(ld);

	/* Initialize wallet, now that we are in the correct directory */
	ld->wallet = wallet_new(ld, ld->log);
	ld->owned_txfilter = txfilter_new(ld);

	/* Set up HSM. */
	hsm_init(ld, newdir);

	/* Now we know our ID, we can set our color/alias if not already. */
	setup_color_and_alias(ld);

	/* Everything is within a transaction. */
	db_begin_transaction(ld->wallet->db);

	/* Initialize the transaction filter with our pubkeys. */
	init_txfilter(ld->wallet, ld->owned_txfilter);

        /* Load invoices from the database */
	if (!wallet_invoices_load(ld->wallet, ld->invoices)) {
		fatal("Could not load invoices from the database");
	}

	/* Set up gossip daemon. */
	gossip_init(ld);

	/* Load peers from database */
	wallet_channels_load_active(ld, ld->wallet, &ld->peers);

	/* TODO(cdecker) Move this into common location for initialization */
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		populate_peer(ld, peer);
		peer->seed = tal(peer, struct privkey);
		derive_peer_seed(ld, peer->seed, &peer->id, peer->channel->id);
		peer->owner = NULL;
		if (!wallet_htlcs_load_for_channel(ld->wallet, peer->channel,
						   &ld->htlcs_in, &ld->htlcs_out)) {
			fatal("could not load htlcs for channel");
		}
	}
	if (!wallet_htlcs_reconnect(ld->wallet, &ld->htlcs_in, &ld->htlcs_out))
		fatal("could not reconnect htlcs loaded from wallet, wallet may be inconsistent.");

	peer_first_blocknum = wallet_channels_first_blocknum(ld->wallet);

	db_commit_transaction(ld->wallet->db);

	/* Initialize block topology (does its own transaction) */
	setup_topology(ld->topology,
		       &ld->timers,
		       ld->config.poll_time,
		       peer_first_blocknum);

	/* Create RPC socket (if any) */
	setup_jsonrpc(ld, ld->rpc_filename);

	/* Mark ourselves live. */
	log_info(ld->log, "Hello world from %s aka %s #%s (version %s)!",
		 type_to_string(ltmp, struct pubkey, &ld->id),
		 ld->alias, tal_hex(ltmp, ld->rgb), version());

	/* Start the peers. */
	activate_peers(ld);

	/* Now kick off topology update, now peers have watches. */
	begin_topology(ld->topology);

	for (;;) {
		struct timer *expired;
		void *v = io_loop(&ld->timers, &expired);

		/* We use io_break(dstate) to shut down. */
		if (v == ld)
			break;

		if (expired) {
			db_begin_transaction(ld->wallet->db);
			timer_expired(ld, expired);
			db_commit_transaction(ld->wallet->db);
		}
	}

	shutdown_subdaemons(ld);

	tal_free(ld);
	opt_free_table();
	tal_free(log_book);

#if DEVELOPER
	memleak_cleanup();
#endif
	take_cleanup();
	secp256k1_context_destroy(secp256k1_ctx);
	return 0;
}

#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <daemon/bitcoind.h>
#include <daemon/chaintopology.h>
#include <daemon/invoice.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <daemon/options.h>
#include <daemon/routing.h>
#include <daemon/timeout.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils.h>
#include <version.h>

char *bitcoin_datadir;

#define FIXME_IMPLEMENT() errx(1, "FIXME: Implement %s", __func__)

struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id);
struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id)
{
	FIXME_IMPLEMENT();
}

struct peer *find_peer_by_unique_id(struct lightningd *ld, u64 unique_id)
{
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		if (peer->unique_id == unique_id)
			return peer;
	}
	return NULL;
}

void peer_debug(struct peer *peer, const char *fmt, ...);
void peer_debug(struct peer *peer, const char *fmt, ...)
{
	FIXME_IMPLEMENT();
}

void debug_dump_peers(struct lightningd_state *dstate);
void debug_dump_peers(struct lightningd_state *dstate)
{
	FIXME_IMPLEMENT();
}

void notify_new_block(struct chain_topology *topo, u32 height);
void notify_new_block(struct chain_topology *topo, u32 height)
{
	/* FIXME */
}

void db_resolve_invoice(struct lightningd_state *dstate,
			const char *label, u64 paid_num);
void db_resolve_invoice(struct lightningd_state *dstate,
			const char *label, u64 paid_num)
{
	/* FIXME */
}

bool db_new_invoice(struct lightningd_state *dstate,
		    u64 msatoshi,
		    const char *label,
		    const struct preimage *r);
bool db_new_invoice(struct lightningd_state *dstate,
		    u64 msatoshi,
		    const char *label,
		    const struct preimage *r)
{
	/* FIXME */
	return true;
}

bool db_remove_invoice(struct lightningd_state *dstate, const char *label);
bool db_remove_invoice(struct lightningd_state *dstate,
		       const char *label)
{
	/* FIXME */
	return true;
}

 #include <daemon/packets.h>
void queue_pkt_nested(struct peer *peer,
		      int type,
		      const u8 *nested_pkt)
{
	FIXME_IMPLEMENT();
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
	ld->dstate.log_book = new_log_book(&ld->dstate, 20*1024*1024,LOG_INFORM);
	ld->log = ld->dstate.base_log = new_log(&ld->dstate,
						ld->dstate.log_book,
						"lightningd(%u):",
						(int)getpid());

	list_head_init(&ld->dstate.peers);
	list_head_init(&ld->dstate.pay_commands);
	ld->dstate.portnum = DEFAULT_PORT;
	ld->dstate.testnet = true;
	timers_init(&ld->dstate.timers, time_mono());
	list_head_init(&ld->dstate.wallet);
	list_head_init(&ld->dstate.addresses);
	ld->dstate.dev_never_routefail = false;
	ld->dstate.reexec = NULL;
	ld->dstate.external_ip = NULL;
	ld->dstate.announce = NULL;
	ld->topology = ld->dstate.topology = new_topology(ld, ld->log);
	ld->bitcoind = ld->dstate.bitcoind = new_bitcoind(ld, ld->log);
	ld->bitcoind->testmode = ld->dstate.testnet?BITCOIND_TESTNET:BITCOIND_MAINNET;

	/* FIXME: Move into invoice daemon. */
	ld->dstate.invoices = invoices_init(&ld->dstate);
	return ld;
}

static const char *daemons[] = {
	"lightningd",
	"lightningd_hsm",
	"lightningd_handshake",
	"lightningd_gossip",
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

		log_debug(ld->dstate.base_log, "testing %s", dpath);
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
		      const struct pubkey *peer_id)
{
	be64 counter = cpu_to_be64(ld->peer_counter);
	u8 input[PUBKEY_DER_LEN + sizeof(counter)];
	char *info = "per-peer seed";

	pubkey_to_der(input, peer_id);
	memcpy(input + PUBKEY_DER_LEN, &counter, sizeof(counter));

	hkdf_sha256(peer_seed, sizeof(*peer_seed),
		    input, sizeof(input),
		    &ld->peer_seed, sizeof(ld->peer_seed),
		    info, strlen(info));
	/* FIXME: This must be saved in db. */
	ld->peer_counter++;
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

int main(int argc, char *argv[])
{
	struct lightningd *ld = new_lightningd(NULL);
	bool newdir;

	err_set_progname(argv[0]);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	/* Figure out where we are first. */
	ld->daemon_dir = find_my_path(ld, argv[0]);

	register_opts(&ld->dstate);
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
	newdir = handle_opts(&ld->dstate, argc, argv);

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
	setup_topology(ld->topology, ld->bitcoind, &ld->dstate.timers,
		       ld->dstate.config.poll_time,
		       /* FIXME: Load from peers. */
		       0);

	/* Create RPC socket (if any) */
	setup_jsonrpc(&ld->dstate, ld->dstate.rpc_filename);

	/* Ready for connections from peers. */
	setup_listeners(ld);

#if 0
	/* Load peers from database. */
	db_load_peers(dstate);
#endif

	for (;;) {
		struct timer *expired;
		void *v = io_loop(&ld->dstate.timers, &expired);

		/* We use io_break(dstate) to shut down. */
		if (v == ld)
			break;

		if (expired)
			timer_expired(&ld->dstate, expired);
	}

	shutdown_subdaemons(ld);

	tal_free(ld);
	opt_free_table();
	return 0;
}


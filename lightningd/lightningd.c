#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
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

/* FIXME: Implement */
struct invoices *invoices_init(struct lightningd_state *dstate)
{
	return NULL;
}

struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id);
struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id)
{
	FIXME_IMPLEMENT();
}

size_t get_tx_depth(struct lightningd_state *dstate,
		    const struct sha256_double *txid)
{
	FIXME_IMPLEMENT();
}

void debug_dump_peers(struct lightningd_state *dstate);
void debug_dump_peers(struct lightningd_state *dstate)
{
	FIXME_IMPLEMENT();
}

u32 get_block_height(struct lightningd_state *dstate)
{
	/* FIXME_IMPLEMENT(); */
	return 0;
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
	ld->bip32_max_index = 0;
	list_head_init(&ld->utxos);
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
	txwatch_hash_init(&ld->dstate.txwatches);
	txowatch_hash_init(&ld->dstate.txowatches);
	list_head_init(&ld->dstate.bitcoin_req);
	list_head_init(&ld->dstate.wallet);
	list_head_init(&ld->dstate.addresses);
	ld->dstate.dev_never_routefail = false;
	ld->dstate.dev_no_broadcast = false;
	ld->dstate.bitcoin_req_running = false;
	ld->dstate.reexec = NULL;
	ld->dstate.external_ip = NULL;
	ld->dstate.announce = NULL;

	ld->dstate.invoices = invoices_init(&ld->dstate);
	return ld;
}

static const char *daemons[] = {
	"lightningd",
	"lightningd_hsm",
	"lightningd_handshake",
	"lightningd_gossip"
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

int main(int argc, char *argv[])
{
	struct lightningd *ld = new_lightningd(NULL);
	bool newdir;

	err_set_progname(argv[0]);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	/* Figure out where we are first. */
	ld->daemon_dir = find_my_path(ld, argv[0]);

	/* Handle options and config; move to .lightningd */
	newdir = handle_opts(&ld->dstate, argc, argv);

	/* Activate crash log now we're in the right place. */
	crashlog_activate(ld->log);

	/* Ignore SIGPIPE: we look at our write return values*/
	signal(SIGPIPE, SIG_IGN);

	/* Make sure we can reach other daemons, and versions match. */
	test_daemons(ld);

	/* Mark ourselves live. */
	log_info(ld->log, "Hello world from %s!", version());

	/* Set up HSM. */
	hsm_init(ld, newdir);

	/* Set up gossip daemon. */
	gossip_init(ld);

	/* Create RPC socket (if any) */
	setup_jsonrpc(&ld->dstate, ld->dstate.rpc_filename);

	/* Ready for connections from peers. */
	setup_listeners(ld);

#if 0
	/* Initialize block topology. */
	setup_topology(dstate);

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

	tal_free(ld);
	opt_free_table();
	return 0;
}


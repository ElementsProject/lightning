#include "bitcoind.h"
#include "chaintopology.h"
#include "configdir.h"
#include "controlled_time.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "secrets.h"
#include "timeout.h"
#include <ccan/container_of/container_of.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/timer/timer.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <version.h>

static char *opt_set_u64(const char *arg, u64 *u)
{
	char *endp;
	unsigned long long l;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoull(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_u32(const char *arg, u32 *u)
{
	char *endp;
	unsigned long l;

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoul(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static void opt_show_u64(char buf[OPT_SHOW_LEN], const u64 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIu64, *u);
}

static void opt_show_u32(char buf[OPT_SHOW_LEN], const u32 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIu32, *u);
}

static void config_register_opts(struct lightningd_state *dstate)
{
	opt_register_arg("--locktime", opt_set_u32, opt_show_u32,
			 &dstate->config.rel_locktime,
			 "Seconds before peer can unilaterally spend funds");
	opt_register_arg("--max-locktime", opt_set_u32, opt_show_u32,
			 &dstate->config.rel_locktime_max,
			 "Maximum seconds peer can lock up our funds");
	opt_register_arg("--anchor-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.anchor_confirms,
			 "Confirmations required for anchor transaction");
	opt_register_arg("--max-anchor-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.anchor_confirms_max,
			 "Maximum confirmations other side can wait for anchor transaction");
	opt_register_arg("--forever-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.forever_confirms,
			 "Confirmations after which we consider a reorg impossible");
	opt_register_arg("--commit-fee-rate", opt_set_u64, opt_show_u64,
			 &dstate->config.commitment_fee_rate,
			 "Satoshis to offer for commitment transaction fee (per kb)");
	opt_register_arg("--min-commit-fee-rate", opt_set_u64, opt_show_u64,
			 &dstate->config.commitment_fee_rate_min,
			 "Minimum satoshis to accept for commitment transaction fee (per kb)");
	opt_register_arg("--closing-fee-rate", opt_set_u64, opt_show_u64,
			 &dstate->config.closing_fee_rate,
			 "Satoshis to use for mutual close transaction fee (per kb)");
	opt_register_arg("--min-expiry", opt_set_u32, opt_show_u32,
			 &dstate->config.min_expiry,
			 "Minimum number of seconds to accept an HTLC before expiry");
	opt_register_arg("--max-expiry", opt_set_u32, opt_show_u32,
			 &dstate->config.max_expiry,
			 "Maximum number of seconds to accept an HTLC before expiry");
	opt_register_arg("--bitcoind-poll", opt_set_u32, opt_show_u32,
			 &dstate->config.poll_seconds,
			 "Seconds between polling for new transactions");
}

#define MINUTES 60
#define HOURS (60 * MINUTES)
#define DAYS (24 * HOURS)

static void default_config(struct config *config)
{
	/* aka. "Dude, where's my coins?" */
	config->testnet = true;

	/* One day to catch cheating attempts. */
	config->rel_locktime = 1 * DAYS;

	/* They can have up to 3 days. */
	config->rel_locktime_max = 2 * DAYS;

	/* We're fairly trusting, under normal circumstances. */
	config->anchor_confirms = 3;

	/* More than 10 confirms seems overkill. */
	config->anchor_confirms_max = 10;

	/* At some point, you've got to let it go... */
	/* BOLT #onchain:
	 *
	 * Outputs... are considered *irrevocably resolved* once they
	 * are included in a block at least 100 deep on the most-work
	 * blockchain.  100 blocks is far greater than the longest
	 * known bitcoin fork, and the same value used to wait for
	 * confirmations of miner's rewards[1].
	 */
	config->forever_confirms = 100;
	
	/* FIXME: These should float with bitcoind's recommendations! */

	/* Pay hefty fee (double historic high of ~100k). */
	config->commitment_fee_rate = 200000;

	/* Don't accept less than double the average 2-block fee. */
	config->commitment_fee_rate_min = 50000;

	/* Use this for mutual close. */
	config->closing_fee_rate = 20000;

	/* Don't bother me unless I have 6 hours to collect. */
	config->min_expiry = 6 * HOURS;
	/* Don't lock up channel for more than 5 days. */
	config->max_expiry = 5 * DAYS;

	config->poll_seconds = 30;
}

static void check_config(struct lightningd_state *dstate)
{
	/* BOLT #2:
	 * The sender MUST set `close_fee` lower than or equal to the
	 * fee of the final commitment transaction
	 */

	/* We do this by ensuring it's less than the minimum we would accept. */
	if (dstate->config.closing_fee_rate > dstate->config.commitment_fee_rate_min)
		fatal("Closing fee rate %"PRIu64
		      " can't exceed minimum commitment fee rate %"PRIu64,
		      dstate->config.closing_fee_rate,
		      dstate->config.commitment_fee_rate_min);

	if (dstate->config.commitment_fee_rate_min
	    > dstate->config.commitment_fee_rate)
		fatal("Minumum fee rate %"PRIu64
		      " can't exceed commitment fee rate %"PRIu64,
		      dstate->config.commitment_fee_rate_min,
		      dstate->config.commitment_fee_rate);

	if (dstate->config.forever_confirms < 100)
		log_unusual(dstate->base_log,
			    "Warning: forever-confirms of %u is less than 100!",
			    dstate->config.forever_confirms);
}

static struct lightningd_state *lightningd_state(void)
{
	struct lightningd_state *dstate = tal(NULL, struct lightningd_state);

	dstate->log_record = new_log_record(dstate, 20*1024*1024, LOG_INFORM);
	dstate->base_log = new_log(dstate, dstate->log_record,
				   "lightningd(%u):", (int)getpid());

	list_head_init(&dstate->peers);
	timers_init(&dstate->timers, controlled_time());
	txwatch_hash_init(&dstate->txwatches);
	txowatch_hash_init(&dstate->txowatches);
	dstate->secpctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						   | SECP256K1_CONTEXT_SIGN);
	default_config(&dstate->config);
	list_head_init(&dstate->bitcoin_req);
	list_head_init(&dstate->wallet);
	dstate->bitcoin_req_running = false;
	return dstate;
}

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

int main(int argc, char *argv[])
{
	struct lightningd_state *dstate = lightningd_state();
	unsigned int portnum = 0;

	err_set_progname(argv[0]);
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);

	if (!streq(protobuf_c_version(), PROTOBUF_C_VERSION))
		errx(1, "Compiled against protobuf %s, but have %s",
		     PROTOBUF_C_VERSION, protobuf_c_version());
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n"
			   "A bitcoin lightning daemon.",
			   "Print this message.");
	opt_register_arg("--port", opt_set_uintval, NULL, &portnum,
			 "Port to bind to (otherwise, dynamic port is used)");
	opt_register_arg("--bitcoin-datadir", opt_set_charp, NULL,
			 &bitcoin_datadir,
			 "-datadir arg for bitcoin-cli");
	opt_register_logging(dstate->base_log);
	opt_register_version();

	configdir_register_opts(dstate,
				&dstate->config_dir, &dstate->rpc_filename);
	config_register_opts(dstate);

	/* Get any configdir options first. */
	opt_early_parse(argc, argv, opt_log_stderr_exit);

	/* Move to config dir, to save ourselves the hassle of path manip. */
	if (chdir(dstate->config_dir) != 0) {
		log_unusual(dstate->base_log, "Creating lightningd dir %s"
			    " (because chdir gave %s)",
			    dstate->config_dir, strerror(errno));
		if (mkdir(dstate->config_dir, 0700) != 0)
			fatal("Could not make directory %s: %s",
			      dstate->config_dir, strerror(errno));
		if (chdir(dstate->config_dir) != 0)
			fatal("Could not change directory %s: %s",
			      dstate->config_dir, strerror(errno));
	}
	/* Activate crash log now we're in the right place. */
	crashlog_activate(dstate->base_log);

	/* Now look for config file */
	opt_parse_from_config(dstate);

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	check_config(dstate);
	
	check_bitcoind_config(dstate);

	/* Create RPC socket (if any) */
	setup_jsonrpc(dstate, dstate->rpc_filename);

	/* Set up connections from peers. */
	setup_listeners(dstate, portnum);

	/* Set up node ID and private key. */
	secrets_init(dstate);

	/* Initialize block topology. */
	setup_topology(dstate);

	/* Make sure we use the artificially-controlled time for timers */
	io_time_override(controlled_time);
	
	log_info(dstate->base_log, "Hello world!");

	for (;;) {
		struct timer *expired;
		void *v = io_loop(&dstate->timers, &expired);

		/* We use io_break(dstate) to shut down. */
		if (v == dstate)
			break;

		/* We use it on a peer when it needs freeing (may be
		 * NULL if we only broke out due to timer). */
		tal_free(v);

		if (expired) {
			struct timeout *to;
			to = container_of(expired, struct timeout, timer);
			to->cb(to->arg);
		}
	}

	tal_free(dstate);
	opt_free_table();
	return 0;
}

#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_escaped.h>
#include <common/memleak.h>
#include <common/version.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/netaddress.h>
#include <lightningd/opt_time.h>
#include <lightningd/options.h>
#include <lightningd/subd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/wire.h>

bool deprecated_apis = true;

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, false, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr) {
		/* realloc(NULL) call is to allocate opt_table */
		static bool opt_table_alloced = false;
		if (!opt_table_alloced) {
			opt_table_alloced = true;
			return notleak(opt_allocfn(size));
		}
		return opt_allocfn(size);
	}
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

/* During option parsing, ld->port can be NULL to indicate "still default" */
static u16 get_portnum(const struct lightningd *ld)
{
	if (ld->portnum)
		return *ld->portnum;
	return get_chainparams(ld)->default_port;
}

/* FIXME: Put into ccan/time. */
#define TIME_FROM_SEC(sec) { { .tv_nsec = 0, .tv_sec = sec } }
#define TIME_FROM_MSEC(msec) \
	{ { .tv_nsec = ((msec) % 1000) * 1000000, .tv_sec = (msec) / 1000 } }

static char *opt_set_u64(const char *arg, u64 *u)
{
	char *endp;
	unsigned long long l;

	assert(arg != NULL);

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

	assert(arg != NULL);

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

static char *opt_set_port(const char *arg, struct lightningd *ld)
{
	char *endp;
	unsigned long l;

	assert(arg != NULL);

	/* Don't leak in case we set it twice */
	tal_free(ld->portnum);
	ld->portnum = tal(ld, u16);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoul(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*ld->portnum = l;
	if (errno || *ld->portnum != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_s32(const char *arg, s32 *u)
{
	char *endp;
	long l;

	assert(arg != NULL);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtol(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_add_ipaddr(const char *arg, struct lightningd *ld)
{
	size_t n = tal_count(ld->wireaddrs);
	u16 defport = get_portnum(ld);
	char const *err_msg;

	assert(arg != NULL);

	tal_resize(&ld->wireaddrs, n+1);

	if (!parse_wireaddr(arg, &ld->wireaddrs[n], defport, &err_msg)) {
		return tal_fmt(NULL, "Unable to parse IP address '%s': %s", arg, err_msg);
	}

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

static void opt_show_s32(char buf[OPT_SHOW_LEN], const s32 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIi32, *u);
}

static void opt_show_port(char buf[OPT_SHOW_LEN], const struct lightningd *ld)
{
	snprintf(buf, OPT_SHOW_LEN, "%u", get_portnum(ld));
}

static char *opt_set_rgb(const char *arg, struct lightningd *ld)
{
	assert(arg != NULL);

	ld->rgb = tal_free(ld->rgb);
	/* BOLT #7:
	 *
	 * the first byte of `rgb` is the red value, the second byte is the
	 * green value and the last byte is the blue value */
	ld->rgb = tal_hexdata(ld, arg, strlen(arg));
	if (!ld->rgb || tal_len(ld->rgb) != 3)
		return tal_fmt(NULL, "rgb '%s' is not six hex digits", arg);
	return NULL;
}

static char *opt_set_alias(const char *arg, struct lightningd *ld)
{
	assert(arg != NULL);

	ld->alias = tal_free(ld->alias);
	/* BOLT #7:
	 *
	 *    * [`32`:`alias`]
	 *...
	 * It MUST set `alias` to a valid UTF-8 string, with any `alias` bytes
	 * following equal to zero.
	 */
	if (strlen(arg) > 32)
		return tal_fmt(NULL, "Alias '%s' is over 32 characters", arg);
	ld->alias = tal_arrz(ld, u8, 33);
	strncpy((char*)ld->alias, arg, 32);
	return NULL;
}

static char *opt_set_fee_rates(const char *arg, struct chain_topology *topo)
{
	tal_free(topo->override_fee_rate);
	topo->override_fee_rate = tal_arr(topo, u32, 3);

	for (size_t i = 0; i < tal_count(topo->override_fee_rate); i++) {
		char *endp;
		char term;

		if (i == tal_count(topo->override_fee_rate)-1)
			term = '\0';
		else
			term = '/';
		topo->override_fee_rate[i] = strtol(arg, &endp, 10);
		if (endp == arg || *endp != term)
			return tal_fmt(NULL,
				       "Feerates must be <num>/<num>/<num>");

		arg = endp + 1;
	}
	return NULL;
}

static char *opt_set_offline(struct lightningd *ld)
{
	ld->portnum = 0;
	ld->no_reconnect = true;
	return NULL;
}

static void config_register_opts(struct lightningd *ld)
{
	opt_register_noarg("--daemon", opt_set_bool, &ld->daemon,
			 "Run in the background, suppress stdout/stderr");
	opt_register_arg("--ignore-fee-limits", opt_set_bool_arg, opt_show_bool,
			 &ld->config.ignore_fee_limits,
			 "(DANGEROUS) allow peer to set any feerate");
	opt_register_arg("--locktime-blocks", opt_set_u32, opt_show_u32,
			 &ld->config.locktime_blocks,
			 "Blocks before peer can unilaterally spend funds");
	opt_register_arg("--max-locktime-blocks", opt_set_u32, opt_show_u32,
			 &ld->config.locktime_max,
			 "Maximum blocks a peer can lock up our funds");
	opt_register_arg("--anchor-onchain", opt_set_u32, opt_show_u32,
			 &ld->config.anchor_onchain_wait,
			 "Blocks before we give up on pending anchor transaction");
	opt_register_arg("--anchor-confirms", opt_set_u32, opt_show_u32,
			 &ld->config.anchor_confirms,
			 "Confirmations required for anchor transaction");
	opt_register_arg("--max-anchor-confirms", opt_set_u32, opt_show_u32,
			 &ld->config.anchor_confirms_max,
			 "Maximum confirmations other side can wait for anchor transaction");
	opt_register_arg("--commit-fee-min=<percent>", opt_set_u32, opt_show_u32,
			 &ld->config.commitment_fee_min_percent,
			 "Minimum percentage of fee to accept for commitment");
	opt_register_arg("--commit-fee-max=<percent>", opt_set_u32, opt_show_u32,
			 &ld->config.commitment_fee_max_percent,
			 "Maximum percentage of fee to accept for commitment (0 for unlimited)");
	opt_register_arg("--commit-fee=<percent>", opt_set_u32, opt_show_u32,
			 &ld->config.commitment_fee_percent,
			 "Percentage of fee to request for their commitment");
	opt_register_arg("--override-fee-rates", opt_set_fee_rates, NULL,
			 ld->topology,
			 "Force a specific rates (immediate/normal/slow) in satoshis per kw regardless of estimated fees");
	opt_register_arg("--default-fee-rate", opt_set_u32, opt_show_u32,
			 &ld->topology->default_fee_rate,
			 "Satoshis per kw if can't estimate fees");
	opt_register_arg("--cltv-delta", opt_set_u32, opt_show_u32,
			 &ld->config.cltv_expiry_delta,
			 "Number of blocks for ctlv_expiry_delta");
	opt_register_arg("--cltv-final", opt_set_u32, opt_show_u32,
			 &ld->config.cltv_final,
			 "Number of blocks for final ctlv_expiry");
	opt_register_arg("--max-htlc-expiry", opt_set_u32, opt_show_u32,
			 &ld->config.max_htlc_expiry,
			 "Maximum number of blocks to accept an HTLC before expiry");
	opt_register_arg("--bitcoind-poll", opt_set_time, opt_show_time,
			 &ld->config.poll_time,
			 "Time between polling for new transactions");
	opt_register_arg("--commit-time", opt_set_time, opt_show_time,
			 &ld->config.commit_time,
			 "Time after changes before sending out COMMIT");
	opt_register_arg("--fee-base", opt_set_u32, opt_show_u32,
			 &ld->config.fee_base,
			 "Millisatoshi minimum to charge for HTLC");
	opt_register_arg("--fee-per-satoshi", opt_set_s32, opt_show_s32,
			 &ld->config.fee_per_satoshi,
			 "Microsatoshi fee for every satoshi in HTLC");
	opt_register_arg("--ipaddr", opt_add_ipaddr, NULL,
			 ld,
			 "Set the IP address (v4 or v6) to announce to the network for incoming connections");
	opt_register_noarg("--offline", opt_set_offline, ld,
			   "Start in offline-mode (do not automatically reconnect and do not accept incoming connections");

	opt_register_arg("--allow-deprecated-apis",
			 opt_set_bool_arg, opt_show_bool,
			 &deprecated_apis,
			 "Enable deprecated options, JSONRPC commands, fields, etc.");
	opt_register_arg("--debug-subdaemon-io",
			 opt_set_charp, NULL, &ld->debug_subdaemon_io,
			 "Enable full peer IO logging in subdaemons ending in this string (can also send SIGUSR1 to toggle)");
	opt_register_arg("--autocleaninvoice-cycle",
			 opt_set_u64, opt_show_u64,
			 &ld->ini_autocleaninvoice_cycle,
			 "Perform cleanup of expired invoices every given seconds, or do not autoclean if 0");
	opt_register_arg("--autocleaninvoice-expired-by",
			 opt_set_u64, opt_show_u64,
			 &ld->ini_autocleaninvoice_cycle,
			 "If expired invoice autoclean enabled, invoices that have expired for at least this given seconds are cleaned");
}

#if DEVELOPER
static void dev_register_opts(struct lightningd *ld)
{
	opt_register_noarg("--dev-no-reconnect", opt_set_bool,
			   &ld->no_reconnect,
			   "Disable automatic reconnect attempts");
	opt_register_noarg("--dev-fail-on-subdaemon-fail", opt_set_bool,
			   &ld->dev_subdaemon_fail, opt_hidden);
	opt_register_arg("--dev-debugger=<subdaemon>", opt_subd_debug, NULL,
			 ld, "Wait for gdb attach at start of <subdaemon>");
	opt_register_arg("--dev-broadcast-interval=<ms>", opt_set_uintval,
			 opt_show_uintval, &ld->config.broadcast_interval,
			 "Time between gossip broadcasts in milliseconds");
	opt_register_arg("--dev-disconnect=<filename>", opt_subd_dev_disconnect,
			 NULL, ld, "File containing disconnection points");
}
#endif

static const struct config testnet_config = {
	/* 6 blocks to catch cheating attempts. */
	.locktime_blocks = 6,

	/* They can have up to 3 days. */
	.locktime_max = 3 * 6 * 24,

	/* Testnet can have long runs of empty blocks. */
	.anchor_onchain_wait = 100,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 1,

	/* More than 10 confirms seems overkill. */
	.anchor_confirms_max = 10,

	/* Testnet fees are crazy, allow infinite feerange. */
	.commitment_fee_min_percent = 0,
	.commitment_fee_max_percent = 0,

	/* We offer to pay 5 times 2-block fee */
	.commitment_fee_percent = 500,

	/* Be aggressive on testnet. */
	.cltv_expiry_delta = 6,
	.cltv_final = 6,

	/* Don't lock up channel for more than 5 days. */
	.max_htlc_expiry = 5 * 6 * 24,

	/* How often to bother bitcoind. */
	.poll_time = TIME_FROM_SEC(10),

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time = TIME_FROM_MSEC(10),

	/* Allow dust payments */
	.fee_base = 1,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* BOLT #7:
	 * Each node SHOULD flush outgoing announcements once every 60 seconds */
	.broadcast_interval = 60000,

	/* Send a keepalive update at least every week, prune every twice that */
	.channel_update_interval = 1209600/2,

	/* Testnet sucks */
	.ignore_fee_limits = true,
};

/* aka. "Dude, where's my coins?" */
static const struct config mainnet_config = {
	/* ~one day to catch cheating attempts. */
	.locktime_blocks = 6 * 24,

	/* They can have up to 3 days. */
	.locktime_max = 3 * 6 * 24,

	/* You should get in within 10 blocks. */
	.anchor_onchain_wait = 10,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 3,

	/* More than 10 confirms seems overkill. */
	.anchor_confirms_max = 10,

	/* Insist between 2 and 20 times the 2-block fee. */
	.commitment_fee_min_percent = 200,
	.commitment_fee_max_percent = 2000,

	/* We offer to pay 5 times 2-block fee */
	.commitment_fee_percent = 500,

	/* BOLT #2:
	 *
	 * The `cltv_expiry_delta` for channels.  `3R+2G+2S` */
	/* R = 2, G = 1, S = 3 */
	.cltv_expiry_delta = 14,

	/* BOLT #2:
	 *
	 * The minimum `cltv_expiry` we will accept for terminal payments: the
	 * worst case for the terminal node C lower at `2R+G+S` blocks */
	.cltv_final = 8,

	/* Don't lock up channel for more than 5 days. */
	.max_htlc_expiry = 5 * 6 * 24,

	/* How often to bother bitcoind. */
	.poll_time = TIME_FROM_SEC(30),

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time = TIME_FROM_MSEC(10),

	/* Discourage dust payments */
	.fee_base = 1000,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* BOLT #7:
	 * Each node SHOULD flush outgoing announcements once every 60 seconds */
	.broadcast_interval = 60000,

	/* Send a keepalive update at least every week, prune every twice that */
	.channel_update_interval = 1209600/2,

	/* Mainnet should have more stable fees */
	.ignore_fee_limits = false,
};

static void check_config(struct lightningd *ld)
{
	/* We do this by ensuring it's less than the minimum we would accept. */
	if (ld->config.commitment_fee_max_percent != 0
	    && ld->config.commitment_fee_max_percent
	    < ld->config.commitment_fee_min_percent)
		fatal("Commitment fee invalid min-max %u-%u",
		      ld->config.commitment_fee_min_percent,
		      ld->config.commitment_fee_max_percent);

	if (ld->config.anchor_confirms == 0)
		fatal("anchor-confirms must be greater than zero");
}

static void setup_default_config(struct lightningd *ld, const char *netname)
{
	/* Now transfer network name to chainparams */
	ld->topology->bitcoind->chainparams = chainparams_for_network(netname);
	if (!ld->topology->bitcoind->chainparams)
		fatal("Unknown network name '%s'", netname);

	if (get_chainparams(ld)->testnet)
		ld->config = testnet_config;
	else
		ld->config = mainnet_config;

	/* Set default PID file name to be per-network */
	tal_free(ld->pidfile);
	ld->pidfile = tal_fmt(ld, "lightningd-%s.pid", get_chainparams(ld)->network_name);
}


/* FIXME: make this nicer! */
static int config_parse_line_number = 0;

static void config_log_stderr_exit(const char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	/* This is the format we expect:*/
	if (streq(fmt, "%s: %.*s: %s")) {
		const char *argv0 = va_arg(ap, const char *);
		unsigned int len = va_arg(ap, unsigned int);
		const char *arg = va_arg(ap, const char *);
		const char *problem = va_arg(ap, const char *);

		assert(argv0 != NULL);
		assert(arg != NULL);
		assert(problem != NULL);
		/*mangle it to remove '--' and add the line number.*/
		msg = tal_fmt(NULL, "%s line %d: %.*s: %s",
			      argv0, config_parse_line_number, len-2, arg+2, problem);
	} else {
		msg = tal_vfmt(NULL, fmt, ap);
	}
	va_end(ap);

	fatal("%s", msg);
}

static void parse_config_lines(const char *configname, char **all_args,
			       int early)
{
	char *argv[3];
	int argc;

	/*
	For each line we construct a fake argc,argv commandline.
	argv[1] is the only element that changes between iterations.
	*/
	argc = 2;
	argv[0] = tal_fmt(tmpctx, "config file '%s'", configname);
	argv[argc] = NULL;

	for (size_t i = 0; i < tal_count(all_args); i++) {
		if (all_args[i] == NULL)
			continue;

		config_parse_line_number = i + 1;
		argv[1] = all_args[i];
		if (early == OPT_EARLY)
			opt_early_parse(argc, argv, config_log_stderr_exit);
		else {
			assert(early == 0);
			opt_parse(&argc, argv, config_log_stderr_exit);
			argc = 2; /* opt_parse might have changed it  */
		}
	}
}

static char *test_daemons_and_exit(struct lightningd *ld)
{
	test_daemons(ld);
	exit(0);
	return NULL;
}

static void register_opts(struct lightningd *ld, char **netname)
{
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);

	opt_register_early_noarg("--help|-h", opt_usage_and_exit,
				 "\n"
				 "A bitcoin lightning daemon.",
				 "Print this message.");
	opt_register_early_noarg("--test-daemons-only",
				 test_daemons_and_exit,
				 ld, opt_hidden);

	opt_register_arg("--port", opt_set_port, opt_show_port, ld,
			 "Port to bind to (0 means don't listen)");
	opt_register_arg("--bitcoin-datadir", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->datadir,
			 "-datadir arg for bitcoin-cli");
	opt_register_arg("--rgb", opt_set_rgb, NULL, ld,
			 "RRGGBB hex color for node");
	opt_register_arg("--alias", opt_set_alias, NULL, ld,
			 "Up to 32-byte alias for node");

	opt_register_arg("--bitcoin-cli", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->cli,
			 "bitcoin-cli pathname");
	opt_register_arg("--bitcoin-rpcuser", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->rpcuser,
			 "bitcoind RPC username");
	opt_register_arg("--bitcoin-rpcpassword", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->rpcpass,
			 "bitcoind RPC password");
	opt_register_arg("--bitcoin-rpcconnect", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->rpcconnect,
			 "bitcoind RPC host to connect to");
	opt_register_arg("--bitcoin-rpcport", opt_set_talstr, NULL,
			 &ld->topology->bitcoind->rpcport,
			 "bitcoind RPC port");
	opt_register_arg("--pid-file=<file>", opt_set_talstr, opt_show_charp,
			 &ld->pidfile,
			 "Specify pid file");

	opt_register_arg(
	    "--channel-update-interval=<s>", opt_set_u32, opt_show_u32,
	    &ld->config.channel_update_interval,
	    "Time in seconds between channel updates for our own channels.");

	opt_register_logging(ld);
	opt_register_version();

	configdir_register_opts(ld, &ld->config_dir, &ld->rpc_filename,
				netname);
	config_register_opts(ld);
#if DEVELOPER
	dev_register_opts(ld);
#endif
}

/* Names stolen from https://github.com/ternus/nsaproductgenerator/blob/master/nsa.js */
static const char *codename_adjective[]
= { "LOUD", "RED", "BLUE", "GREEN", "YELLOW", "IRATE", "ANGRY", "PEEVED",
    "HAPPY", "SLIMY", "SLEEPY", "JUNIOR", "SLICKER", "UNITED", "SOMBER",
    "BIZARRE", "ODD", "WEIRD", "WRONG", "LATENT", "CHILLY", "STRANGE", "LOUD",
    "SILENT", "HOPPING", "ORANGE", "VIOLET", "VIOLENT", "LIGHTNING" };

static const char *codename_noun[]
= { "WHISPER", "FELONY", "MOON", "SUCKER", "PENGUIN", "WAFFLE", "MAESTRO",
    "NIGHT", "TRINITY", "DEITY", "MONKEY", "ARK", "SQUIRREL", "IRON", "BOUNCE",
    "FARM", "CHEF", "TROUGH", "NET", "TRAWL", "GLEE", "WATER", "SPORK", "PLOW",
    "FEED", "SOUFFLE", "ROUTE", "BAGEL", "MONTANA", "ANALYST", "AUTO", "WATCH",
    "PHOTO", "YARD", "SOURCE", "MONKEY", "SEAGULL", "TOLL", "SPAWN", "GOPHER",
    "CHIPMUNK", "SET", "CALENDAR", "ARTIST", "CHASER", "SCAN", "TOTE", "BEAM",
    "ENTOURAGE", "GENESIS", "WALK", "SPATULA", "RAGE", "FIRE", "MASTER" };

void setup_color_and_alias(struct lightningd *ld)
{
	u8 der[PUBKEY_DER_LEN];
	pubkey_to_der(der, &ld->id);

	if (!ld->rgb)
		/* You can't get much red by default */
		ld->rgb = tal_dup_arr(ld, u8, der, 3, 0);

	if (!ld->alias) {
		u64 adjective, noun;
		char *name;

		memcpy(&adjective, der+3, sizeof(adjective));
		memcpy(&noun, der+3+sizeof(adjective), sizeof(noun));
		noun %= ARRAY_SIZE(codename_noun);
		adjective %= ARRAY_SIZE(codename_adjective);

		/* Only use 32 characters */
		name = tal_fmt(ld, "%s%s-",
			       codename_adjective[adjective],
			       codename_noun[noun]);
#if DEVELOPER
		assert(strlen(name) < 32);
		int taillen = 32 - strlen(name);
		if (taillen > strlen(version()))
			taillen = strlen(version());
		/* Fit as much of end of version() as possible */
		tal_append_fmt(&name, "%s",
			       version() + strlen(version()) - taillen);
#endif
		assert(strlen(name) <= 32);
		ld->alias = tal_arrz(ld, u8, 33);
		strcpy((char*)ld->alias, name);
		tal_free(name);
	}
}

void handle_opts(struct lightningd *ld, int argc, char *argv[])
{
	char **config_args;
	char *per_net_configfile;
	/* In case we ever have aliases: use ->network_name instead! */
	char *netname = tal_strdup(tmpctx, get_chainparams(ld)->network_name);

	register_opts(ld, &netname);

	/* Load defaults first, so that --help (in early options) has something
	 * to display. The actual values loaded here, will be overwritten later
	 * by opt_parse_from_config. */
	setup_default_config(ld, netname);

	/* Get any configdir/testnet options first. */
	opt_early_parse(argc, argv, opt_log_stderr_exit);

	/* Move to config dir, to save ourselves the hassle of path manip. */
	if (chdir(ld->config_dir) != 0) {
		log_unusual(ld->log, "Creating configuration directory %s",
			    ld->config_dir);
		if (mkdir(ld->config_dir, 0700) != 0)
			fatal("Could not make directory %s: %s",
			      ld->config_dir, strerror(errno));
		if (chdir(ld->config_dir) != 0)
			fatal("Could not change directory %s: %s",
			      ld->config_dir, strerror(errno));
	}

	/* Now get early options from 'config' */
	config_args = args_from_config_file(ld, "config");
	/* Args need to persist because we might keep pointers to them. */
	if (!config_args) {
		if (errno != ENOENT)
			fatal("Opening and reading config: %s", strerror(errno));
	} else {
		notleak(config_args);
		parse_config_lines("config", config_args, OPT_EARLY);
	}

	/* Corner case: parse cmdline again, as network here should override
	 * network in config file! */
	opt_early_parse(argc, argv, opt_log_stderr_exit);

	/* Now we know network name, we can set proper defaults. */
	setup_default_config(ld, netname);

	/* Now parse the non-early options from default config. */
	parse_config_lines("config", config_args, 0);

	/* Now look for per-network config file */
	per_net_configfile = tal_fmt(tmpctx,
				     "config-%s",
				     get_chainparams(ld)->network_name);
	config_args = args_from_config_file(ld, per_net_configfile);
	/* Args need to persist because we might keep pointers to them. */
	if (!config_args) {
		if (errno != ENOENT)
			fatal("Opening and reading config: %s", strerror(errno));
	} else {
		notleak(config_args);
		parse_config_lines(per_net_configfile, config_args, 0);
	}

	/* Finally, parse commandline (which overrides config files). */
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	/* Free network name; it might have been assigned by --network */
	tal_free(netname);

	/* If they didn't set --rpc-file, do it now */
	config_finalize_rpc_name(ld, &ld->rpc_filename,
				 get_chainparams(ld)->network_name);

	check_config(ld);

	/* If port is still unset, assign it the default */
	if (!ld->portnum) {
		ld->portnum = tal(ld, u16);
		*ld->portnum = get_chainparams(ld)->default_port;
	}

	if (*ld->portnum && tal_count(ld->wireaddrs) == 0)
		guess_addresses(ld);
	else
		log_debug(ld->log, "Not guessing addresses: %s",
			  *ld->portnum ? "manually set" : "port set to zero");
}

/* FIXME: This is a hack!  Expose somehow in ccan/opt.*/
/* Returns string after first '-'. */
static const char *first_name(const char *names, unsigned *len)
{
	*len = strcspn(names + 1, "|= ");
	return names + 1;
}

static const char *next_name(const char *names, unsigned *len)
{
	names += *len;
	if (names[0] == ' ' || names[0] == '=' || names[0] == '\0')
		return NULL;
	return first_name(names + 1, len);
}

static void add_config(struct lightningd *ld,
		       struct json_result *response,
		       const struct opt_table *opt,
		       const char *name, size_t len)
{
	char *name0 = tal_strndup(response, name, len);
	const char *answer = NULL;

	if (opt->type & OPT_NOARG) {
		if (opt->cb == (void *)opt_usage_and_exit
		    || opt->cb == (void *)version_and_exit
		    || opt->cb == (void *)opt_set_offline /* will show up as port=0 and --no-reconnect */
		    || opt->cb == (void *)test_daemons_and_exit) {
			/* These are not important */
		} else if (opt->cb == (void *)opt_set_bool) {
			const bool *b = opt->u.carg;
			answer = tal_fmt(name0, "%s", *b ? "true" : "false");
		} else {
			/* Insert more decodes here! */
			abort();
		}
	} else if (opt->type & OPT_HASARG) {
		if (opt->show) {
			char *buf = tal_arr(name0, char, OPT_SHOW_LEN+1);
			opt->show(buf, opt->u.carg);

			if (streq(buf, "true") || streq(buf, "false")
			    || strspn(buf, "0123456789.") == strlen(buf)) {
				/* Let pure numbers and true/false through as
				 * literals. */
				json_add_literal(response, name0,
						 buf, strlen(buf));
				return;
			}

			/* opt_show_charp surrounds with "", strip them */
			if (strstarts(buf, "\"")) {
				buf[strlen(buf)-1] = '\0';
				answer = buf + 1;
			} else
				answer = buf;
		} else if (opt->cb_arg == (void *)opt_set_talstr
			   || opt->cb_arg == (void *)opt_set_charp) {
			const char *arg = *(char **)opt->u.carg;
			if (arg)
				answer = tal_fmt(name0, "%s", arg);
		} else if (opt->cb_arg == (void *)opt_set_rgb) {
			if (ld->rgb)
				answer = tal_hexstr(name0, ld->rgb, 3);
		} else if (opt->cb_arg == (void *)opt_set_alias) {
			answer = (const char *)ld->alias;
		} else if (opt->cb_arg == (void *)arg_log_to_file) {
			answer = ld->logfile;
		} else if (opt->cb_arg == (void *)opt_set_fee_rates) {
			struct chain_topology *topo = ld->topology;
			if (topo->override_fee_rate)
				answer = tal_fmt(name0, "%u/%u/%u",
						 topo->override_fee_rate[0],
						 topo->override_fee_rate[1],
						 topo->override_fee_rate[2]);
		} else if (opt->cb_arg == (void *)opt_add_ipaddr) {
			/* This is a bit weird, we can have multiple args */
			for (size_t i = 0; i < tal_count(ld->wireaddrs); i++) {
				json_add_string(response,
						name0,
						fmt_wireaddr(name0,
							     ld->wireaddrs+i));
			}
			return;
#if DEVELOPER
		} else if (strstarts(name, "dev-")) {
			/* Ignore dev settings */
#endif
		} else {
			/* Insert more decodes here! */
			abort();
		}
	}

	if (answer) {
		struct json_escaped *esc = json_escape(NULL, answer);
		json_add_escaped_string(response, name0, take(esc));
	}
	tal_free(name0);
}

static void json_listconfigs(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	size_t i;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *configtok;
	bool found = false;

	if (!json_get_params(cmd, buffer, params, "?config", &configtok, NULL)) {
		return;
	}

	json_object_start(response, NULL);
	if (!configtok)
		json_add_string(response, "# version", version());

	for (i = 0; i < opt_count; i++) {
		unsigned int len;
		const char *name;

		/* FIXME: Print out comment somehow? */
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;

		for (name = first_name(opt_table[i].names, &len);
		     name;
		     name = next_name(name, &len)) {
			/* Skips over first -, so just need to look for one */
			if (name[0] != '-')
				continue;

			if (configtok
			    && !memeq(buffer + configtok->start,
				      configtok->end - configtok->start,
				      name + 1, len - 1))
				continue;

			found = true;
			add_config(cmd->ld, response, &opt_table[i],
				   name+1, len-1);
		}
	}
	json_object_end(response);

	if (configtok && !found) {
		command_fail(cmd, "Unknown config option '%.*s'",
			     configtok->end - configtok->start,
			     buffer + configtok->start);
		return;
	}
	command_success(cmd, response);
}

static const struct json_command listconfigs_command = {
	"listconfigs",
	json_listconfigs,
	"List all configuration options, or with [config], just that one.",

	.verbose = "listconfigs [config]\n"
	"Outputs an object, with each field a config options\n"
	"(Option names which start with # are comments)\n"
	"With [config], object only has that field"
};
AUTODATA(json_command, &listconfigs_command);

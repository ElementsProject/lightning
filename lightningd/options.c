#include <arpa/inet.h>
#include <bitcoin/chainparams.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/version.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/opt_time.h>
#include <lightningd/options.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/wire.h>

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, false, TAL_LABEL("opt_allocfn", ""));
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

/* FIXME: Put into ccan/time. */
#define TIME_FROM_SEC(sec) { { .tv_nsec = 0, .tv_sec = sec } }
#define TIME_FROM_MSEC(msec) \
	{ { .tv_nsec = ((msec) % 1000) * 1000000, .tv_sec = (msec) / 1000 } }

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

static char *opt_set_u16(const char *arg, u16 *u)
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

static char *opt_set_s32(const char *arg, s32 *u)
{
	char *endp;
	long l;

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

static char *opt_set_ipaddr(const char *arg, struct ipaddr *addr)
{
	struct in6_addr v6;
	struct in_addr v4;
	char *err = NULL;
	memset(&addr->addr, 0, sizeof(addr->addr));
	if (inet_pton(AF_INET, arg, &v4) == 1) {
		addr->type = ADDR_TYPE_IPV4;
		addr->addrlen = 4;
		memcpy(&addr->addr, &v4, addr->addrlen);
	} else if (inet_pton(AF_INET6, arg, &v6) == 1) {
		addr->type = ADDR_TYPE_IPV6;
		addr->addrlen = 16;
		memcpy(&addr->addr, &v6, addr->addrlen);
	} else {
		err = tal_fmt(NULL, "Unable to parse IP address '%s'", arg);
	}
	return err;
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

static void opt_show_u16(char buf[OPT_SHOW_LEN], const u16 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%u", *u);
}

static char *opt_set_network(const char *arg, struct lightningd *ld)
{
	ld->chainparams = chainparams_for_network(arg);
	if (!ld->chainparams)
		return tal_fmt(NULL, "Unknown network name '%s'", arg);
	ld->dstate.testnet = ld->chainparams->testnet;
	ld->bitcoind->chainparams = ld->chainparams;
	return NULL;
}

/* FIXME: Uncomment once legacy daemon has been removed */
/*
static void opt_show_network(char buf[OPT_SHOW_LEN],
			     const struct lightningd *ld)
{
	snprintf(buf, OPT_SHOW_LEN, "%s", ld->chainparams->network_name);
}
*/

static void config_register_opts(struct lightningd_state *dstate)
{
	opt_register_arg("--locktime-blocks", opt_set_u32, opt_show_u32,
			 &dstate->config.locktime_blocks,
			 "Blocks before peer can unilaterally spend funds");
	opt_register_arg("--max-locktime-blocks", opt_set_u32, opt_show_u32,
			 &dstate->config.locktime_max,
			 "Maximum seconds peer can lock up our funds");
	opt_register_arg("--anchor-onchain", opt_set_u32, opt_show_u32,
			 &dstate->config.anchor_onchain_wait,
			 "Blocks before we give up on pending anchor transaction");
	opt_register_arg("--anchor-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.anchor_confirms,
			 "Confirmations required for anchor transaction");
	opt_register_arg("--max-anchor-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.anchor_confirms_max,
			 "Maximum confirmations other side can wait for anchor transaction");
	opt_register_arg("--forever-confirms", opt_set_u32, opt_show_u32,
			 &dstate->config.forever_confirms,
			 "Confirmations after which we consider a reorg impossible");
	opt_register_arg("--commit-fee-min=<percent>", opt_set_u32, opt_show_u32,
			 &dstate->config.commitment_fee_min_percent,
			 "Minimum percentage of fee to accept for commitment");
	opt_register_arg("--commit-fee-max=<percent>", opt_set_u32, opt_show_u32,
			 &dstate->config.commitment_fee_max_percent,
			 "Maximum percentage of fee to accept for commitment (0 for unlimited)");
	opt_register_arg("--commit-fee=<percent>", opt_set_u32, opt_show_u32,
			 &dstate->config.commitment_fee_percent,
			 "Percentage of fee to request for their commitment");
	opt_register_arg("--override-fee-rate", opt_set_u64, opt_show_u64,
			 &dstate->topology->override_fee_rate,
			 "Force a specific rate in satoshis per kb regardless of estimated fees");
	opt_register_arg("--default-fee-rate", opt_set_u64, opt_show_u64,
			 &dstate->topology->default_fee_rate,
			 "Satoshis per kb if can't estimate fees");
	opt_register_arg("--min-htlc-expiry", opt_set_u32, opt_show_u32,
			 &dstate->config.min_htlc_expiry,
			 "Minimum number of blocks to accept an HTLC before expiry");
	opt_register_arg("--max-htlc-expiry", opt_set_u32, opt_show_u32,
			 &dstate->config.max_htlc_expiry,
			 "Maximum number of blocks to accept an HTLC before expiry");
	opt_register_arg("--deadline-blocks", opt_set_u32, opt_show_u32,
			 &dstate->config.deadline_blocks,
			 "Number of blocks before HTLC timeout before we drop connection");
	opt_register_arg("--bitcoind-poll", opt_set_time, opt_show_time,
			 &dstate->config.poll_time,
			 "Time between polling for new transactions");
	opt_register_arg("--commit-time", opt_set_time, opt_show_time,
			 &dstate->config.commit_time,
			 "Time after changes before sending out COMMIT");
	opt_register_arg("--fee-base", opt_set_u32, opt_show_u32,
			 &dstate->config.fee_base,
			 "Millisatoshi minimum to charge for HTLC");
	opt_register_arg("--fee-per-satoshi", opt_set_s32, opt_show_s32,
			 &dstate->config.fee_per_satoshi,
			 "Microsatoshi fee for every satoshi in HTLC");
	opt_register_noarg("--disable-irc", opt_set_invbool,
			   &dstate->config.use_irc,
			   "Disable IRC peer discovery for routing");

	opt_register_noarg("--ignore-dbversion", opt_set_bool,
			   &dstate->config.db_version_ignore,
			   "Continue despite invalid database version (DANGEROUS!)");

	opt_register_arg("--ipaddr", opt_set_ipaddr, NULL,
			   &dstate->config.ipaddr,
			   "Set the IP address (v4 or v6) to announce to the network for incoming connections");

	/* FIXME: Register opt_show_network with the option */
	opt_register_arg("--network", opt_set_network, NULL,
			 ld_from_dstate(dstate),
			 "Select the network parameters (bitcoin, testnet, "
			 "regtest, or litecoin)");
}

static void dev_register_opts(struct lightningd_state *dstate)
{
	opt_register_noarg("--dev-no-routefail", opt_set_bool,
			   &dstate->dev_never_routefail, opt_hidden);
	opt_register_noarg("--dev-no-broadcast", opt_set_bool,
			   &dstate->topology->dev_no_broadcast, opt_hidden);
}

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

	/* At some point, you've got to let it go... */
	/* FIXME-OLD #onchain:
	 *
	 * Outputs... are considered *irrevocably resolved* once they
	 * are included in a block at least 100 deep on the most-work
	 * blockchain.  100 blocks is far greater than the longest
	 * known bitcoin fork, and the same value used to wait for
	 * confirmations of miner's rewards[1].
	 */
	.forever_confirms = 10,

	/* Testnet fees are crazy, allow infinite feerange. */
	.commitment_fee_min_percent = 0,
	.commitment_fee_max_percent = 0,

	/* We offer to pay 5 times 2-block fee */
	.commitment_fee_percent = 500,

	/* Don't bother me unless I have 6 hours to collect. */
	.min_htlc_expiry = 6 * 6,
	/* Don't lock up channel for more than 5 days. */
	.max_htlc_expiry = 5 * 6 * 24,

	/* If we're closing on HTLC expiry, and you're unresponsive, we abort. */
	.deadline_blocks = 4,

	/* How often to bother bitcoind. */
	.poll_time = TIME_FROM_SEC(10),

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time = TIME_FROM_MSEC(10),

	/* Allow dust payments */
	.fee_base = 1,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* Discover new peers using IRC */
	.use_irc = true,

	/* Don't ignore database version */
	.db_version_ignore = false,

	/* Do not advertise any IP */
	.ipaddr.type = 0,
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

	/* At some point, you've got to let it go... */
	/* FIXME-OLD #onchain:
	 *
	 * Outputs... are considered *irrevocably resolved* once they
	 * are included in a block at least 100 deep on the most-work
	 * blockchain.  100 blocks is far greater than the longest
	 * known bitcoin fork, and the same value used to wait for
	 * confirmations of miner's rewards[1].
	 */
	.forever_confirms = 100,

	/* Insist between 2 and 20 times the 2-block fee. */
	.commitment_fee_min_percent = 200,
	.commitment_fee_max_percent = 2000,

	/* We offer to pay 5 times 2-block fee */
	.commitment_fee_percent = 500,

	/* Don't bother me unless I have 6 hours to collect. */
	.min_htlc_expiry = 6 * 6,
	/* Don't lock up channel for more than 5 days. */
	.max_htlc_expiry = 5 * 6 * 24,

	/* If we're closing on HTLC expiry, and you're unresponsive, we abort. */
	.deadline_blocks = 10,

	/* How often to bother bitcoind. */
	.poll_time = TIME_FROM_SEC(30),

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time = TIME_FROM_MSEC(10),

	/* Discourage dust payments */
	.fee_base = 546000,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* Discover new peers using IRC */
	.use_irc = true,

	/* Don't ignore database version */
	.db_version_ignore = false,

	/* Do not advertise any IP */
	.ipaddr.type = 0,
};

static void check_config(struct lightningd_state *dstate)
{
	/* We do this by ensuring it's less than the minimum we would accept. */
	if (dstate->config.commitment_fee_max_percent != 0
	    && dstate->config.commitment_fee_max_percent
	    < dstate->config.commitment_fee_min_percent)
		fatal("Commitment fee invalid min-max %u-%u",
		      dstate->config.commitment_fee_min_percent,
		      dstate->config.commitment_fee_max_percent);

	if (dstate->config.forever_confirms < 100 && !dstate->testnet)
		log_unusual(dstate->base_log,
			    "Warning: forever-confirms of %u is less than 100!",
			    dstate->config.forever_confirms);

	if (dstate->config.anchor_confirms == 0)
		fatal("anchor-confirms must be greater than zero");

	/* FIXME-OLD #2:
	 *
	 * a node MUST estimate the deadline for successful redemption
	 * for each HTLC it offers.  A node MUST NOT offer a HTLC
	 * after this deadline */
	if (dstate->config.deadline_blocks >= dstate->config.min_htlc_expiry)
		fatal("Deadline %u can't be more than minimum expiry %u",
		      dstate->config.deadline_blocks,
		      dstate->config.min_htlc_expiry);
}

static void setup_default_config(struct lightningd_state *dstate)
{
	if (dstate->testnet)
		dstate->config = testnet_config;
	else
		dstate->config = mainnet_config;
}


/* FIXME: make this nicer! */
static void config_log_stderr_exit(const char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	/* This is the format we expect: mangle it to remove '--'. */
	if (streq(fmt, "%s: %.*s: %s")) {
		const char *argv0 = va_arg(ap, const char *);
		unsigned int len = va_arg(ap, unsigned int);
		const char *arg = va_arg(ap, const char *);
		const char *problem = va_arg(ap, const char *);

		msg = tal_fmt(NULL, "%s line %s: %.*s: %s",
			      argv0, arg+strlen(arg)+1, len-2, arg+2, problem);
	} else {
		msg = tal_vfmt(NULL, fmt, ap);
	}
	va_end(ap);

	fatal("%s", msg);
}

/* We turn the config file into cmdline arguments. */
static void opt_parse_from_config(struct lightningd_state *dstate)
{
	char *contents, **lines;
	char **argv;
	int i, argc;

	contents = grab_file(dstate, "config");
	/* Doesn't have to exist. */
	if (!contents) {
		if (errno != ENOENT)
			fatal("Opening and reading config: %s",
			      strerror(errno));
		/* Now we can set up defaults, since no config file. */
		setup_default_config(dstate);
		return;
	}

	lines = tal_strsplit(contents, contents, "\r\n", STR_NO_EMPTY);

	/* We have to keep argv around, since opt will point into it */
	argv = tal_arr(dstate, char *, argc = 1);
	argv[0] = "lightning config file";

	for (i = 0; i < tal_count(lines) - 1; i++) {
		if (strstarts(lines[i], "#"))
			continue;
		/* Only valid forms are "foo" and "foo=bar" */
		tal_resize(&argv, argc+1);
		/* Stash line number after nul. */
		argv[argc++] = tal_fmt(argv, "--%s%c%u", lines[i], 0, i+1);
	}
	tal_resize(&argv, argc+1);
	argv[argc] = NULL;

	opt_early_parse(argc, argv, config_log_stderr_exit);
	/* Now we can set up defaults, depending on whether testnet or not */
	setup_default_config(dstate);

	opt_parse(&argc, argv, config_log_stderr_exit);
	tal_free(contents);
}

void register_opts(struct lightningd_state *dstate)
{
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);

	opt_register_early_noarg("--help|-h", opt_usage_and_exit,
				 "\n"
				 "A bitcoin lightning daemon.",
				 "Print this message.");
	opt_register_arg("--port", opt_set_u16, opt_show_u16, &dstate->portnum,
			 "Port to bind to (0 means don't listen)");
	opt_register_arg("--bitcoin-datadir", opt_set_charp, NULL,
			 &dstate->bitcoind->datadir,
			 "-datadir arg for bitcoin-cli");
	opt_register_logging(dstate->base_log);
	opt_register_version();

	configdir_register_opts(dstate,
				&dstate->config_dir, &dstate->rpc_filename);
	config_register_opts(dstate);
	dev_register_opts(dstate);
}

bool handle_opts(struct lightningd_state *dstate, int argc, char *argv[])
{
	bool newdir = false;

	/* Get any configdir/testnet options first. */
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
		newdir = true;
	}

	/* Now look for config file */
	opt_parse_from_config(dstate);

	dstate->config.ipaddr.port = dstate->portnum;
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	check_config(dstate);
	return newdir;
}

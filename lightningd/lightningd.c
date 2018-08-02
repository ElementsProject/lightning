#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"
#include <backtrace.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/version.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/invoice.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/onchain_control.h>
#include <lightningd/options.h>
#include <onchaind/onchain_wire.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

char *bitcoin_datadir;

struct backtrace_state *backtrace_state;

int pid_fd;

static struct lightningd *new_lightningd(const tal_t *ctx)
{
	struct lightningd *ld = tal(ctx, struct lightningd);

#if DEVELOPER
	ld->dev_debug_subdaemon = NULL;
	ld->dev_disconnect_fd = -1;
	ld->dev_subdaemon_fail = false;
	ld->dev_allow_localhost = false;

	if (getenv("LIGHTNINGD_DEV_MEMLEAK"))
		memleak_init(ld, backtrace_state);
#endif

	list_head_init(&ld->peers);
	htlc_in_map_init(&ld->htlcs_in);
	htlc_out_map_init(&ld->htlcs_out);
	ld->log_book = new_log_book(20*1024*1024, LOG_INFORM);
	ld->log = new_log(ld, ld->log_book, "lightningd(%u):", (int)getpid());
	ld->logfile = NULL;
	ld->alias = NULL;
	ld->rgb = NULL;
	list_head_init(&ld->connects);
	list_head_init(&ld->fundchannels);
	list_head_init(&ld->waitsendpay_commands);
	list_head_init(&ld->sendpay_commands);
	list_head_init(&ld->close_commands);
	ld->proposed_wireaddr = tal_arr(ld, struct wireaddr_internal, 0);
	ld->proposed_listen_announce = tal_arr(ld, enum addr_listen_announce, 0);
	ld->portnum = DEFAULT_PORT;
	ld->listen = true;
	ld->autolisten = true;
	ld->reconnect = true;
	timers_init(&ld->timers, time_mono());
	ld->topology = new_topology(ld, ld->log);
	ld->daemon = false;
	ld->config_filename = NULL;
	ld->pidfile = NULL;
	ld->ini_autocleaninvoice_cycle = 0;
	ld->ini_autocleaninvoice_expiredby = 86400;
	ld->proxyaddr = NULL;
	ld->use_proxy_always = false;
	ld->pure_tor_setup = false;
	ld->tor_service_password = NULL;
	ld->max_funding_unconfirmed = 2016;

	return ld;
}

static const char *daemons[] = {
	"lightning_channeld",
	"lightning_closingd",
	"lightning_connectd",
	"lightning_gossipd",
	"lightning_hsmd",
	"lightning_onchaind",
	"lightning_openingd"
};

/* Check we can run them, and check their versions */
void test_daemons(const struct lightningd *ld)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(daemons); i++) {
		int outfd;
		const char *dpath = path_join(tmpctx, ld->daemon_dir, daemons[i]);
		const char *verstring;
		pid_t pid = pipecmd(&outfd, NULL, &outfd,
				    dpath, "--version", NULL);

		log_debug(ld->log, "testing %s", dpath);
		if (pid == -1)
			err(1, "Could not run %s", dpath);
		verstring = grab_fd(tmpctx, outfd);
		if (!verstring)
			err(1, "Could not get output from %s", dpath);
		if (!strstarts(verstring, version())
		    || verstring[strlen(version())] != '\n')
			errx(1, "%s: bad version '%s'", daemons[i], verstring);
	}
}
/* Check if all daemons exist in specified directory. */
static bool has_all_daemons(const char* daemon_dir)
{
	size_t i;
	bool missing_daemon = false;

	for (i = 0; i < ARRAY_SIZE(daemons); ++i) {
		if (!path_is_file(path_join(tmpctx, daemon_dir, daemons[i]))) {
			missing_daemon = true;
			break;
		}
	}

	return !missing_daemon;
}

static const char *find_my_path(const tal_t *ctx, const char *argv0)
{
	char *me;

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

static void shutdown_subdaemons(struct lightningd *ld)
{
	struct peer *p;

	db_begin_transaction(ld->wallet->db);
	/* Let everyone shutdown cleanly. */
	close(ld->hsm_fd);
	subd_shutdown(ld->connectd, 10);
	subd_shutdown(ld->gossip, 10);
	subd_shutdown(ld->hsm, 10);

	free_htlcs(ld, NULL);

	while ((p = list_top(&ld->peers, struct peer, list)) != NULL) {
		struct channel *c;

		while ((c = list_top(&p->channels, struct channel, list))
		       != NULL) {
			/* Removes itself from list as we free it */
			tal_free(c);
		}

		/* Freeing uncommitted channel will free peer. */
		if (p->uncommitted_channel) {
			struct uncommitted_channel *uc = p->uncommitted_channel;

			/* Setting to NULL stops destroy_uncommitted_channel
			 * from trying to remove peer from db! */
			p->uncommitted_channel = NULL;
			tal_free(uc);
		}
		/* Removes itself from list as we free it */
		tal_free(p);
	}
	db_commit_transaction(ld->wallet->db);
}

const struct chainparams *get_chainparams(const struct lightningd *ld)
{
	return ld->topology->bitcoind->chainparams;
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

static void daemonize_but_keep_dir(struct lightningd *ld)
{
	/* daemonize moves us into /, but we want to be here */
	const char *cwd = path_cwd(NULL);

	db_close_for_fork(ld->wallet->db);
	if (!cwd)
		fatal("Could not get current directory: %s", strerror(errno));
	if (!daemonize())
		fatal("Could not become a daemon: %s", strerror(errno));

	/* Move back: important, since lightning dir may be relative! */
	if (chdir(cwd) != 0)
		fatal("Could not return to directory %s: %s",
		      cwd, strerror(errno));

	db_reopen_after_fork(ld->wallet->db);
	tal_free(cwd);
}

static void pidfile_create(const struct lightningd *ld)
{
	char *pid;

	/* Create PID file */
	pid_fd = open(ld->pidfile, O_WRONLY|O_CREAT, 0640);
	if (pid_fd < 0)
		err(1, "Failed to open PID file");

	/* Lock PID file */
	if (lockf(pid_fd, F_TLOCK, 0) < 0)
		/* Problem locking file */
		err(1, "lightningd already running? Error locking PID file");

	/* Get current PID and write to PID fie */
	pid = tal_fmt(tmpctx, "%d\n", getpid());
	write_all(pid_fd, pid, strlen(pid));
}

/* Yuck, we need globals here. */
static int (*io_poll_debug)(struct pollfd *, nfds_t, int);
static int io_poll_lightningd(struct pollfd *fds, nfds_t nfds, int timeout)
{
	db_assert_no_outstanding_statements();

	return io_poll_debug(fds, nfds, timeout);
}

void notify_new_block(struct lightningd *ld,
		      u32 block_height)
{
	/* Inform our subcomponents individually. */
	htlcs_notify_new_block(ld, block_height);
	channel_notify_new_block(ld, block_height);
}

int main(int argc, char *argv[])
{
	struct lightningd *ld;
	u32 min_blockheight, max_blockheight;
	int connectd_gossipd_fd;

	setup_locale();
	daemon_setup(argv[0], log_backtrace_print, log_backtrace_exit);
	ld = new_lightningd(NULL);

	/* Figure out where our daemons are first. */
	ld->daemon_dir = find_daemon_dir(ld, argv[0]);
	if (!ld->daemon_dir)
		errx(1, "Could not find daemons");

	register_opts(ld);

	/* Handle options and config; move to .lightningd */
	handle_opts(ld, argc, argv);

	/* Ignore SIGPIPE: we look at our write return values*/
	signal(SIGPIPE, SIG_IGN);

	/* Make sure we can reach other daemons, and versions match. */
	test_daemons(ld);

	/* Initialize wallet, now that we are in the correct directory */
	ld->wallet = wallet_new(ld, ld->log, &ld->timers);
	ld->owned_txfilter = txfilter_new(ld);
	ld->topology->wallet = ld->wallet;

	/* We do extra checks in io_loop. */
	io_poll_debug = io_poll_override(io_poll_lightningd);

	/* Set up HSM. */
	hsm_init(ld);

	/* Now we know our ID, we can set our color/alias if not already. */
	setup_color_and_alias(ld);

	/* Set up connect daemon. */
	connectd_gossipd_fd = connectd_init(ld);

 	/* Set up gossip daemon. */
	gossip_init(ld, connectd_gossipd_fd);

	/* Everything is within a transaction. */
	db_begin_transaction(ld->wallet->db);

	if (!wallet_network_check(ld->wallet, get_chainparams(ld)))
		errx(1, "Wallet network check failed.");

	/* Initialize the transaction filter with our pubkeys. */
	init_txfilter(ld->wallet, ld->owned_txfilter);

        /* Check invoices loaded from the database */
	if (!wallet_invoice_load(ld->wallet)) {
		fatal("Could not load invoices from the database");
	}

	/* Set up invoice autoclean. */
	wallet_invoice_autoclean(ld->wallet,
				 ld->ini_autocleaninvoice_cycle,
				 ld->ini_autocleaninvoice_expiredby);

	/* Load peers from database */
	if (!wallet_channels_load_active(ld, ld->wallet))
		fatal("Could not load channels from the database");

	/* TODO(cdecker) Move this into common location for initialization */
	struct peer *peer;
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel;

		list_for_each(&peer->channels, channel, list) {
			if (!wallet_htlcs_load_for_channel(ld->wallet,
							   channel,
							   &ld->htlcs_in,
							   &ld->htlcs_out)) {
				fatal("could not load htlcs for channel");
			}
		}
	}
	if (!wallet_htlcs_reconnect(ld->wallet, &ld->htlcs_in, &ld->htlcs_out))
		fatal("could not reconnect htlcs loaded from wallet, wallet may be inconsistent.");

	/* Get the blockheight we are currently at, UINT32_MAX is used to signal
	 * an unitialized wallet and that we should start off of bitcoind's
	 * current height */
	wallet_blocks_heights(ld->wallet, UINT32_MAX, &min_blockheight, &max_blockheight);

	/* If we were asked to rescan from an absolute height (--rescan < 0)
	 * then just go there. Otherwise compute the diff to our current height,
	 * lowerbounded by 0. */
	if (ld->config.rescan < 0)
		max_blockheight = -ld->config.rescan;
	else if (max_blockheight < (u32)ld->config.rescan)
		max_blockheight = 0;
	else if (max_blockheight != UINT32_MAX)
		max_blockheight -= ld->config.rescan;

	db_commit_transaction(ld->wallet->db);

	/* Initialize block topology (does its own transaction) */
	setup_topology(ld->topology, &ld->timers, min_blockheight, max_blockheight);

	/* Create RPC socket (if any) */
	setup_jsonrpc(ld, ld->rpc_filename);

	/* Now we're about to start, become daemon if desired. */
	if (ld->daemon)
		daemonize_but_keep_dir(ld);

	/* Create PID file */
	pidfile_create(ld);

	/* Activate connect daemon. Needs to be after the initialization of
	 * chaintopology, otherwise we may be asking for uninitialized data. */
	connectd_activate(ld);

	/* Replay transactions for all running onchainds */
	onchaind_replay_channels(ld);

	/* Mark ourselves live. */
	log_info(ld->log, "Server started with public key %s, alias %s (color #%s) and lightningd %s",
		 type_to_string(tmpctx, struct pubkey, &ld->id),
		 json_escape(tmpctx, (const char *)ld->alias)->s,
		 tal_hex(tmpctx, ld->rgb), version());

	/* Start the peers. */
	activate_peers(ld);

	/* Now kick off topology update, now peers have watches. */
	begin_topology(ld->topology);

	/* Activate crash log now we're not reporting startup failures. */
	crashlog = ld->log;

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

	/* Clean up the JSON-RPC. This needs to happen in a DB transaction since
	 * it might actually be touching the DB in some destructors, e.g.,
	 * unreserving UTXOs (see #1737) */
	db_begin_transaction(ld->wallet->db);
	tal_free(ld->rpc_listener);
	db_commit_transaction(ld->wallet->db);

	close(pid_fd);
	remove(ld->pidfile);

	tal_free(ld);
	opt_free_table();

#if DEVELOPER
	memleak_cleanup();
#endif
	daemon_shutdown();
	return 0;
}

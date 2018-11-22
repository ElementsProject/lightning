/*~ Welcome, wonderful reader!
 *
 * This is the core of c-lightning: the main file of the master daemon
 * `lightningd`.  It's mainly cluttered with the miscellany of setup,
 * and a few startup sanity checks.
 *
 * The role of this daemon is to start the subdaemons, shuffle peers
 * between them, handle the JSON RPC requests, bitcoind, the database
 * and centralize logging.  In theory, it doesn't trust the other
 * daemons, though we expect `hsmd` (which holds secret keys) to be
 * responsive.
 *
 * Comments beginning with a ~ (like this one!) are part of our shared
 * adventure through the source, so they're more meta than normal code
 * comments, and meant to be read in a certain order.
 */

/*~ Notice how includes are in ASCII order: this is actually enforced by
 * the build system under `make check-source`.  It avoids merge conflicts
 * and keeps things consistent. */
#include "gossip_control.h"
#include "hsm_control.h"
#include "lightningd.h"
#include "peer_control.h"
#include "subd.h"

/*~ This is Ian Lance Taylor's libbacktrace.  It turns out that it's
 * horrifically difficult to obtain a decent backtrace in C; the standard
 * backtrace function is useless in most programs. */
#include <backtrace.h>

/*~ These headers are from CCAN: http://ccodearchive.net.
 *
 * It's another one of Rusty's projects, and we copy and paste it
 * automatically into the source tree here, so you should never edit
 * it.  There's a Makefile target update-ccan to update it (and add modules
 * if CCAN_NEW is specified).
 *
 * The most used of these are `ccan/tal` and `ccan/take`, which we'll describe
 * in detail below.
 */
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

/*~ This is common code: routines shared by one or more executables
 *  (separate daemons, or the lightning-cli program). */
#include <common/daemon.h>
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
#include <lightningd/json_escaped.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/onchain_control.h>
#include <lightningd/options.h>
#include <onchaind/onchain_wire.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

/*~ The core lightning object: it's passed everywhere, and is basically a
 * global variable.  This new_xxx pattern is something we'll see often:
 * it allocates and initializes a new structure, using *tal*, the hierarchical
 * allocator. */
static struct lightningd *new_lightningd(const tal_t *ctx)
{
	/*~ tal: each allocation is a child of an existing object (or NULL,
	 * the top-level object).  When an object is freed, all the objects
	 * `tallocated` off it are also freed.  We use it in place of malloc
	 * and free.  For the technically inclined: tal allocations usually
	 * build a tree, and tal_freeing any node in the tree will result in
	 * the entire subtree rooted at that node to be freed.
	 *
	 * It's incredibly useful for grouping object lifetimes, as we'll see.
	 * For example, a `struct bitcoin_tx` has a pointer to an array of
	 * `struct bitcoin_tx_input`; they are allocated off the `struct
	 * bitcoind_tx`, so freeing the `struct bitcoind_tx` frees them all.
	 *
	 * In this case, freeing `ctx` will free `ld`:
	 */
	struct lightningd *ld = tal(ctx, struct lightningd);

	/*~ Style note: `ctx` is declared `const`, yet we can `tallocate` from
	 * it.  Adding/removing children is not considered to change an
	 * object; nor, in fact, is freeing it with tal_free().  This allows
	 * us to use const more liberally: the style rule here is that you
	 * should use 'const' on pointers if you can. */

	/*~ Note that we generally EXPLICITLY #if-wrap DEVELOPER code.  This
	 * is a nod to keeping it minimal and explicit: we need this code for
	 * testing, but its existence means we're not actually testing the
	 * same exact code users will be running. */
#if DEVELOPER
	ld->dev_debug_subdaemon = NULL;
	ld->dev_disconnect_fd = -1;
	ld->dev_subdaemon_fail = false;
	ld->dev_allow_localhost = false;
#endif

	/*~ These are CCAN lists: an embedded double-linked list.  It's not
	 * really typesafe, but relies on convention to access the contents.
	 * It's inspired by the closely-related Linux kernel list.h.
	 *
	 * You declare them as a `struct list_head` (or use the LIST_HEAD()
	 * macro which doesn't work on dynamically-allocated objects like `ld`
	 * here).  The item which will go into the list must declared a
	 * `struct list_node` for each list it can be in.
	 *
	 * The most common operations are list_head_init(), list_add(),
	 * list_del() and list_for_each().
	 *
	 * This method of manually declaring the list hooks avoids dynamic
	 * allocations to put things into a list. */
	list_head_init(&ld->peers);

	/*~ These are hash tables of incoming and outgoing HTLCs (contracts),
	 * defined as `struct htlc_in` and `struct htlc_out`in htlc_end.h.
	 * The hash tables are declared there using the very ugly
	 * HTABLE_DEFINE_TYPE macro.  The key is the channel the HTLC is in
	 * and the 64-bit htlc-id which is unique for that channel and
	 * direction.  That htlc-id is used in the inter-peer wire protocol,
	 * so it is the logical key.
	 *
	 * There aren't usually many HTLCs, so we could have just used a linked
	 * list attached to the channel structure itself, or even left them in
	 * the database rather than making an in-memory version.  Obviously
	 * I was in a premature optimization mood when I wrote this: */
	htlc_in_map_init(&ld->htlcs_in);
	htlc_out_map_init(&ld->htlcs_out);

	/*~ We have a two-level log-book infrastructure: we define a 20MB log
	 * book to hold all the entries (and trims as necessary), and multiple
	 * log objects which each can write into it, each with a unique
	 * prefix. */
	ld->log_book = new_log_book(20*1024*1024, LOG_INFORM);
	/*~ Note the tal context arg (by convention, the first argument to any
	 * allocation function): ld->log will be implicitly freed when ld
	 * is. */
	ld->log = new_log(ld, ld->log_book, "lightningd(%u):", (int)getpid());
	ld->logfile = NULL;

	/*~ We explicitly set these to NULL: if they're still NULL after option
	 * parsing, we know they're to be set to the defaults. */
	ld->alias = NULL;
	ld->rgb = NULL;
	list_head_init(&ld->connects);
	list_head_init(&ld->waitsendpay_commands);
	list_head_init(&ld->sendpay_commands);
	list_head_init(&ld->close_commands);
	list_head_init(&ld->ping_commands);

	/*~ Tal also explicitly supports arrays: it stores the number of
	 * elements, which can be accessed with tal_count() (or tal_bytelen()
	 * for raw bytecount).  It's common for simple arrays to use
	 * tal_resize() (or tal_arr_expand) to expand, which does not work on
	 * NULL.  So we start with an zero-length array. */
	ld->proposed_wireaddr = tal_arr(ld, struct wireaddr_internal, 0);
	ld->proposed_listen_announce = tal_arr(ld, enum addr_listen_announce, 0);
	ld->portnum = DEFAULT_PORT;
	ld->listen = true;
	ld->autolisten = true;
	ld->reconnect = true;

	/*~ This is from ccan/timer: it is efficient for the case where timers
	 * are deleted before expiry (as is common with timeouts) using an
	 * ingenious bucket system which more precisely sorts timers as they
	 * approach expiry.  It's a fascinating implementation you should read
	 * if you have a spare few hours. */
	timers_init(&ld->timers, time_mono());

	/*~ This is detailed in chaintopology.c */
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

	/*~ In the next step we will initialize the plugins. This will
	 *  also populate the JSON-RPC with passthrough methods, hence
	 *  lightningd needs to have something to put those in. This
	 *  is that :-)
	 */
	ld->jsonrpc = jsonrpc_new(ld, ld);

	/*~ We run a number of plugins (subprocesses that we talk JSON-RPC with)
	 *alongside this process. This allows us to have an easy way for users
	 *to add their own tools without having to modify the c-lightning source
	 *code. Here we initialize the context that will keep track and control
	 *the plugins.
	 */
	ld->plugins = plugins_new(ld, ld->log_book);

	return ld;
}

/*~ We list our daemons here so on startup we can test they're the
 * correct versions and that they exist. */
static const char *subdaemons[] = {
	"lightning_channeld",
	"lightning_closingd",
	"lightning_connectd",
	"lightning_gossipd",
	"lightning_hsmd",
	"lightning_onchaind",
	"lightning_openingd"
};

/*~ Check we can run them, and check their versions */
void test_subdaemons(const struct lightningd *ld)
{
	size_t i;

	/*~ CCAN's ARRAY_SIZE() should always be used on defined arrays like
	 * the subdaemons array above.  You can calculate the number of
	 * elements it has using `sizeof(subdaemons)/sizeof(subdaemons[0])`
	 * but if `subdaemons` were refactored into a pointer (eg. to make
	 * it a dynamic array) that would erroneously evaluate to `1`.
	 *
	 * ARRAY_SIZE will cause a compiler error if the argument is actually
	 * a pointer, not an array. */
	for (i = 0; i < ARRAY_SIZE(subdaemons); i++) {
		int outfd;
		/*~ CCAN's path module uses tal, so wants a context to
		 * allocate from.  We have a magic convenience context
		 * `tmpctx` for temporary allocations like this.
		 *
		 * Because all our daemons at their core are of form `while
		 * (!stopped) handle_events();` (an event loop pattern), we
		 * can free `tmpctx` in that top-level loop after each event
		 * is handled.
		 */
		const char *dpath = path_join(tmpctx, ld->daemon_dir, subdaemons[i]);
		const char *verstring;
		/*~ CCAN's pipecmd module is like popen for grownups: it
		 * takes pointers to fill in stdout, stdin and stderr file
		 * descriptors if desired, and the remainder of arguments
		 * are the command and its argument. */
		pid_t pid = pipecmd(&outfd, NULL, &outfd,
				    dpath, "--version", NULL);

		/*~ Our logging system: spam goes in at log_debug level, but
		 * logging is mainly added by developer necessity and removed
		 * by developer/user complaints .  The only strong convention
		 * is that log_broken() is used for "should never happen".
		 *
		 * Note, however, that logging takes care to preserve the
		 * global `errno` which is set above. */
		log_debug(ld->log, "testing %s", dpath);

		/*~ ccan/err is a wrapper around BSD's err.h, which defines
		 * the convenience functions err() (error with message
		 * followed by a string based on errno) and errx() (same,
		 * but no errno string). */
		if (pid == -1)
			err(1, "Could not run %s", dpath);

		/*~ CCAN's grab_file module contains a routine to read into a
		 * tallocated buffer until EOF */
		verstring = grab_fd(tmpctx, outfd);
		/*~ Like many CCAN modules, it set errno on failure, which
		 * err (ccan/err, but usually just the BSD <err.h>) prints */
		if (!verstring)
			err(1, "Could not get output from %s", dpath);
		/*~ strstarts is from CCAN/str. */
		if (!strstarts(verstring, version())
		    || verstring[strlen(version())] != '\n')
			errx(1, "%s: bad version '%s'",
			     subdaemons[i], verstring);
	}
}

/* Check if all subdaemons exist in specified directory. */
static bool has_all_subdaemons(const char *daemon_dir)
{
	size_t i;
	bool missing_daemon = false;

	for (i = 0; i < ARRAY_SIZE(subdaemons); ++i) {
		if (!path_is_file(path_join(tmpctx, daemon_dir, subdaemons[i]))) {
			missing_daemon = true;
			break;
		}
	}

	return !missing_daemon;
}

/* Returns the directory this executable is running from */
static const char *find_my_directory(const tal_t *ctx, const char *argv0)
{
	/* find_my_abspath simply exits on failure, so never returns NULL. */
	const char *me = find_my_abspath(NULL, argv0);

	/*~ The caller just wants the directory we're in.
	 *
	 * Note the magic `take()` macro here: it annotates a pointer as "to
	 * be taken", and the recipient is expected to take ownership of the
	 * pointer.  This improves efficiency because the recipient might
	 * choose to use or even keep it rather than make a copy (or it
	 * might just free it).
	 *
	 * Many CCAN and our own routines support this, but if you hand a
	 * `take()` to a routine which *doesn't* expect it, unfortunately you
	 * don't get a compile error (we have runtime detection for this
	 * case, however).
	 */
	return path_dirname(ctx, take(me));
}

/*~ This returns the PKGLIBEXEC path which is where binaries get installed.
 * Note the `TAKES` annotation which indicates that the `my_path` parameter
 * can be take(); in which case, this function will handle freeing it.
 *
 * TAKES is only a convention unfortunately, and ignored by the compiler.
 */
static const char *find_my_pkglibexec_path(const tal_t *ctx,
					   const char *my_path TAKES)
{
	const char *pkglibexecdir;

	/*~`path_join` is declared in ccan/path/path.h as:
	 *
	 *     char *path_join(const tal_t *ctx,
	 *                     const char *base TAKES, const char *a TAKES);
	 *
	 * So, as we promised with 'TAKES' in our own declaration, if the
	 * caller has called `take()` the `my_path` parameter, path_join()
	 * will free it. */
	pkglibexecdir = path_join(ctx, my_path, BINTOPKGLIBEXECDIR);

	/*~ Sometimes take() can be more efficient, since the routine can
	 * manipulate the string in place.  This is the case here. */
	return path_simplify(ctx, take(pkglibexecdir));
}

/* Determine the correct daemon dir. */
static const char *find_daemon_dir(const tal_t *ctx, const char *argv0)
{
	const char *my_path = find_my_directory(ctx, argv0);
	/* If we're running in-tree, all the subdaemons are with lightningd. */
	if (has_all_subdaemons(my_path))
		return my_path;

	/* Otherwise we assume they're in the installed dir. */
	return find_my_pkglibexec_path(ctx, take(my_path));
}

/*~ We like to free everything on exit, so valgrind doesn't complain (valgrind
 * is an awesome runtime memory usage detector for C and C++ programs). In
 * some ways it would be neater not to do this, but it turns out some
 * transient objects still need cleaning. */
static void shutdown_subdaemons(struct lightningd *ld)
{
	struct peer *p;

	/*~ tal supports *destructors* using `tal_add_destructor()`; the most
	 * common use is for an object to delete itself from a linked list
	 * when it's freed.
	 *
	 * As a result, freeing an object (which frees any tal objects
	 * allocated off it, and any allocated off them, etc) may cause
	 * callbacks; in this case, some objects freed here can cause database
	 * writes, which must be inside a transaction. */
	db_begin_transaction(ld->wallet->db);

	/* Let everyone shutdown cleanly. */
	close(ld->hsm_fd);
	/*~ The three "global" daemons, which we shutdown explicitly: we
	 * give them 10 seconds to exit gracefully before killing them.  */
	subd_shutdown(ld->connectd, 10);
	subd_shutdown(ld->gossip, 10);
	subd_shutdown(ld->hsm, 10);

	/* Now we free all the HTLCs */
	free_htlcs(ld, NULL);

	/*~ For every peer, we free every channel.  On allocation the peer was
	 * given a destructor (`destroy_peer`) which removes itself from the
	 * list.  Thus we use list_top() not list_pop() here. */
	while ((p = list_top(&ld->peers, struct peer, list)) != NULL) {
		struct channel *c;

		/*~ A peer can have multiple channels; we only allow one to be
		 * open at any time, but we remember old ones for 100 blocks,
		 * after all the outputs we care about are spent. */
		while ((c = list_top(&p->channels, struct channel, list))
		       != NULL) {
			/* Removes itself from list as we free it */
			tal_free(c);
		}

		/* A peer may have a channel in the process of opening. */
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

	/*~ Commit the transaction.  Note that the db is actually
	 * single-threaded, so commits never fail and we don't need
	 * spin-and-retry logic everywhere. */
	db_commit_transaction(ld->wallet->db);
}

/*~ Chainparams are the parameters for eg. testnet vs mainnet.  This wrapper
 * saves lots of struggles with our 80-column guideline! */
const struct chainparams *get_chainparams(const struct lightningd *ld)
{
	/* "The lightningd is connected to the blockchain."
	 * "The blockchain is connected to the bitcoind API."
	 * "The bitcoind API is connected chain parameters."
	 * -- Worst childhood song ever. */
	return ld->topology->bitcoind->chainparams;
}

/*~ Our wallet logic needs to know what outputs we might be interested in.  We
 * use BIP32 (a.k.a. "HD wallet") to generate keys from a single seed, so we
 * keep the maximum-ever-used key index in the db, and add them all to the
 * filter here. */
static void init_txfilter(struct wallet *w, struct txfilter *filter)
{
	/*~ This is defined in libwally, so we didn't have to reimplement */
	struct ext_key ext;
	/*~ Note the use of ccan/short_types u64 rather than uint64_t.
	 * Thank me later. */
	u64 bip32_max_index;

	bip32_max_index = db_get_intvar(w->db, "bip32_max_index", 0);
	/*~ One of the C99 things I unequivocally approve: for-loop scope. */
	for (u64 i = 0; i <= bip32_max_index; i++) {
		if (bip32_key_from_parent(w->bip32_base, i, BIP32_FLAG_KEY_PUBLIC, &ext) != WALLY_OK) {
			abort();
		}
		txfilter_add_derkey(filter, ext.pub_key);
	}
}

/*~ The normal advice for daemons is to move into the root directory, so you
 * don't prevent unmounting whatever filesystem you happen to start in.
 *
 * But we define every path relative to our (~/.lightning) data dir, so we
 * make sure we stay there.
 */
static void daemonize_but_keep_dir(struct lightningd *ld)
{
	/* daemonize moves us into /, but we want to be here */
	const char *cwd = path_cwd(NULL);

	/*~ SQLite3 does NOT like being open across fork(), a.k.a. daemonize() */
	db_close_for_fork(ld->wallet->db);
	if (!cwd)
		fatal("Could not get current directory: %s", strerror(errno));
	if (!daemonize())
		fatal("Could not become a daemon: %s", strerror(errno));

	/*~ Move back: important, since lightning dir may be relative! */
	if (chdir(cwd) != 0)
		fatal("Could not return to directory %s: %s",
		      cwd, strerror(errno));

	db_reopen_after_fork(ld->wallet->db);

	/*~ Why not allocate cwd off tmpctx?  Probably because this code predates
	 * tmpctx.  So we free manually here. */
	tal_free(cwd);
}

/*~ It's pretty standard behaviour (especially for daemons) to create and
 * file-lock a pidfile.  This not only prevents accidentally running multiple
 * daemons on the same database at once, but lets nosy sysadmins see what pid
 * the currently-running daemon is supposed to be. */
static int pidfile_create(const struct lightningd *ld)
{
	int pid_fd;

	/* Create PID file */
	pid_fd = open(ld->pidfile, O_WRONLY|O_CREAT, 0640);
	if (pid_fd < 0)
		err(1, "Failed to open PID file");

	/* Lock PID file, so future lockf will fail. */
	if (lockf(pid_fd, F_TLOCK, 0) < 0)
		/* Problem locking file */
		err(1, "lightningd already running? Error locking PID file");

	/*~ As closing the file will remove the lock, we need to keep it open;
	 * the OS will close it implicitly when we exit for any reason. */
	return pid_fd;
}

/*~ Writing the pid into the lockfile provides a useful clue to users as to
 * what created it; however, we can't do that until we've got a stable process
 * id, and if --daemon is specified, that's quite late. */
static void pidfile_write(const struct lightningd *ld, int pid_fd)
{
	char *pid;

	/*~ Note that tal_fmt() is what asprintf() dreams of being. */
	pid = tal_fmt(tmpctx, "%d\n", getpid());
	/*~ CCAN's write_all writes to a file descriptor, looping if necessary
	 * (which, on a file unlike a socket, is never, for historical UNIX
	 * reasons).  It also isn't declared with GCC's warn_unused_result
	 * which write() is when FORTIFY_SOURCE is defined, so we're allowed
	 * to ignore the result without jumping through hoops. */
	write_all(pid_fd, pid, strlen(pid));
}

/*~ ccan/io allows overriding the poll() function that is the very core
 * of the event loop it runs for us.  We override it so that we can do
 * extra sanity checks, and it's also a good point to free the tmpctx. */
static int io_poll_lightningd(struct pollfd *fds, nfds_t nfds, int timeout)
{
	/*~ In particular, we should *not* have left a database transaction
	 * open! */
	db_assert_no_outstanding_statements();

	/* The other checks and freeing tmpctx are common to all daemons. */
	return daemon_poll(fds, nfds, timeout);
}

/*~ Ever had one of those functions which doesn't quite fit anywhere?  Me too.
 * Implementing a generic notifier framework is overkill in a static codebase
 * like this, and it's always better to have compile-time calls than runtime,
 * as it makes the code more explicit.  But pasting in direct calls is also an
 * abstraction violation, so we use this middleman function. */
void notify_new_block(struct lightningd *ld, u32 block_height)
{
	/* Inform our subcomponents individually. */
	htlcs_notify_new_block(ld, block_height);
	channel_notify_new_block(ld, block_height);
}

int main(int argc, char *argv[])
{
	struct lightningd *ld;
	u32 min_blockheight, max_blockheight;
	int connectd_gossipd_fd, pid_fd;

	/*~ What happens in strange locales should stay there. */
	setup_locale();
	/*~ Every daemon calls this in some form: the hooks are for dumping
	 * backtraces when we crash (if supported on this platform). */
	daemon_setup(argv[0], log_backtrace_print, log_backtrace_exit);

	/*~ There's always a battle between what a constructor like this
	 * should do, and what should be added later by the caller.  In
	 * general, because we use valgrind heavily for testing, we prefer not
	 * to initialize unused fields which we expect the caller to set:
	 * valgrind will warn us if we make decisions based on uninitialized
	 * variables. */
	ld = new_lightningd(NULL);

	/* Figure out where our daemons are first. */
	ld->daemon_dir = find_daemon_dir(ld, argv[0]);
	if (!ld->daemon_dir)
		errx(1, "Could not find daemons");

	/*~ The ccan/opt code requires registration then parsing; we
	 *  mimic this API here, even though they're on separate lines.*/
	register_opts(ld);

	/*~ Handle early options, but don't move to --lightning-dir
	 *  just yet. Plugins may add new options, which is why we are
	 *  splitting between early args (including --plugin
	 *  registration) and non-early opts. */
	handle_early_opts(ld, argc, argv);

	/*~ Initialize all the plugins we just registered, so they can
	 *  do their thing and tell us about themselves (including
	 *  options registration). */
	plugins_init(ld->plugins);

	/*~ Handle options and config; move to .lightningd (--lightning-dir) */
	handle_opts(ld, argc, argv);

	/*~ Now that we have collected all the early options, gave
	 *  plugins a chance to register theirs and collected all
	 *  remaining options it's time to tell the plugins. */
	plugins_config(ld->plugins);

	/*~ Make sure we can reach the subdaemons, and versions match. */
	test_subdaemons(ld);

	/*~ Our "wallet" code really wraps the db, which is more than a simple
	 * bitcoin wallet (though it's that too).  It also stores channel
	 * states, invoices, payments, blocks and bitcoin transactions. */
	ld->wallet = wallet_new(ld, ld->log, &ld->timers);

	/*~ We keep a filter of scriptpubkeys we're interested in. */
	ld->owned_txfilter = txfilter_new(ld);

	/*~ This is the ccan/io central poll override from above. */
	io_poll_override(io_poll_lightningd);

	/*~ Set up the HSM daemon, which knows our node secret key, so tells
	 *  us who we are.
	 *
	 * HSM stands for Hardware Security Module, which is the industry
	 * standard of key storage; ours is in software for now, so the name
	 * doesn't really make sense, but we can't call it the Badly-named
	 * Daemon Software Module. */
	hsm_init(ld);

	/*~ Our default color and alias are derived from our node id, so we
	 * can only set those now (if not set by config options). */
	setup_color_and_alias(ld);

	/*~ Set up connect daemon: this manages receiving and making
	 * TCP connections.  It needs to talk to the gossip daemon
	 * which knows (via node_announcement messages) the public
	 * addresses of nodes, so connectd_init hands it one end of a
	 * socket pair, and gives us the other */
	connectd_gossipd_fd = connectd_init(ld);

 	/*~ The gossip daemon looks after the routing gossip;
	 *  channel_announcement, channel_update, node_announcement and gossip
	 *  queries. */
	gossip_init(ld, connectd_gossipd_fd);

	/*~ We do every database operation within a transaction; usually this
	 * is covered by the infrastructure (eg. opening a transaction before
	 * handling a message or expiring a timer), but for startup we do this
	 * explicitly. */
	db_begin_transaction(ld->wallet->db);

	/*~ Our default names, eg. for the database file, are not dependent on
	 * the network.  Instead, the db knows what chain it belongs to, and we
	 * simple barf here if it's wrong. */
	if (!wallet_network_check(ld->wallet, get_chainparams(ld)))
		errx(1, "Wallet network check failed.");

	/*~ Initialize the transaction filter with our pubkeys. */
	init_txfilter(ld->wallet, ld->owned_txfilter);

	/*~ Set up invoice autoclean. */
	wallet_invoice_autoclean(ld->wallet,
				 ld->ini_autocleaninvoice_cycle,
				 ld->ini_autocleaninvoice_expiredby);

	/*~ Pull peers, channels and HTLCs from db. */
	load_channels_from_wallet(ld);

	/*~ Get the blockheight we are currently at, UINT32_MAX is used to signal
	 * an uninitialized wallet and that we should start off of bitcoind's
	 * current height */
	wallet_blocks_heights(ld->wallet, UINT32_MAX,
			      &min_blockheight, &max_blockheight);

	/*~ If we were asked to rescan from an absolute height (--rescan < 0)
	 * then just go there. Otherwise compute the diff to our current height,
	 * lowerbounded by 0. */
	if (ld->config.rescan < 0)
		max_blockheight = -ld->config.rescan;
	else if (max_blockheight < (u32)ld->config.rescan)
		max_blockheight = 0;
	else if (max_blockheight != UINT32_MAX)
		max_blockheight -= ld->config.rescan;

	/*~ That's all of the wallet db operations for now. */
	db_commit_transaction(ld->wallet->db);

	/*~ Initialize block topology.  This does its own io_loop to
	 * talk to bitcoind, so does its own db transactions. */
	setup_topology(ld->topology, &ld->timers,
		       min_blockheight, max_blockheight);

	/*~ Now create the PID file: this errors out if there's already a
	 * daemon running, so we call before trying to create an RPC socket. */
	pid_fd = pidfile_create(ld);

	/*~ Create RPC socket: now lightning-cli can send us JSON RPC commands
	 *  over a UNIX domain socket specified by `ld->rpc_filename`. */
	jsonrpc_listen(ld->jsonrpc, ld);

	/*~ We defer --daemon until we've completed most initialization: that
	 *  way we'll exit with an error rather than silently exiting 0, then
	 *  realizing we can't start and forcing the confused user to read the
	 *  logs. */
	if (ld->daemon)
		daemonize_but_keep_dir(ld);

	/*~ We have to do this after daemonize, since that changes our pid! */
	pidfile_write(ld, pid_fd);

	/*~ Activate connect daemon.  Needs to be after the initialization of
	 * chaintopology, otherwise peers may connect and ask for
	 * uninitialized data. */
	connectd_activate(ld);

	/*~ "onchaind" is a dumb daemon which tries to get our funds back: it
	 * doesn't handle reorganizations, but it's idempotent, so we can
	 * simply just restart it if the chain moves.  Similarly, we replay it
	 * chain events from the database on restart, beginning with the
	 * "funding transaction spent" event which creates it. */
	onchaind_replay_channels(ld);

	/*~ Mark ourselves live.
	 *
	 * Note the use of type_to_string() here: it's a typesafe formatter,
	 * often handed 'tmpctx' like here to allocate a throwaway string for
	 * formatting.  json_escape() avoids printing weird characters in our
	 * log.  And tal_hex() is a helper from utils which returns a hex string;
	 * it's assumed that the argument was allocated with tal or tal_arr
	 * so it can use tal_bytelen() to get the length. */
	log_info(ld->log, "Server started with public key %s, alias %s (color #%s) and lightningd %s",
		 type_to_string(tmpctx, struct pubkey, &ld->id),
		 json_escape(tmpctx, (const char *)ld->alias)->s,
		 tal_hex(tmpctx, ld->rgb), version());

	/*~ This is where we ask connectd to reconnect to any peers who have
	 * live channels with us, and makes sure we're watching the funding
	 * tx. */
	activate_peers(ld);

	/*~ Now that all the notifications for transactions are in place, we
	 *  can start the poll loop which queries bitcoind for new blocks. */
	begin_topology(ld->topology);

	/*~ Setting this (global) activates the crash log: we don't usually need
	 * a backtrace if we fail during startup. */
	crashlog = ld->log;

	/*~ The root of every backtrace (almost).  This is our main event
	 *  loop. */
	for (;;) {
		/* ~ccan/io's io_loop() continuously calls
		 * io_poll_lightningd() for all file descriptors registered
		 * with it, then calls their callbacks or closes them if they
		 * fail, as appropriate.
		 *
		 * It will only exit if there's an expired timer, *or* someone
		 * calls io_break, or if there are no more file descriptors
		 * (which never happens in our code). */
		struct timer *expired;
		void *v = io_loop(&ld->timers, &expired);

		/*~ We use io_break(ld) to shut down. */
		if (v == ld)
			break;

		/*~ Notice that timers are called here in the event loop like
		 * anything else, so there are no weird concurrency issues. */
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
	tal_free(ld->jsonrpc);
	db_commit_transaction(ld->wallet->db);

	remove(ld->pidfile);

	/* FIXME: pay can have children off tmpctx which unlink from
	 * ld->payments, so clean that up. */
	clean_tmpctx();
	tal_free(ld);
	opt_free_table();

	daemon_shutdown();

	/*~ Farewell.  Next stop: hsmd/hsmd.c. */
	return 0;
}

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
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/json_escape/json_escape.h>
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
#include <common/ecdh_hsmd.h>
#include <common/features.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <common/version.h>

#include <errno.h>
#include <fcntl.h>
#include <gen_header_versions.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/connect_control.h>
#include <lightningd/invoice.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>
#include <lightningd/memdump.h>
#include <lightningd/onchain_control.h>
#include <lightningd/options.h>
#include <onchaind/onchain_wire.h>
#include <signal.h>
#include <sodium.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

static void destroy_alt_subdaemons(struct lightningd *ld);
#if DEVELOPER
static void memleak_help_alt_subdaemons(struct htable *memtable,
					struct lightningd *ld);
#endif /* DEVELOPER */

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
	 * For example, a `struct lightningd` has a pointer to a `log_book`
	 * which is allocated off the `struct lightningd`, and has its own
	 * internal members allocated off `log_book`: freeing `struct
	 * lightningd` frees them all.
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
	ld->dev_debug_subprocess = NULL;
	ld->dev_disconnect_fd = -1;
	ld->dev_subdaemon_fail = false;
	ld->dev_allow_localhost = false;
	ld->dev_gossip_time = 0;
	ld->dev_fast_gossip = false;
	ld->dev_fast_gossip_prune = false;
	ld->dev_force_privkey = NULL;
	ld->dev_force_bip32_seed = NULL;
	ld->dev_force_channel_secrets = NULL;
	ld->dev_force_channel_secrets_shaseed = NULL;
	ld->dev_force_tmp_channel_id = NULL;
	ld->dev_no_htlc_timeout = false;
	ld->dev_no_version_checks = false;
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
	 * defined as `struct htlc_in` and `struct htlc_out` in htlc_end.h.
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

	/*~ For multi-part payments, we need to keep some incoming payments
	 * in limbo until we get all the parts, or we time them out. */
	htlc_set_map_init(&ld->htlc_sets);

	/*~ We have a multi-entry log-book infrastructure: we define a 100MB log
	 * book to hold all the entries (and trims as necessary), and multiple
	 * log objects which each can write into it, each with a unique
	 * prefix. */
	ld->log_book = new_log_book(ld, 100*1024*1024);
	/*~ Note the tal context arg (by convention, the first argument to any
	 * allocation function): ld->log will be implicitly freed when ld
	 * is. */
	ld->log = new_log(ld, ld->log_book, NULL, "lightningd");
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
	list_head_init(&ld->waitblockheight_commands);

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
	ld->timers = tal(ld, struct timers);
	timers_init(ld->timers, time_mono());

	/*~ This is detailed in chaintopology.c */
	ld->topology = new_topology(ld, ld->log);
	ld->daemon_parent_fd = -1;
	ld->proxyaddr = NULL;
	ld->use_proxy_always = false;
	ld->pure_tor_setup = false;
	ld->tor_service_password = NULL;
	ld->max_funding_unconfirmed = 2016;

	/*~ This is initialized later, but the plugin loop examines this,
	 * so set it to NULL explicitly now. */
	ld->wallet = NULL;

	/*~ In the next step we will initialize the plugins. This will
	 *  also populate the JSON-RPC with passthrough methods, hence
	 *  lightningd needs to have something to put those in. This
	 *  is that :-)
	 */
	jsonrpc_setup(ld);

	/*~ We changed when we start plugins, messing up relative paths.
	 * This saves our original dirs so we can fixup and warn for the
	 * moment (0.7.2). */
	ld->original_directory = path_cwd(ld);

	/*~ We run a number of plugins (subprocesses that we talk JSON-RPC with)
	 * alongside this process. This allows us to have an easy way for users
	 * to add their own tools without having to modify the c-lightning source
	 * code. Here we initialize the context that will keep track and control
	 * the plugins.
	 */
	ld->plugins = plugins_new(ld, ld->log_book, ld);
	ld->plugins->startup = true;

	/*~ This is set when a JSON RPC command comes in to shut us down. */
	ld->stop_conn = NULL;

	/*~ This is used to signal that `hsm_secret` is encrypted, and will
	 * be set to `true` if the `--encrypted-hsm` option is passed at startup.
	 */
	ld->encrypted_hsm = false;

	/* This is used to override subdaemons */
	strmap_init(&ld->alt_subdaemons);
	tal_add_destructor(ld, destroy_alt_subdaemons);
	memleak_add_helper(ld, memleak_help_alt_subdaemons);

	/*~ We change umask if we daemonize, but not if we don't. Initialize the
	 * initial_umask anyway as we might rely on it later (`plugin start`). */
	ld->initial_umask = umask(0);
	umask(ld->initial_umask);

	/*~ This is the mode of the created JSON-RPC socket file, in
	 * traditional Unix octal. 0600 means only the user that ran
	 * lightningd can invoke RPC on it. Changing it to 0660 may
	 * be sensible if you run lightningd in its own system user,
	 * and just let specific users (add the group of the
	 * lightningd runner as an ancillary group) access its
	 * RPC. Can be overridden with `--rpc-file-mode`.
	 */
	ld->rpc_filemode = 0600;

	/*~ This is the exit code to use on exit.
	 * Set to NULL meaning we are not interested in exiting yet.
	 */
	ld->exit_code = NULL;

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

/* Return true if called with a recognized subdaemon e.g. "hsmd" */
bool is_subdaemon(const char *sdname)
{
	for (size_t i = 0; i < ARRAY_SIZE(subdaemons); i++)
		/* Skip the "lightning_" prefix in the table */
		if (streq(sdname, subdaemons[i] + strlen("lightning_")))
			return true;
	return false;
}

static void destroy_alt_subdaemons(struct lightningd *ld)
{
	strmap_clear(&ld->alt_subdaemons);
}

#if DEVELOPER
static void memleak_help_alt_subdaemons(struct htable *memtable,
					struct lightningd *ld)
{
	memleak_remove_strmap(memtable, &ld->alt_subdaemons);
}
#endif /* DEVELOPER */

const char *subdaemon_path(const tal_t *ctx, const struct lightningd *ld, const char *name)
{
	/* Strip the leading "lightning_" before looking in alt_subdaemons.
	 */
	size_t pfxlen = strlen("lightning_");
	assert(strlen(name) > pfxlen);
	const char *short_name = tal_strdup(ctx, name + pfxlen);

	/* Is there an alternate path for this subdaemon? */
	const char *dpath;
	const char *alt = strmap_get(&ld->alt_subdaemons, short_name);
	if (alt) {
		/* path_join will honor absolute paths as well. */
		dpath = path_join(ctx, ld->daemon_dir, alt);
	} else {
		/* This subdaemon is found in the standard place. */
		dpath = path_join(ctx, ld->daemon_dir, name);
	}
	return dpath;
}

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
		/*~ CCAN's path module uses tal, so wants a context to
		 * allocate from.  We have a magic convenience context
		 * `tmpctx` for temporary allocations like this.
		 *
		 * Because all our daemons at their core are of form `while
		 * (!stopped) handle_events();` (an event loop pattern), we
		 * can free `tmpctx` in that top-level loop after each event
		 * is handled.
		 */
		int outfd;
		const char *dpath = subdaemon_path(tmpctx, ld, subdaemons[i]);
		const char *verstring;
		/*~ CCAN's pipecmd module is like popen for grownups: it
		 * takes pointers to fill in stdin, stdout and stderr file
		 * descriptors if desired, and the remainder of arguments
		 * are the command and its argument. */
		pid_t pid = pipecmd(NULL, &outfd, &outfd,
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

		/*~ finally reap the child process, freeing all OS
		 *  resources that go with it */
		waitpid(pid, NULL, 0);
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
static const char *find_my_pkglibexec_path(struct lightningd *ld,
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
	pkglibexecdir = path_join(NULL, my_path, BINTOPKGLIBEXECDIR);

	/*~ The plugin dir is in ../libexec/c-lightning/plugins, which (unlike
	 * those given on the command line) does not need to exist. */
	plugins_set_builtin_plugins_dir(ld->plugins,
					path_join(tmpctx,
						  pkglibexecdir, "plugins"));

	/*~ Sometimes take() can be more efficient, since the routine can
	 * manipulate the string in place.  This is the case here. */
	return path_simplify(ld, take(pkglibexecdir));
}

/* Determine the correct daemon dir. */
static const char *find_daemon_dir(struct lightningd *ld, const char *argv0)
{
	const char *my_path = find_my_directory(ld, argv0);
	/* If we're running in-tree, all the subdaemons are with lightningd. */
	if (has_all_subdaemons(my_path)) {
		/* In this case, look for built-in plugins in ../plugins */
		plugins_set_builtin_plugins_dir(ld->plugins,
						path_join(tmpctx,
							  my_path,
							  "../plugins"));
		return my_path;
	}

	/* Otherwise we assume they're in the installed dir. */
	return find_my_pkglibexec_path(ld, take(my_path));
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
	ld->connectd = subd_shutdown(ld->connectd, 10);

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

	/*~ Now they're all dead, we can stop gossipd: doing it before HTLCs is
	 * problematic because local_fail_in_htlc_needs_update() asks gossipd */
	ld->gossip = subd_shutdown(ld->gossip, 10);
	ld->hsm = subd_shutdown(ld->hsm, 10);

	/*~ Commit the transaction.  Note that the db is actually
	 * single-threaded, so commits never fail and we don't need
	 * spin-and-retry logic everywhere. */
	db_commit_transaction(ld->wallet->db);
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
	for (u64 i = 0; i <= bip32_max_index + w->keyscan_gap; i++) {
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
 * make sure we stay there.  The rest of this is taken from ccan/daemonize,
 * which was based on W. Richard Steven's advice in Programming in The Unix
 * Environment.
 */
static void complete_daemonize(struct lightningd *ld)
{
	int ok_status = 0;

	/* Don't hold files open. */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Many routines write to stderr; that can cause chaos if used
	 * for something else, so set it here. */
	if (open("/dev/null", O_WRONLY) != 0)
		fatal("Could not open /dev/null: %s", strerror(errno));
	if (dup2(0, STDERR_FILENO) != STDERR_FILENO)
		fatal("Could not dup /dev/null for stderr: %s", strerror(errno));
	close(0);

	/* Session leader so ^C doesn't whack us. */
	if (setsid() == (pid_t)-1)
		fatal("Could not setsid: %s", strerror(errno));

	/* Discard our parent's old-fashioned umask prejudices. */
	ld->initial_umask = umask(0);

	/* OK, parent, you can exit(0) now. */
	write_all(ld->daemon_parent_fd, &ok_status, sizeof(ok_status));
	close(ld->daemon_parent_fd);
}

/*~ It's pretty standard behaviour (especially for daemons) to create and
 * file-lock a pidfile.  This not only prevents accidentally running multiple
 * daemons on the same database at once, but lets nosy sysadmins see what pid
 * the currently-running daemon is supposed to be. */
static void pidfile_create(const struct lightningd *ld)
{
	int pid_fd;
	char *pid;

	/* Create PID file: relative to .config dir. */
	pid_fd = open(ld->pidfile, O_WRONLY|O_CREAT, 0640);
	if (pid_fd < 0)
		err(1, "Failed to open PID file");

	/* Lock PID file, so future lockf will fail. */
	if (lockf(pid_fd, F_TLOCK, 0) < 0)
		/* Problem locking file */
		err(1, "lightningd already running? Error locking PID file");

	/*~ As closing the file will remove the lock, we need to keep it open;
	 * the OS will close it implicitly when we exit for any reason. */

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
	/* These checks and freeing tmpctx are common to all daemons. */
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
	gossip_notify_new_block(ld, block_height);
	waitblockheight_notify_new_block(ld, block_height);
}

static void on_sigint(int _ UNUSED)
{
        static const char *msg = "lightningd: SIGINT caught, exiting.\n";
        write_all(STDERR_FILENO, msg, strlen(msg));
        _exit(1);
}

static void on_sigterm(int _ UNUSED)
{
        static const char *msg = "lightningd: SIGTERM caught, exiting.\n";
        write_all(STDERR_FILENO, msg, strlen(msg));
        _exit(1);
}

/*~ We only need to handle SIGTERM and SIGINT for the case we are PID 1 of
 * docker container since Linux makes special this PID and requires that
 * some handler exist. */
static void setup_sig_handlers(void)
{
	struct sigaction sigint, sigterm;
	memset(&sigint, 0, sizeof(struct sigaction));
	memset(&sigterm, 0, sizeof(struct sigaction));

	sigint.sa_handler = on_sigint;
	sigterm.sa_handler = on_sigterm;

	if (1 == getpid()) {
		sigaction(SIGINT, &sigint, NULL);
		sigaction(SIGTERM, &sigterm, NULL);
	}
}

/*~ We actually keep more than one set of features, used in different
 * contexts.  common/features.c knows how each standard feature is
 * presented, so we have it generate the set for each one at a time, and
 * combine them.
 *
 * This is inefficient, but the primitives are useful for adding single
 * features later, or adding them when supplied by plugins. */
static struct feature_set *default_features(const tal_t *ctx)
{
	struct feature_set *ret = NULL;
	static const u32 features[] = {
		OPTIONAL_FEATURE(OPT_DATA_LOSS_PROTECT),
		OPTIONAL_FEATURE(OPT_UPFRONT_SHUTDOWN_SCRIPT),
		OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES),
		OPTIONAL_FEATURE(OPT_VAR_ONION),
		OPTIONAL_FEATURE(OPT_PAYMENT_SECRET),
		OPTIONAL_FEATURE(OPT_BASIC_MPP),
		OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES_EX),
		OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY),
#if EXPERIMENTAL_FEATURES
		OPTIONAL_FEATURE(OPT_ANCHOR_OUTPUTS),
		OPTIONAL_FEATURE(OPT_ONION_MESSAGES),
#endif
	};

	for (size_t i = 0; i < ARRAY_SIZE(features); i++) {
		struct feature_set *f
			= feature_set_for_feature(NULL, features[i]);
		if (!ret)
			ret = tal_steal(ctx, f);
		else
			feature_set_or(ret, take(f));
	}

	return ret;
}

/*~ We need this function style to hand to ecdh_hsmd_setup, but it's just a thin
 * wrapper around fatal() */
static void hsm_ecdh_failed(enum status_failreason fail,
			    const char *fmt, ...)
{
	fatal("hsm failure: %s", fmt);
}

/*~ This signals to the mainloop that some part wants to cleanly exit now.  */
void lightningd_exit(struct lightningd *ld, int exit_code)
{
	ld->exit_code = tal(ld, int);
	*ld->exit_code = exit_code;
	io_break(ld);
}

int main(int argc, char *argv[])
{
	struct lightningd *ld;
	u32 min_blockheight, max_blockheight;
	int connectd_gossipd_fd;
	int stop_fd;
	struct timers *timers;
	const char *stop_response;
	struct htlc_in_map *unconnected_htlcs_in;
	struct ext_key *bip32_base;
	struct rlimit nofile = {1024, 1024};

	int exit_code = 0;

	/*~ Make sure that we limit ourselves to something reasonable. Modesty
	 *  is a virtue. */
	setrlimit(RLIMIT_NOFILE, &nofile);

	/*~ What happens in strange locales should stay there. */
	setup_locale();

	setup_sig_handlers();

	/*~ This checks that the system-installed libraries (usually
	 * dynamically linked) actually are compatible with the ones we
	 * compiled with.
	 *
	 * The header itself is auto-generated every time the version of the
	 * installed libraries changes, as we had an sqlite3 version update
	 * which broke people, and "make" didn't think there was any work to
	 * do, so rebuilding didn't fix it. */
	check_linked_library_versions();

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
	ld->state = LD_STATE_RUNNING;

	/* Figure out where our daemons are first. */
	ld->daemon_dir = find_daemon_dir(ld, argv[0]);
	if (!ld->daemon_dir)
		errx(1, "Could not find daemons");

	/* Set up the feature bits for what we support */
	ld->our_features = default_features(ld);

	/*~ Handle early options; this moves us into --lightning-dir.
	 * Plugins may add new options, which is why we are splitting
	 * between early args (including --plugin registration) and
	 * non-early opts.  This also forks if they say --daemon. */
	handle_early_opts(ld, argc, argv);

	/*~ Initialize all the plugins we just registered, so they can
	 *  do their thing and tell us about themselves (including
	 *  options registration). */
	plugins_init(ld->plugins);

	/*~ Handle options and config. */
	handle_opts(ld, argc, argv);

	/*~ Now create the PID file: this errors out if there's already a
	 * daemon running, so we call before doing almost anything else. */
	pidfile_create(ld);

	/*~ Make sure we can reach the subdaemons, and versions match.
	 * This can be turned off in DEVELOPER builds with --dev-skip-version-checks,
	 * but the `dev_no_version_checks` field of `ld` doesn't even exist
	 * if DEVELOPER isn't defined, so we use IFDEV(devoption,non-devoption):
	 */
	if (IFDEV(!ld->dev_no_version_checks, 1))
		test_subdaemons(ld);

	/*~ Set up the HSM daemon, which knows our node secret key, so tells
	 *  us who we are.
	 *
	 * HSM stands for Hardware Security Module, which is the industry
	 * standard of key storage; ours is in software for now, so the name
	 * doesn't really make sense, but we can't call it the Badly-named
	 * Daemon Software Module. */
	bip32_base = hsm_init(ld);

	/*~ Our "wallet" code really wraps the db, which is more than a simple
	 * bitcoin wallet (though it's that too).  It also stores channel
	 * states, invoices, payments, blocks and bitcoin transactions. */
	ld->wallet = wallet_new(ld, ld->timers, bip32_base);

	/*~ We keep track of how many 'coin moves' we've ever made.
	 * Initialize the starting value from the database here. */
	coin_mvts_init_count(ld);

	/*~ We keep a filter of scriptpubkeys we're interested in. */
	ld->owned_txfilter = txfilter_new(ld);

	/*~ This is the ccan/io central poll override from above. */
	io_poll_override(io_poll_lightningd);

	/*~ If hsm_secret is encrypted, we don't need its encryption key
	 * anymore. Note that sodium_munlock() also zeroes the memory.*/
	if (ld->config.keypass)
		sodium_munlock(ld->config.keypass->data, sizeof(ld->config.keypass->data));

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
	if (!wallet_network_check(ld->wallet))
		errx(1, "Wallet network check failed.");

	/*~ Initialize the transaction filter with our pubkeys. */
	init_txfilter(ld->wallet, ld->owned_txfilter);

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
	setup_topology(ld->topology, ld->timers,
		       min_blockheight, max_blockheight);

	db_begin_transaction(ld->wallet->db);
	/*~ Tell the wallet to start figuring out what to do for any reserved
	 * unspent outputs we may have crashed with. */
	wallet_clean_utxos(ld->wallet, ld->topology->bitcoind);

	/*~ Pull peers, channels and HTLCs from db. Needs to happen after the
	 *  topology is initialized since some decisions rely on being able to
	 *  know the blockheight. */
	unconnected_htlcs_in = load_channels_from_wallet(ld);
	db_commit_transaction(ld->wallet->db);

	/*~ Create RPC socket: now lightning-cli can send us JSON RPC commands
	 *  over a UNIX domain socket specified by `ld->rpc_filename`. */
	jsonrpc_listen(ld->jsonrpc, ld);

	/*~ Now that the rpc path exists, we can start the plugins and they
	 * can start talking to us. */
	plugins_config(ld->plugins);

	/*~ Process any HTLCs we were in the middle of when we exited, now
	 * that plugins (who might want to know via htlc_accepted hook) are
	 * active.  These will immediately fail, since no peers are connected,
	 * however partial payments may still be absorbed into htlc_set. */
	db_begin_transaction(ld->wallet->db);
	htlcs_resubmit(ld, unconnected_htlcs_in);
	db_commit_transaction(ld->wallet->db);

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
	log_info(ld->log, "--------------------------------------------------");
	log_info(ld->log, "Server started with public key %s, alias %s (color #%s) and lightningd %s",
		 type_to_string(tmpctx, struct node_id, &ld->id),
		 json_escape(tmpctx, (const char *)ld->alias)->s,
		 tal_hex(tmpctx, ld->rgb), version());

	/*~ This is where we ask connectd to reconnect to any peers who have
	 * live channels with us, and makes sure we're watching the funding
	 * tx. */
	activate_peers(ld);

	/*~ Now that all the notifications for transactions are in place, we
	 *  can start the poll loop which queries bitcoind for new blocks. */
	begin_topology(ld->topology);

	/*~ To handle --daemon, we fork the daemon early (otherwise we hit
	 * issues with our pid changing), but keep the parent around until
	 * we've completed most initialization: that way we'll exit with an
	 * error rather than silently exiting 0, then realizing we can't start
	 * and forcing the confused user to read the logs.
	 *
	 * But we're all initialized, so detach and have parent exit now. */
	if (ld->daemon_parent_fd != -1)
		complete_daemonize(ld);

	/*~ Setting this (global) activates the crash log: we don't usually need
	 * a backtrace if we fail during startup. */
	crashlog = ld->log;

	/*~ This sets up the ecdh() function in ecdh_hsmd to talk to hsmd */
	ecdh_hsmd_setup(ld->hsm_fd, hsm_ecdh_failed);

	/*~ The root of every backtrace (almost).  This is our main event
	 *  loop. */
	void *io_loop_ret = io_loop_with_timers(ld);
	/*~ io_loop_with_timers will only exit if we call io_break.
	 *  At this point in code, we should use io_break(ld) to
	 *  shut down.
	 */
	assert(io_loop_ret == ld);
	ld->state = LD_STATE_SHUTDOWN;

	/* Were we exited via `lightningd_exit`?  */
	if (ld->exit_code) {
		exit_code = *ld->exit_code;
		stop_fd = -1;
		stop_response = NULL;
	} else {
		/* Keep this fd around, to write final response at the end. */
		stop_fd = io_conn_fd(ld->stop_conn);
		io_close_taken_fd(ld->stop_conn);
		stop_response = tal_steal(NULL, ld->stop_response);
	}

	shutdown_subdaemons(ld);

	/* Remove plugins. */
	plugins_free(ld->plugins);

	/* Clean up the JSON-RPC. This needs to happen in a DB transaction since
	 * it might actually be touching the DB in some destructors, e.g.,
	 * unreserving UTXOs (see #1737) */
	db_begin_transaction(ld->wallet->db);
	tal_free(ld->jsonrpc);
	free_unreleased_txs(ld->wallet);
	db_commit_transaction(ld->wallet->db);

	/* Clean our our HTLC maps, since they use malloc. */
	htlc_in_map_clear(&ld->htlcs_in);
	htlc_out_map_clear(&ld->htlcs_out);

	remove(ld->pidfile);

	/* FIXME: pay can have children off tmpctx which unlink from
	 * ld->payments, so clean that up. */
	clean_tmpctx();

	/* Free this last: other things may clean up timers. */
	timers = tal_steal(NULL, ld->timers);
	tal_free(ld);

	timers_cleanup(timers);
	tal_free(timers);
	opt_free_table();

	daemon_shutdown();

	/* Finally, send response to shutdown command if appropriate.  */
	if (stop_fd >= 0) {
		write_all(stop_fd, stop_response, strlen(stop_response));
		close(stop_fd);
		tal_free(stop_response);
	}

	/*~ Farewell.  Next stop: hsmd/hsmd.c. */
	return exit_code;
}

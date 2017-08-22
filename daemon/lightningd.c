#include "bitcoind.h"
#include "chaintopology.h"
#include "db.h"
#include "invoice.h"
#include "irc_announce.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "options.h"
#include "p2p_announce.h"
#include "peer.h"
#include "routing.h"
#include "secrets.h"
#include "timeout.h"
#include "utils.h"
#include <bitcoin/chainparams.h>
#include <ccan/container_of/container_of.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <version.h>

static struct lightningd_state *lightningd_state(void)
{
	struct lightningd_state *dstate = tal(NULL, struct lightningd_state);
	struct sha256_double unused;

	dstate->log_book = new_log_book(dstate, 20*1024*1024, LOG_INFORM);
	dstate->base_log = new_log(dstate, dstate->log_book,
				   "lightningd(%u):", (int)getpid());

	list_head_init(&dstate->peers);
	list_head_init(&dstate->pay_commands);
	dstate->portnum = 0;
	dstate->testnet = true;
	timers_init(&dstate->timers, time_mono());
	list_head_init(&dstate->wallet);
	list_head_init(&dstate->addresses);
	dstate->dev_never_routefail = false;
	dstate->rstate = new_routing_state(dstate, dstate->base_log, &unused);
	dstate->reexec = NULL;
	dstate->external_ip = NULL;
	dstate->announce = NULL;
	dstate->invoices = invoices_init(dstate);
	return dstate;
}

static void json_lightningd_dev_broadcast(struct command *cmd,
					  const char *buffer,
					  const jsmntok_t *params)
{
	json_dev_broadcast(cmd, cmd->dstate->topology, buffer, params);
}

static const struct json_command dev_broadcast_command = {
	"dev-broadcast",
	json_lightningd_dev_broadcast,
	"Pretend we broadcast txs, but don't send to bitcoind",
	"Returns an empty result on success (waits for flush if enabled)"
};
AUTODATA(json_command, &dev_broadcast_command);

int main(int argc, char *argv[])
{
	struct lightningd_state *dstate = lightningd_state();

	err_set_progname(argv[0]);

	if (!streq(protobuf_c_version(), PROTOBUF_C_VERSION))
		errx(1, "Compiled against protobuf %s, but have %s",
		     PROTOBUF_C_VERSION, protobuf_c_version());

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	dstate->topology = new_topology(dstate, dstate->base_log);
	dstate->bitcoind = new_bitcoind(dstate, dstate->base_log);
	dstate->bitcoind->chainparams = chainparams_for_network("regtest");

	/* Handle options and config; move to .lightningd */
	register_opts(dstate);
	handle_opts(dstate, argc, argv);

	/* Now we can set chain_hash properly. */ 
	dstate->rstate->chain_hash
		= dstate->bitcoind->chainparams->genesis_blockhash;

	/* Activate crash log now we're in the right place. */
	crashlog_activate(dstate->base_log);

	/* Ignore SIGPIPE: we look at our write return values*/
	signal(SIGPIPE, SIG_IGN);

	/* Set up node ID and private key. */
	secrets_init(dstate);
	new_node(dstate->rstate, &dstate->id);

	/* Read or create database. */
	db_init(dstate);

	/* Initialize block topology. */
	setup_topology(dstate->topology, dstate->bitcoind, &dstate->timers,
		       dstate->config.poll_time,
		       get_peer_min_block(dstate));

	/* Create RPC socket (if any) */
	setup_jsonrpc(dstate, dstate->rpc_filename);

	/* Set up connections from peers (if dstate->portnum is set) */
	setup_listeners(dstate);

	/* set up IRC peer discovery */
	if (dstate->config.use_irc)
		setup_irc_connection(dstate);

	/* set up P2P gossip protocol */
	setup_p2p_announce(dstate);

	log_info(dstate->base_log, "Hello world!");

	/* If we loaded peers from database, reconnect now. */
	reconnect_peers(dstate);

	/* And send out anchors again if we're waiting. */
	rebroadcast_anchors(dstate);

	for (;;) {
		struct timer *expired;
		void *v = io_loop(&dstate->timers, &expired);

		/* We use io_break(dstate) to shut down. */
		if (v == dstate)
			break;

		if (expired)
			timer_expired(dstate, expired);
		else
			cleanup_peers(dstate);
	}

	if (dstate->reexec) {
		int fd;

		log_unusual(dstate->base_log, "Restart at user request");
		fflush(stdout);
		fflush(stderr);

		/* Manually close all fds (or near enough!) */
		for (fd = 3; fd < 1024; fd++)
			close(fd);

		if (dstate->dev_never_routefail) {
			size_t n = tal_count(dstate->reexec);
			tal_resizez(&dstate->reexec, n+1);
			dstate->reexec[n-1] = "--dev-no-routefail";
		}
		execvp(dstate->reexec[0], dstate->reexec);
		fatal("Exec '%s' failed: %s",
		      dstate->reexec[0], strerror(errno));
	}

	tal_free(dstate);
	opt_free_table();
	return 0;
}

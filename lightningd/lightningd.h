#ifndef LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#define LIGHTNING_LIGHTNINGD_LIGHTNINGD_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/container_of/container_of.h>
#include <daemon/lightningd.h>
#include <lightningd/htlc_end.h>
#include <wallet/wallet.h>

/* BOLT #1:
 *
 * The default TCP port is 9735. This corresponds to hexadecimal
 * `0x2607`, the Unicode code point for LIGHTNING.
 */
#define DEFAULT_PORT 0x2607

/* FIXME: This is two structures, during the migration from old setup to new */
struct lightningd {
	/* Must be first, since things assume we can tal() off it */
	struct lightningd_state dstate;

	/* The directory to find all the subdaemons. */
	const char *daemon_dir;

	/* Log for general stuff. */
	struct log *log;

	/* Bearer of all my secrets. */
	int hsm_fd;

	/* Daemon looking after peers during init / before channel. */
	struct subd *gossip;

	/* All peers we're tracking. */
	struct list_head peers;
	/* FIXME: This should stay in HSM */
	struct secret peer_seed;
	/* Used to give a unique seed to every peer. */
	u64 peer_counter;

	/* Public base for bip32 keys, and max we've ever used. */
	struct ext_key *bip32_base;

	/* Our bitcoind context. */
	struct bitcoind *bitcoind;

	/* Our chain topology. */
	struct chain_topology *topology;

	/* If we want to debug a subdaemon. */
	const char *dev_debug_subdaemon;

	/* If we have a --dev-disconnect file */
	int dev_disconnect_fd;

	/* HTLCs in flight. */
	struct htlc_in_map htlcs_in;
	struct htlc_out_map htlcs_out;

	u32 broadcast_interval;

	struct wallet *wallet;
};

void derive_peer_seed(struct lightningd *ld, struct privkey *peer_seed,
		      const struct pubkey *peer_id);
struct peer *find_peer_by_unique_id(struct lightningd *ld, u64 unique_id);
/* FIXME */
static inline struct lightningd *
ld_from_dstate(const struct lightningd_state *dstate)
{
	return container_of(dstate, struct lightningd, dstate);
}
#endif /* LIGHTNING_LIGHTNINGD_LIGHTNINGD_H */

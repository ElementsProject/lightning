#ifndef LIGHTNING_PLUGINS_SPENDER_SPLICE_H
#define LIGHTNING_PLUGINS_SPENDER_SPLICE_H
#include "config.h"

#include <common/amount.h>
#include <plugins/libplugin.h>

extern const struct plugin_command splice_commands[];
extern const size_t num_splice_commands;

/* Call once at plugin init */
void splice_plugin_init(void);

enum splice_cmd_state {
	SPLICE_CMD_NONE = 0,
	SPLICE_CMD_INIT,
	SPLICE_CMD_UPDATE,
	SPLICE_CMD_UPDATE_NEEDS_CHANGES,
	SPLICE_CMD_UPDATE_DONE,
	SPLICE_CMD_RECVED_SIGS,
	SPLICE_CMD_PENDING,
	SPLICE_CMD_DONE,
};

struct splice_cmd_action_state {
	enum splice_cmd_state state;
	/* Node view of this action's negotiation (channel/peer actions
	 * only): the psbt as that negotiation last saw it, in its own
	 * serial space (this peer's contributions keep their odd
	 * serials; other peers' are masked even on the parent). */
	struct wally_psbt *psbt;
	/* Even serials the daemon minted at *_init which must be copied
	 * onto the parent verbatim: a splice leg's old-funding input,
	 * and every leg's new funding output. */
	u64 *preserve_in_serials;
	u64 *preserve_out_serials;
	/* Open legs: peer's tx_signatures have been combined into the
	 * parent psbt */
	bool peer_sigs_received;
};

struct splice_cmd {
	/* The plugin-level command.  */
	struct command *cmd;
	/* In the active splice command registry (for routing
	 * openchannel_peer_sigs notifications) */
	struct list_node list;
	/* Script input by user */
	const char *script;
	/* The result of parsing the script or json */
	struct splice_script_result **actions;
	/* The states of actions at the same index */
	struct splice_cmd_action_state **states;
	/* The parent psbt: union of all negotiations, with every peer
	 * contribution's serial even-pair normalized (see
	 * plugins/spender/psbt_multiview.h) */
	struct wally_psbt *psbt;
	/* Parked in continue_splice until a peer's tx_signatures
	 * arrive via openchannel_peer_sigs */
	bool waiting_peer_sigs;
	/* Output result but don't do any action */
	bool dryrun;
	/* Execute the splice and abort at the last moment */
	bool wetrun;
	/* Feerate provided, otherwise queried from lightningd */
	u32 feerate_per_kw;
	/* Override max feerate */
	bool force_feerate;
	/* How many wallet inputs have we added to the psbt */
	int wallet_inputs_to_signed;
	/* Final result */
	struct bitcoin_txid final_txid;
	/* Has the fee been calculated yet */
	bool fee_calculated;
	/* The amount of sats provided by the user in the inital psbt */
	struct amount_sat initial_funds;
	/* The minimum sats that must go back into the wallet */
	struct amount_sat emergency_sat;
	/* A verbose debug log of all the splice states */
	char *debug_log;
	/* Counter used for more readable debug logs */
	int debug_counter;
	/* Remaining funds needed from wallet */
	struct amount_sat needed_funds;
};

#endif /* LIGHTNING_PLUGINS_SPENDER_SPLICE_H */

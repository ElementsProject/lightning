#ifndef LIGHTNING_PLUGINS_SPENDER_SPLICE_H
#define LIGHTNING_PLUGINS_SPENDER_SPLICE_H
#include "config.h"

#include <plugins/libplugin.h>

extern const struct plugin_command splice_commands[];
extern const size_t num_splice_commands;

enum splice_cmd_state {
	SPLICE_CMD_NONE = 0,
	SPLICE_CMD_INIT,
	SPLICE_CMD_UPDATE,
	SPLICE_CMD_UPDATE_NEEDS_CHANGES,
	SPLICE_CMD_UPDATE_DONE,
	SPLICE_CMD_RECVED_SIGS,
	SPLICE_CMD_DONE,
};

struct splice_cmd_action_state {
	enum splice_cmd_state state;
};

struct splice_cmd {
	/* The plugin-level command.  */
	struct command *cmd;
	/* Script input by user */
	const char *script;
	/* The result of parsing the script or json */
	struct splice_script_result **actions;
	/* The states of actions at the same index */
	struct splice_cmd_action_state **states;
	/* The active psbt */
	struct wally_psbt *psbt;
	/* Output result but don't do any action */
	bool dryrun;
	/* Execute the splice and abort at the last moment */
	bool wetrun;
	/* Feerate queried from lightningd */
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
};

#endif /* LIGHTNING_PLUGINS_SPENDER_SPLICE_H */

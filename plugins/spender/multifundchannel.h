#ifndef LIGHTNING_PLUGINS_SPENDER_MULTIFUNDCHANNEL_H
#define LIGHTNING_PLUGINS_SPENDER_MULTIFUNDCHANNEL_H
#include "config.h"

#include <ccan/ccan/list/list.h>
#include <common/channel_id.h>
#include <plugins/libplugin.h>

extern const struct plugin_command multifundchannel_commands[];
extern const size_t num_multifundchannel_commands;

/* Which protocol this channel open is using.
 * OPEN_CHANNEL implies opt_dual_fund  */
enum channel_protocol {
	FUND_CHANNEL,
	OPEN_CHANNEL,
};

/* Current state of the funding process.  */
enum multifundchannel_state {
	/* We have not yet performed `fundchannel_start`.  */
	MULTIFUNDCHANNEL_START_NOT_YET = 0,
	/* The `connect` command succeeded.  `*/
	MULTIFUNDCHANNEL_CONNECTED,

	/* The `fundchannel_start` or `openchannel_init` command
	 * succeeded.  */
	MULTIFUNDCHANNEL_STARTED,

	/* V1 states */
	/* The `fundchannel_complete` command succeeded.  */
	MULTIFUNDCHANNEL_COMPLETED,

	/* V2 states */
	/* The `openchannel_update` command succeeded.  */
	MULTIFUNDCHANNEL_UPDATED,
	/* The commitments for this destinations have been secured */
	MULTIFUNDCHANNEL_SECURED,
	/* We've recieved the peer sigs for this destination */
	MULTIFUNDCHANNEL_SIGNED,
	/* We've gotten their sigs, but still waiting for their commit sigs */
	MULTIFUNDCHANNEL_SIGNED_NOT_SECURED,

	/* The transaction might now be broadcasted.  */
	MULTIFUNDCHANNEL_DONE,
	/* Global fail state. Oops */
	MULTIFUNDCHANNEL_FAILED,
};

/* Stores a destination that was removed due to some failure.  */
struct multifundchannel_removed {
	/* The destination we removed.  */
	struct node_id id;
	/* The method that failed:
	connect, fundchannel_start, fundchannel_complete.
	*/
	const char *method;
	const char *error_message;
	errcode_t error_code;
	/* Optional JSON object containing extra data */
	const char *error_data;
};

/* the object for a single destination.  */
struct multifundchannel_destination {
	/* the overall multifundchannel command object.  */
	struct multifundchannel_command *mfc;

	/* the overall multifundchannel_command contains an
	array of multifundchannel_destinations.
	this provides the index within the array.

	this is used in debug printing.
	*/
	unsigned int index;

	/* id for this destination.  */
	struct node_id id;
	/* address hint for this destination, null if not
	specified.
	*/
	const char *addrhint;
	/* the features this destination has.  */
	const u8 *their_features;

	/* whether we have `fundchannel_start`, failed `connect` or
	`fundchannel_complete`, etc.
	*/
	enum multifundchannel_state state;

	/* Last known state before failure */
	enum multifundchannel_state fail_state;

	/* the actual target script and address.  */
	const u8 *funding_script;
	const char *funding_addr;

	/* the upfront shutdown script for this channel */
	const char *close_to_str;

	/* The scriptpubkey we will close to. Only set if
	 * peer supports opt_upfront_shutdownscript and
	 * we passsed in a valid close_to_str */
	const u8 *close_to_script;

	/* the amount to be funded for this destination.
	if the specified amount is "all" then the `all`
	flag is set, and the amount is initially 0 until
	we have figured out how much exactly "all" is,
	after the dryrun stage.
	*/
	bool all;
	struct amount_sat amount;

	/* the output index for this destination.  */
	unsigned int outnum;

	/* whether the channel to this destination will
	be announced.
	*/
	bool announce;
	/* how much of the initial funding to push to
	the destination.
	*/
	struct amount_msat push_msat;

	/* the actual channel_id.  */
	struct channel_id channel_id;

	const char *error_message;
	errcode_t error_code;
	/* Optional JSON object containing extra data */
	const char *error_data;

	/* what channel protocol this destination is using */
	enum channel_protocol protocol;

	/* PSBT for the inflight channel open (OPEN_CHANNEL) */
	struct wally_psbt *psbt;

	/* PSBT for the inflight channel open, updated (OPEN_CHANNEL) */
	struct wally_psbt *updated_psbt;

	/* serial of the funding output for this channel (OPEN_CHANNEL) */
	u64 funding_serial;

	/* amount to request peer to lease (OPEN_CHANNEL) */
	struct amount_sat request_amt;

	/* Channel lease rates that we expect the peer to respond with */
	struct lease_rates *rates;
};


/* The object for a single multifundchannel command.  */
struct multifundchannel_command {
	/* A unique numeric identifier for this particular
	multifundchannel execution.

	This is used for debug logs; we want to be able to
	identify *which* multifundchannel is being described
	in the debug logs, especially if the user runs
	multiple `multifundchannel` commands in parallel, or
	in very close sequence, which might confuse us with
	*which* debug message belongs with *which* command.

	We actually just reuse the id from the cmd.
	Store it here for easier access.
	*/
	u64 id;

	/* The plugin-level command.  */
	struct command *cmd;
	/* An array of destinations.  */
	struct multifundchannel_destination *destinations;
	/* Number of pending parallel fundchannel_start or
	fundchannel_complete.
	*/
	size_t pending;

	/* The feerate desired by the user.  */
	const char *feerate_str;

	/* If specified, the feerate to be used for channel commitment
	 * transactions. Defaults to the `feerate_str` if not provided. */
	const char *cmtmt_feerate_str;

	/* The minimum number of confirmations for owned
	UTXOs to be selected.
	*/
	u32 minconf;
	/* The set of utxos to be used.  */
	const char *utxos_str;
	/* How long should we keep going if things fail. */
	size_t minchannels;
	/* Array of destinations that were removed in a best-effort
	attempt to fund as many channels as possible.
	*/
	struct multifundchannel_removed *removeds;

	/* The PSBT of the funding transaction we are building.
	Prior to `fundchannel_start` completing for all destinations,
	this contains an unsigned incomplete transaction that is just a
	reservation of the inputs.
	After `fundchannel_start`, this contains an unsigned transaction
	with complete outputs.
	After `fundchannel_complete`, this contains a signed, finalized
	transaction.
	*/
	struct wally_psbt *psbt;
	/* The actual feerate of the PSBT.  */
	u32 feerate_per_kw;
	/* The expected weight of the PSBT after adding in all the outputs.
	 * In weight units (sipa).  */
	u32 estimated_final_weight;
	/* Excess satoshi from the PSBT.
	 * If "all" this is the entire amount; if not "all" this is the
	 * proposed change amount, which if dusty should be donated to
	 * the miners.
	 */
	struct amount_sat excess_sat;

	/* A convenient change address. NULL at the start, filled in
	 * if we detect we need it.  */
	const u8 *change_scriptpubkey;
	/* Whether we need a change output.  */
	bool change_needed;
	/* The change amount.  */
	struct amount_sat change_amount;

	/* The txid of the final funding transaction.  */
	struct bitcoin_txid *txid;

	/* The actual tx of the actual final funding transaction
	that was broadcast.
	*/
	const char *final_tx;
	const char *final_txid;

	/* V2 things */
	struct list_node list;

	/* V2 channel opens use this flag to gate PSBT signing */
	bool sigs_collected;
};

/* Use this instead of forward_error.  */
struct command_result *
mfc_forward_error(struct command *cmd,
		  const char *buf, const jsmntok_t *error,
		  struct multifundchannel_command *);

/* When a destination fails, record the furthest state reached, and the
 * error message for the failure */
void fail_destination_tok(struct multifundchannel_destination *dest,
			  const char *buf,
			  const jsmntok_t *error);
void fail_destination_msg(struct multifundchannel_destination *dest,
			  int error_code,
			  const char *err_str TAKES);

/* dest_count - Returns count of destinations using given protocol version */
size_t dest_count(const struct multifundchannel_command *mfc,
		  enum channel_protocol);

/* Is this destination using the v2/OPEN_CHANNEL protocol? */
bool is_v2(const struct multifundchannel_destination *dest);

/* Use this instead of command_finished.  */
struct command_result *
mfc_finished(struct multifundchannel_command *, struct json_stream *response);

struct command_result *
after_channel_start(struct multifundchannel_command *mfc);

struct command_result *
perform_fundchannel_complete(struct multifundchannel_command *mfc);

struct command_result *
perform_signpsbt(struct multifundchannel_command *mfc);

struct command_result *
multifundchannel_finished(struct multifundchannel_command *mfc);

struct command_result *
redo_multifundchannel(struct multifundchannel_command *mfc,
		      const char *failing_method,
		      const char *why);
#endif /* LIGHTNING_PLUGINS_SPENDER_MULTIFUNDCHANNEL_H */

#ifndef LIGHTNING_COMMON_PSBT_OPEN_H
#define LIGHTNING_COMMON_PSBT_OPEN_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>
#include <stdbool.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

struct channel_id;
struct wally_tx_input;
struct wally_tx_output;
struct wally_psbt;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_map;
struct witness_element;

struct input_set {
	struct wally_tx_input tx_input;
	struct wally_psbt_input input;
};

struct output_set {
	struct wally_tx_output tx_output;
	struct wally_psbt_output output;
};

struct psbt_changeset {
	struct input_set *added_ins;
	struct input_set *rm_ins;
	struct output_set *added_outs;
	struct output_set *rm_outs;
};

#define PSBT_TYPE_SERIAL_ID 0x01
#define PSBT_TYPE_MAX_WITNESS_LEN 0x02

/* psbt_get_serial_id - Returns the serial_id from an unknowns map
 *
 * @map - the map to find the serial id entry within
 * @serial_id - found serial_id
 *
 * Returns false if serial_id is not present
 */
WARN_UNUSED_RESULT bool psbt_get_serial_id(const struct wally_map *map,
					   u16 *serial_id);

/* psbt_sort_by_serial_id - Sort PSBT by serial_ids
 *
 * MUST have a serial_id on every input/output.
 *
 * @psbt - psbt to sort
 */
void psbt_sort_by_serial_id(struct wally_psbt *psbt);

/* psbt_get_changeset - Returns set of diffs btw orig + new psbt
 *
 * All inputs+outputs MUST have a serial_id field present before
 * calling this.
 *
 * @ctx - allocation context for returned changeset
 * @orig - original psbt
 * @new - updated psbt
 *
 * Note that the input + output data returned in the changeset
 * contains references to the originating PSBT; they are not copies.
 */
struct psbt_changeset *psbt_get_changeset(const tal_t *ctx,
					  struct wally_psbt *orig,
					  struct wally_psbt *new);

/* psbt_changeset_get_next - Get next message to send
 *
 * This generates the next message to send from a changeset for the
 * interactive transaction protocol.
 *
 * @ctx - allocation context of returned msg
 * @cid - channel_id for the message
 * @set - changeset to get next update from
 *
 * Returns a wire message or NULL if no changes.
 */
u8 *psbt_changeset_get_next(const tal_t *ctx, struct channel_id *cid,
			    struct psbt_changeset *set);

/* psbt_input_set_serial_id - Sets a serial id on given input
 *
 * @ctx - tal context for allocations
 * @input - to set serial_id on
 * @serial_id - to set
 */
void psbt_input_set_serial_id(const tal_t *ctx,
			      struct wally_psbt_input *input,
			       u16 serial_id);
/* psbt_output_set_serial_id - Sets a serial id on given output
 *
 * @ctx - tal context for allocations
 * @output - to set serial_id on
 * @serial_id - to set
 */
void psbt_output_set_serial_id(const tal_t *ctx,
			       struct wally_psbt_output *output,
			       u16 serial_id);

/* psbt_sort_by_serial_id - Sorts the inputs + outputs by serial_id
 *
 * Requires every input/output to have a serial_id entry.
 *
 * @psbt - psbt to sort inputs/outputs
 */
void psbt_sort_by_serial_id(struct wally_psbt *psbt);

/* psbt_find_serial_input - Checks inputs for provided serial_id
 *
 * @psbt - psbt's inputs to check
 * @serial_id - id to look for
 *
 * Returns index of input with matching serial if found or -1
 */
int psbt_find_serial_input(struct wally_psbt *psbt, u16 serial_id);

/* psbt_find_serial_output - Checks outputs for provided serial_id
 *
 * @psbt - psbt's outputs to check
 * @serial_id - id to look for
 *
 * Returns index of output with matching serial if found or -1
 */
int psbt_find_serial_output(struct wally_psbt *psbt, u16 serial_id);

/* psbt_new_input_serial - Generate a new serial for an input for {role}
 *
 * @psbt - psbt to get a new serial for
 * @role - which tx role to generate the serial for
 *
 * Returns a new, unique serial of the correct parity for the specified {role}
 */
u16 psbt_new_input_serial(struct wally_psbt *psbt, enum tx_role role);

/* psbt_new_output_serial - Generate a new serial for an output for {role}
 *
 * @psbt - psbt to get a new serial for
 * @role - which tx role to generate the serial for
 *
 * Returns a new, unique serial of the correct parity for the specified {role}
 */
u16 psbt_new_output_serial(struct wally_psbt *psbt, enum tx_role role);

/* psbt_has_required_fields - Validates psbt field completion
 *
 * Required fields are:
 * - a serial_id; input+output
 * - a prev_tx; input,non_witness_utxo
 * - redeemscript; input,iff is P2SH-P2W*
 * @psbt - psbt to validate
 *
 * Returns true if all required fields are present
 */
bool psbt_has_required_fields(struct wally_psbt *psbt);

/* psbt_input_set_final_witness_stack - Set the witness stack for PSBT input
 *
 * @in - input to set final_witness for
 * @witness_element - elements to add to witness stack
 */
void psbt_input_set_final_witness_stack(struct wally_psbt_input *in,
					const struct witness_element **elements);

/* psbt_to_witness_stacks - Take all sigs on a PSBT and copy to a
 * 			    witness_stack
 *
 * @ctx - allocation context
 * @psbt - PSBT to copy sigs from
 * @opener - which side initiated this tx
 */
const struct witness_stack **
psbt_to_witness_stacks(const tal_t *ctx,
		       const struct wally_psbt *psbt,
		       enum tx_role side_to_stack);

/* psbt_side_finalized - True if designated role has all signature data */
bool psbt_side_finalized(const struct wally_psbt *psbt,
			 enum tx_role role);
#endif /* LIGHTNING_COMMON_PSBT_OPEN_H */

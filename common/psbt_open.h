#ifndef LIGHTNING_COMMON_PSBT_OPEN_H
#define LIGHTNING_COMMON_PSBT_OPEN_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/tx_roles.h>
#include <wally_psbt.h>

struct channel_id;
struct wally_tx_input;
struct wally_tx_output;
struct wally_psbt;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_map;

struct input_set {
	struct wally_tx_input tx_input;
	struct wally_psbt_input input;
	/* index on PSBT of this input */
	size_t idx;
};

struct output_set {
	struct wally_tx_output tx_output;
	struct wally_psbt_output output;
	/* index on PSBT of this output */
	size_t idx;
};

struct psbt_changeset {
	struct input_set *added_ins;
	struct input_set *rm_ins;
	struct output_set *added_outs;
	struct output_set *rm_outs;
};

#define PSBT_TYPE_SERIAL_ID 0x01
#define PSBT_TYPE_INPUT_MARKER 0x02
#define PSBT_TYPE_OUTPUT_EXTERNAL 0x04

/* psbt_get_serial_id - Returns the serial_id from an unknowns map
 *
 * @map - the map to find the serial id entry within
 * @serial_id - found serial_id
 *
 * Returns false if serial_id is not present
 */
WARN_UNUSED_RESULT bool psbt_get_serial_id(const struct wally_map *map,
					   u64 *serial_id);

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

/* psbt_input_set_serial_id - Sets a serial id on given input
 *
 * @ctx - tal context for allocations
 * @input - to set serial_id on
 * @serial_id - to set
 */
void psbt_input_set_serial_id(const tal_t *ctx,
			      struct wally_psbt_input *input,
			       u64 serial_id);
/* psbt_output_set_serial_id - Sets a serial id on given output
 *
 * @ctx - tal context for allocations
 * @output - to set serial_id on
 * @serial_id - to set
 */
void psbt_output_set_serial_id(const tal_t *ctx,
			       struct wally_psbt_output *output,
			       u64 serial_id);

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
int psbt_find_serial_input(struct wally_psbt *psbt, u64 serial_id);

/* psbt_find_serial_output - Checks outputs for provided serial_id
 *
 * @psbt - psbt's outputs to check
 * @serial_id - id to look for
 *
 * Returns index of output with matching serial if found or -1
 */
int psbt_find_serial_output(struct wally_psbt *psbt, u64 serial_id);

/* psbt_new_input_serial - Generate a new serial for an input for {role}
 *
 * @psbt - psbt to get a new serial for
 * @role - which tx role to generate the serial for
 *
 * Returns a new, unique serial of the correct parity for the specified {role}
 */
u64 psbt_new_input_serial(struct wally_psbt *psbt, enum tx_role role);

/* psbt_new_output_serial - Generate a new serial for an output for {role}
 *
 * @psbt - psbt to get a new serial for
 * @role - which tx role to generate the serial for
 *
 * Returns a new, unique serial of the correct parity for the specified {role}
 */
u64 psbt_new_output_serial(struct wally_psbt *psbt, enum tx_role role);

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

/* psbt_side_finalized - True if designated role has all signature data */
bool psbt_side_finalized(const struct wally_psbt *psbt,
			 enum tx_role role);

/* psbt_add_serials - Add serials to inputs/outputs that are missing them
 *
 * Adds a serial of the correct parity for the designated {role} to all
 * inputs and outputs of this PSBT that do not currently have a serial_id
 * set.
 *
 * @psbt - the psbt to add serials to
 * @role - the role we should use to select serial parity
 */
void psbt_add_serials(struct wally_psbt *psbt, enum tx_role role);

/* psbt_input_mark_ours - Sets the PSBT_TYPE_INPUT_MARKER on this input
 */
void psbt_input_mark_ours(const tal_t *ctx,
			  struct wally_psbt_input *input);

/* psbt_input_is_ours  - Returns true if this psbt input has
 * 			 the PSBT_TYPE_INPUT_MARKER set on it.
 */
bool psbt_input_is_ours(const struct wally_psbt_input *input);

/* psbt_has_our_input  - Returns true if this psbt contains
 * 			 any input that is ours
 */
bool psbt_has_our_input(const struct wally_psbt *psbt);

/* psbt_output_mark_external - Marks an output as a deposit to
 * 			       an external address.
 * 			       Used when withdrawing from internal
 * 			       wallet */
void psbt_output_mark_as_external(const tal_t *ctx,
				  struct wally_psbt_output *output);

/* psbt_output_to_external - Is this an output we're paying to an external
 * 			     party? */
bool psbt_output_to_external(const struct wally_psbt_output *output);

/* psbt_contribs_changed - Returns true if the psbt's inputs/outputs
 *                         have changed.
 *
 * @orig - originating psbt
 * @new  - 'updated' psbt, to verify is unchanged
 */
bool psbt_contribs_changed(struct wally_psbt *orig,
			   struct wally_psbt *new);
#endif /* LIGHTNING_COMMON_PSBT_OPEN_H */

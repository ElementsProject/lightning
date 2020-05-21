#ifndef LIGHTNING_BITCOIN_PSBT_H
#define LIGHTNING_BITCOIN_PSBT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stddef.h>

struct wally_tx_input;
struct wally_tx_output;
struct wally_psbt;
struct wally_psbt_input;
struct wally_tx;

void psbt_destroy(struct wally_psbt *psbt);

struct wally_psbt *new_psbt(const tal_t *ctx,
			    const struct wally_tx *wtx);

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
					size_t insert_at);

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at);

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at);

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at);

void towire_psbt(u8 **pptr, const struct wally_psbt *psbt);
struct wally_psbt *fromwire_psbt(const tal_t *ctx,
				 const u8 **curosr, size_t *max);
#endif /* LIGHTNING_BITCOIN_PSBT_H */

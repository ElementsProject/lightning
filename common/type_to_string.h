#ifndef LIGHTNING_COMMON_TYPE_TO_STRING_H
#define LIGHTNING_COMMON_TYPE_TO_STRING_H
#include "config.h"
#include <common/autodata.h>
#include <common/utils.h>

/* This must match the type_to_string_ cases. */
union printable_types {
	const struct pubkey *pubkey;
	const struct node_id *node_id;
	const struct bitcoin_txid *bitcoin_txid;
	const struct bitcoin_blkid *bitcoin_blkid;
	const struct bitcoin_outpoint *bitcoin_outpoint;
	const struct sha256 *sha256;
	const struct sha256_double *sha256_double;
	const struct ripemd160 *ripemd160;
	const struct bitcoin_tx *bitcoin_tx;
	const struct htlc *htlc;
	const struct preimage *preimage;
	const struct channel_oneside *channel_oneside;
	const struct wireaddr *wireaddr;
	const struct wireaddr_internal *wireaddr_internal;
	const secp256k1_pubkey *secp256k1_pubkey;
	const struct channel_id *channel_id;
	const struct short_channel_id *short_channel_id;
	const struct short_channel_id_dir *short_channel_id_dir;
	const struct secret *secret;
	const struct privkey *privkey;
	const secp256k1_ecdsa_signature *secp256k1_ecdsa_signature;
	const struct bitcoin_signature *bitcoin_signature;
	const struct bip340sig *bip340sig;
	const struct channel *channel;
	const struct amount_msat *amount_msat;
	const struct amount_sat *amount_sat;
	const struct fee_states *fee_states;
	const struct height_states *height_states;
	const char *charp_;
	const struct wally_psbt *wally_psbt;
	const struct wally_tx *wally_tx;
};

#define type_to_string(ctx, type, ptr)					\
	type_to_string_((ctx), stringify(type),				\
			((void)sizeof((ptr) == (type *)NULL),		\
			 ((union printable_types)((const type *)ptr))))

const char *type_to_string_(const tal_t *ctx, const char *typename,
			    union printable_types u);

#define REGISTER_TYPE_TO_STRING(typename, fmtfn)			\
	static const char *fmt_##typename##_(const tal_t *ctx,		\
					     union printable_types u)	\
	{								\
		return fmtfn(ctx, u.typename);				\
	}								\
	static struct type_to_string ttos_##typename = {		\
		#typename, fmt_##typename##_				\
	};								\
	AUTODATA(type_to_string, &ttos_##typename)

struct type_to_string {
	const char *typename;
	const char *(*fmt)(const tal_t *ctx, union printable_types u);
};
AUTODATA_TYPE(type_to_string, struct type_to_string);

char *fmt_sha256(const tal_t *ctx, const struct sha256 *sha256);
char *fmt_ripemd160(const tal_t *ctx, const struct ripemd160 *ripemd160);

#endif /* LIGHTNING_COMMON_TYPE_TO_STRING_H */

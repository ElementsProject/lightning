#ifndef LIGHTNING_DEVTOOLS_PRINT_WIRE_H
#define LIGHTNING_DEVTOOLS_PRINT_WIRE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/tx.h>
#include <common/wireaddr.h>
#include <wire/peer_wire.h>
#include <wire/onion_wire.h>

struct tlv_print_record_type {
	u64 type;
	void (*print)(const char *tlv_name, const u8 **cursor, size_t *plen);
};

typedef u64 bigsize;
#define printwire_bigsize printwire_u64

void printwire_u8(const char *fieldname, const u8 *v);
void printwire_u16(const char *fieldname, const u16 *v);
void printwire_u32(const char *fieldname, const u32 *v);
void printwire_u64(const char *fieldname, const u64 *v);
void printwire_u8_array(const char *fieldname, const u8 **cursor, size_t *plen, size_t len);
void printwire_tlvs(const char *tlv_name, const u8 **cursor, size_t *plen,
		    const struct tlv_print_record_type types[], size_t num_types);

void printwire_bitcoin_blkid(const char *fieldname, const struct bitcoin_blkid *bitcoin_blkid);
void printwire_bitcoin_txid(const char *fieldname, const struct bitcoin_txid *bitcoin_txid);
void printwire_channel_id(const char *fieldname, const struct channel_id *channel_id);
void printwire_amount_sat(const char *fieldname, const struct amount_sat *sat);
void printwire_amount_msat(const char *fieldname, const struct amount_msat *msat);
void printwire_preimage(const char *fieldname, const struct preimage *preimage);
void printwire_pubkey(const char *fieldname, const struct pubkey *pubkey);
void printwire_node_id(const char *fieldname, const struct node_id *id);
void printwire_secp256k1_ecdsa_signature(const char *fieldname, const secp256k1_ecdsa_signature *);
void printwire_sha256(const char *fieldname, const struct sha256 *sha256);
void printwire_secret(const char *fieldname, const struct secret *secret);
void printwire_short_channel_id(const char *fieldname, const struct short_channel_id *short_channel_id);

#endif /* LIGHTNING_DEVTOOLS_PRINT_WIRE_H */

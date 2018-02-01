#ifndef LIGHTNING_DEVTOOLS_PRINT_WIRE_H
#define LIGHTNING_DEVTOOLS_PRINT_WIRE_H
#include <bitcoin/preimage.h>
#include <bitcoin/tx.h>
#include <wire/gen_peer_wire.h>

void printwire_u8(const u8 *v);
void printwire_u16(const u16 *v);
void printwire_u32(const u32 *v);
void printwire_u64(const u64 *v);
void printwire_u8_array(const u8 **cursor, size_t *plen, size_t len);

void printwire_bitcoin_blkid(const struct bitcoin_blkid *bitcoin_blkid);
void printwire_bitcoin_txid(const struct bitcoin_txid *bitcoin_txid);
void printwire_channel_id(const struct channel_id *channel_id);
void printwire_preimage(const struct preimage *preimage);
void printwire_pubkey(const struct pubkey *pubkey);
void printwire_secp256k1_ecdsa_signature(const secp256k1_ecdsa_signature *);
void printwire_sha256(const struct sha256 *sha256);
void printwire_short_channel_id(const struct short_channel_id *short_channel_id);

#endif /* LIGHTNING_DEVTOOLS_PRINT_WIRE_H */

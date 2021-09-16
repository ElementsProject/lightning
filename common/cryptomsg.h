#ifndef LIGHTNING_COMMON_CRYPTOMSG_H
#define LIGHTNING_COMMON_CRYPTOMSG_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/crypto_state.h>

/* BOLT #8:
 *
 * ### Receiving and Decrypting Messages
 *
 * In order to decrypt the _next_ message in the network stream, the
 * following steps are completed:
 *
 *  1. Read _exactly_ 18 bytes from the network buffer.
 */
#define CRYPTOMSG_HDR_SIZE 18

/* BOLT #8:
 *
 * 4. Read _exactly_ `l+16` bytes from the network buffer
 */
#define CRYPTOMSG_BODY_OVERHEAD 16

/* Low-level functions for sync comms: doesn't discard unknowns! */
u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg);
bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 hdr[18], u16 *lenp);
u8 *cryptomsg_decrypt_body(const tal_t *ctx,
			   struct crypto_state *cs, const u8 *in);
#endif /* LIGHTNING_COMMON_CRYPTOMSG_H */

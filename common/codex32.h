#ifndef LIGHTNING_COMMON_CODEX32_H
#define LIGHTNING_COMMON_CODEX32_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdio.h>

/* Supported encodings. */
typedef enum {
   CODEX32_ENCODING_SHARE,
   CODEX32_ENCODING_SECRET
} codex32_encoding;

/* Decoded codex32 parts */
struct codex32 {
	const char *hrp;
	uint8_t threshold;
	const char *id;
	const char *share_idx;
	const char *payload;
	const char *checksum;
	bool codexl;
	codex32_encoding type;
};

/** Decode a codex32 or codex32l string
 *
 *  Out: parts:       Pointer to a codex32. Will be
 *                    updated to contain the details extracted from the codex32 string.
 *       fail:        Pointer to a char *, that would be updated with the reason
 * 		      of failure in case this function returns a NULL.
 *  In: input:        Pointer to a null-terminated codex32 string.
 *      Returns Parts to indicate decoding was successful. NULL is returned if decoding failed,
 * 	with appropriate reason in the fail param
 */
struct codex32 *codex32_decode(const tal_t *ctx,
				     const char *codex32str,
				     char **fail);

/** Get hex encoding of the payload.
 *
 *  Out: payload:          Pointer to a u8 array which contains the hex encoding of parts->payload.
 *  In:  parts:        Pointer to a valid struct codex32.
 *       Returns hex encoding of the payload or NULL if it doesn't exists.
 */
const u8 *codex32_decode_payload(const tal_t *ctx,
				 const struct codex32 *parts);

#endif /* LIGHTNING_COMMON_CODEX32_H */
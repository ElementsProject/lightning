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
	/* "ms" */
	const char *hrp;
	/* 0, or 2-9 */
	uint8_t threshold;
	/* Four valid bech32 characters which identify this complete codex32 secret, the last char is null */
	char id[4 + 1];
	/* Valid bech32 character identifying this share of the secret, or `s` for unshared */
	char share_idx;
	/* The actual data payload */
	const u8 *payload;
	/* Is this a share, or a secret? */
	codex32_encoding type;
};

/** Decode a codex32 or codex32l string
 *
 *  Out: parts:       Pointer to a codex32. Will be
 *                    updated to contain the details extracted from the codex32 string.
 *       fail:        Pointer to a char *, that would be updated with the reason
 * 		      of failure in case this function returns a NULL.
 *  In: ctx:          Allocation context for *fail or return.
 *      hrp:          If non-NULL, a hrp which must match.
 *      codex32str:   Pointer to a nul-terminated codex32 string.
 *
 *      Returns Parts to indicate decoding was successful. NULL is returned if decoding failed,
 * 	with appropriate reason in the fail param
 */
struct codex32 *codex32_decode(const tal_t *ctx,
			       const char *hrp,
			       const char *codex32str,
			       char **fail);

/** Encode a seed into codex32 secret format.
 *
 *  In: input:        hrp: 2 character human-readable-prefix
 *                    id: Valid 4 char string identifying the secret
 * 		      threshold: Threshold according to the bip93
 * 		      seed: The secret in u8*
 * 		      seedlen: Length of the seed provided.
 *      Returns a string which contains the seed provided in bip93 format.
 *
 * Returns an error string, or returns NULL and sets @bip93.
 */
const char *codex32_secret_encode(const tal_t *ctx,
				  const char *hrp,
				  const char *id,
				  const u32 threshold,
				  const u8 *seed,
				  size_t seedlen,
				  char **bip93);

#endif /* LIGHTNING_COMMON_CODEX32_H */

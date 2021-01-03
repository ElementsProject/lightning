#ifndef LIGHTNING_COMMON_HSM_ENCRYPTION_H
#define LIGHTNING_COMMON_HSM_ENCRYPTION_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>


/** Derive the hsm_secret encryption key from a passphrase.
 * @pass: the passphrase string.
 * @encryption_key: the output key derived from the passphrase.
 *
 * On success, NULL is returned. On error, a human-readable error is.
 */
char *hsm_secret_encryption_key(const char *pass, struct secret *encryption_key);

/** Unlock and zeroize the encryption key memory after use.
 * @key: the encryption key. If taken, it will be tal_free'd
 */
void discard_key(struct secret *key TAKES);

/** Read hsm_secret encryption pass from stdin, disabling echoing.
 * @reason: if NULL is returned, will point to the human-readable error.
 *
 * Caller must free the string as it does tal-reallocate getline's output.
 */
char *read_stdin_pass(char **reason);

#endif /* LIGHTNING_COMMON_HSM_ENCRYPTION_H */

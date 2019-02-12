#ifndef LIGHTNING_COMMON_DISSECTOR_H
#define LIGHTNING_COMMON_DISSECTOR_H
#include <common/crypto_state.h>

/* Set of utilities for writing out and storing
 * the secret keys that we use to send and receive messages
 * for peers. Meant to be used by a wireshark plugin.
 *
 * Keys are printed at connection establishment time, with
 * each connection keyset getting its own file.
 */
void dissector_init(void);
void dissector_print_keys(const char *our_addr, const char *peer_addr, const struct crypto_state *cs);
void dissector_remove_connection(const char *our_addr, const char *peer_addr);
#endif /* LIGHTNING_COMMON_DISSECTOR_H */

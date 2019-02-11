#ifndef LIGHTNING_COMMON_DISSECTOR_H
#define LIGHTNING_COMMON_DISSECTOR_H

/* Set of utilities for writing out and storing
 * the secret keys that we use to send and receive messages
 * for peers. We keep a map of keys (sening/receiving) for 
 * each peer, and write them out to a log file that the
 * wireshark plugin can read.
 */

void dissector_add_keys(const char *host, const char *sk, const char *rk);
void dissector_update_key(const char *old_key, const char *new_key);
void dissector_delete_host(const char *host);
#endif /* LIGHTNING_COMMON_DISSECTOR_H */

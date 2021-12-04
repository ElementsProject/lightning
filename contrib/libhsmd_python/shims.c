#include <stdlib.h>
#include <stdbool.h>

/* The following functions are for some reason referenced but not
 * included in the library. We provide them with dummy implementations
 * here. */
bool alignment_ok(void *p) { return true; }
void dev_disconnect_init(int fd) {}
void CCAN_CLEAR_MEMORY(void *p, size_t len) { wally_clear(p, len); }

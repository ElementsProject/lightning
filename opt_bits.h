#ifndef LIGHTNING_OPT_BITS_H
#define LIGHTNING_OPT_BITS_H
#include "config.h"
#include <ccan/opt/opt.h>
#include <ccan/short_types/short_types.h>

char *opt_set_bits(const char *arg, u64 *satoshi);
void opt_show_bits(char buf[OPT_SHOW_LEN], const u64 *bits);

#endif /* LIGHTNING_OPT_BITS_H */

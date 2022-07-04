#ifndef CCAN_RUNE_INTERNAL_H
#define CCAN_RUNE_INTERNAL_H
/* MIT (BSD) license - see LICENSE file for details */
void rune_sha256_endmarker(struct sha256_ctx *shactx);
void rune_sha256_add_restr(struct sha256_ctx *shactx,
			struct rune_restr *restr);
bool runestr_eq(const char *a, const char *b);
#endif /* CCAN_RUNE_INTERNAL_H */

#ifndef LIGHTNING_LIGHTNINGD_HTLC_END_H
#define LIGHTNING_LIGHTNINGD_HTLC_END_H
#include "config.h"
#include <ccan/htable/htable_type.h>
#include <ccan/short_types/short_types.h>

/* A HTLC has a source and destination: if other is NULL, it's this node.
 *
 * The main daemon simply shuffles them back and forth.
 */
enum htlc_end_type { HTLC_SRC, HTLC_DST };

struct htlc_end {
	enum htlc_end_type which_end;
	struct peer *peer;
	u64 htlc_id;
	u64 msatoshis;

	struct htlc_end *other_end;
	/* If this is driven by a command. */
	struct pay_command *pay_command;
};

static inline const struct htlc_end *keyof_htlc_end(const struct htlc_end *e)
{
	return e;
}

size_t hash_htlc_end(const struct htlc_end *e);

static inline bool htlc_end_eq(const struct htlc_end *a,
			       const struct htlc_end *b)
{
	return a->peer == b->peer
		&& a->htlc_id == b->htlc_id
		&& a->which_end == b->which_end;
}
HTABLE_DEFINE_TYPE(struct htlc_end, keyof_htlc_end, hash_htlc_end, htlc_end_eq,
		   htlc_end_map);

struct htlc_end *find_htlc_end(const struct htlc_end_map *map,
			       const struct peer *peer,
			       u64 htlc_id,
			       enum htlc_end_type which_end);

void connect_htlc_end(struct htlc_end_map *map, struct htlc_end *hend);
#endif /* LIGHTNING_LIGHTNINGD_HTLC_END_H */

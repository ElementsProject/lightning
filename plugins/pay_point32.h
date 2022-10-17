#ifndef LIGHTNING_PLUGINS_PAY_POINT32_H
#define LIGHTNING_PLUGINS_PAY_POINT32_H

struct gossmap;
struct point32;
struct node_id;

void gossmap_guess_node_id(const struct gossmap *map,
			   const struct point32 *point32,
			   struct node_id *id);

#endif /* LIGHTNING_PLUGINS_PAY_POINT32_H */

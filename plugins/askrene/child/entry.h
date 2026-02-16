#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_ENTRY_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_ENTRY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/fp16.h>
#include <stdbool.h>

struct route_query;
struct gossmap_node;
struct json_filter;
struct layer;
struct reserve_htable;
struct additional_cost_htable;

/* Entry point to the child process. */
int fork_router_child(const struct gossmap *gossmap,
		      const struct layer **layers,
		      const s8 *biases,
		      const struct additional_cost_htable *additional_costs,
		      struct reserve_htable *reserved,
		      fp16_t *capacities TAKES,
		      bool single_path,
		      struct timemono deadline,
		      const struct gossmap_node *srcnode,
		      const struct gossmap_node *dstnode,
		      struct amount_msat amount, struct amount_msat maxfee,
		      u32 finalcltv, u32 maxdelay, size_t maxparts,
		      bool include_fees,
		      const char *cmd_id,
		      struct json_filter *cmd_filter,
		      int *log_fd,
		      int *child_pid);
#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_ENTRY_H */

#ifndef LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#define LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <common/amount.h>
#include <common/fp16.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>

struct gossmap_chan;

/* Grab-bag of "globals" for this plugin */
struct askrene {
	struct plugin *plugin;
	struct gossmap *gossmap;
	/* Hash table of layers by name */
	struct layer_name_hash *layers;
	/* In-flight payment attempts */
	struct reserve_htable *reserved;
	/* Compact cache of gossmap capacities */
	fp16_t *capacities;
	/* My own id */
	struct node_id my_id;
	/* Aux command for layer */
	struct command *layer_cmd;
	/* How long before we abort trying to find a route? */
	u32 route_seconds;
	/* Routing children currently in flight. */
	struct list_head children;
};

/* Useful plugin->askrene mapping */
static inline struct askrene *get_askrene(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct askrene);
}
#endif /* LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H */

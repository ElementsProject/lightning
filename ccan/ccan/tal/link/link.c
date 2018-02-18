/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/tal/link/link.h>
#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <assert.h>

/* Our linkable parent. */
struct linkable {
	struct list_head links;
};

struct link {
	struct list_node list;
};

static void linkable_notifier(tal_t *linkable,
			      enum tal_notify_type type,
			      void *info UNNEEDED)
{
	struct linkable *l = tal_parent(linkable);
	assert(type == TAL_NOTIFY_STEAL || type == TAL_NOTIFY_FREE);

	/* We let you free it if you haven't linked it yet. */
	if (type == TAL_NOTIFY_FREE && list_empty(&l->links)) {
		tal_free(l);
		return;
	}

	/* Don't try to steal or free this: it has multiple links! */
	abort();
}

void *tal_linkable_(tal_t *newobj)
{
	struct linkable *l;

	/* Must be a fresh object. */
	assert(!tal_parent(newobj));

	l = tal(NULL, struct linkable);
	if (!l)
		goto fail;
	list_head_init(&l->links);

	if (!tal_steal(l, newobj))
		goto fail;

	if (!tal_add_notifier(newobj, TAL_NOTIFY_STEAL|TAL_NOTIFY_FREE,
			      linkable_notifier)) {
		tal_steal(NULL, newobj);
		goto fail;
	}

	return (void *)newobj;

fail:
	tal_free(l);
	return NULL;
}

static void destroy_link(struct link *lnk)
{
	struct linkable *l;

	/* Only true if we're first in list! */
	l = container_of(lnk->list.prev, struct linkable, links.n);

	list_del(&lnk->list);

	if (list_empty(&l->links))
		tal_free(l);
}

void *tal_link_(const tal_t *ctx, const tal_t *link)
{
	struct linkable *l = tal_parent(link);
	struct link *lnk = tal(ctx, struct link);

	if (!lnk)
		return NULL;
	if (!tal_add_destructor(lnk, destroy_link)) {
		tal_free(lnk);
		return NULL;
	}
	list_add(&l->links, &lnk->list);
	return (void *)link;
}

void tal_delink_(const tal_t *ctx, const tal_t *link)
{
	struct linkable *l = tal_parent(link);
	struct link *i;

	if (!link)
		return;

	/* FIXME: slow, but hopefully unusual. */
	list_for_each(&l->links, i, list) {
		if (tal_parent(i) == ctx) {
			tal_free(i);
			return;
		}
	}
	abort();
}

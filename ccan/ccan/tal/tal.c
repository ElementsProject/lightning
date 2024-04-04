/* Licensed under BSD-MIT - see LICENSE file for details */
#include <ccan/tal/tal.h>
#include <ccan/compiler/compiler.h>
#include <ccan/list/list.h>
#include <ccan/alignof/alignof.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>

//#define TAL_DEBUG 1

#define NOTIFY_IS_DESTRUCTOR 512
#define NOTIFY_EXTRA_ARG 1024

/* This makes our parent_child ptr stand out for to_tal_hdr checks */
#define TAL_PTR_OBFUSTICATOR ((intptr_t)0x1984200820142016ULL)

/* 32-bit type field, first byte 0 in either endianness. */
enum prop_type {
	CHILDREN = 0x00c1d500,
	NAME = 0x00111100,
	NOTIFIER = 0x00071f00,
};

struct tal_hdr {
	struct list_node list;
	/* Use is_prop_hdr tell if this is a struct prop_hdr or string! */
	char *prop;
	/* XOR with TAL_PTR_OBFUSTICATOR */
	intptr_t parent_child;
	size_t bytelen;
};

struct prop_hdr {
	enum prop_type type;
	/* Use is_prop_hdr to tell if this is a struct prop_hdr or string! */
	char *next;
};

struct children {
	struct prop_hdr hdr; /* CHILDREN */
	struct tal_hdr *parent;
	struct list_head children; /* Head of siblings. */
};

struct name {
	struct prop_hdr hdr; /* NAME */
	char name[];
};

struct notifier {
	struct prop_hdr hdr; /* NOTIFIER */
	enum tal_notify_type types;
	union notifier_cb {
		void (*notifyfn)(tal_t *, enum tal_notify_type, void *);
		void (*destroy)(tal_t *); /* If NOTIFY_IS_DESTRUCTOR set */
		void (*destroy2)(tal_t *, void *); /* If NOTIFY_EXTRA_ARG */
	} u;
};

/* Extra arg */
struct notifier_extra_arg {
	struct notifier n;
	void *arg;
};

#define EXTRA_ARG(n) (((struct notifier_extra_arg *)(n))->arg)

static struct {
	struct tal_hdr hdr;
	struct children c;
} null_parent = { { { &null_parent.hdr.list, &null_parent.hdr.list },
		(char *)&null_parent.c.hdr, TAL_PTR_OBFUSTICATOR, 0 },
		  { { CHILDREN, NULL },
		    &null_parent.hdr,
		    { { &null_parent.c.children.n,
			&null_parent.c.children.n } }
		  }
};


static void *(*allocfn)(size_t size) = malloc;
static void *(*resizefn)(void *, size_t size) = realloc;
static void (*freefn)(void *) = free;
static void (*errorfn)(const char *msg) = (void *)abort;
/* Count on non-destrutor notifiers; often stays zero. */
static size_t notifiers = 0;

static inline void COLD call_error(const char *msg)
{
	errorfn(msg);
}

static bool get_destroying_bit(intptr_t parent_child)
{
	return parent_child & 1;
}

static void set_destroying_bit(intptr_t *parent_child)
{
	*parent_child |= 1;
}

static struct children *ignore_destroying_bit(intptr_t parent_child)
{
	return (void *)((parent_child ^ TAL_PTR_OBFUSTICATOR) & ~(intptr_t)1);
}

/* This means valgrind can see leaks. */
void tal_cleanup(void)
{
	struct tal_hdr *i;

	while ((i = list_top(&null_parent.c.children, struct tal_hdr, list))) {
		list_del(&i->list);
		memset(i, 0, sizeof(*i));
	}

	/* Cleanup any taken pointers. */
	take_cleanup();
}

/* We carefully start all real properties with a zero byte. */
static struct prop_hdr *is_prop_hdr(const char *ptr)
{
	if (*ptr != 0)
		return NULL;
	return (struct prop_hdr *)ptr;
}

#ifndef NDEBUG
static const void *bounds_start, *bounds_end;

static void update_bounds(const void *new, size_t size)
{
	if (unlikely(!bounds_start)) {
		bounds_start = new;
		bounds_end = (char *)new + size;
	} else if (new < bounds_start)
		bounds_start = new;
	else if ((char *)new + size > (char *)bounds_end)
		bounds_end = (char *)new + size;
}

static bool in_bounds(const void *p)
{
	return !p
		|| (p >= (void *)&null_parent && p <= (void *)(&null_parent + 1))
		|| (p >= bounds_start && p <= bounds_end);
}
#else
static void update_bounds(const void *new, size_t size)
{
}

static bool in_bounds(const void *p)
{
	return true;
}
#endif

static void check_bounds(const void *p)
{
	if (!in_bounds(p))
		call_error("Not a valid header");
}

static struct tal_hdr *to_tal_hdr(const void *ctx)
{
	struct tal_hdr *t;

	t = (struct tal_hdr *)((char *)ctx - sizeof(struct tal_hdr));
	check_bounds(t);
	check_bounds(ignore_destroying_bit(t->parent_child));
	check_bounds(t->list.next);
	check_bounds(t->list.prev);
	if (t->prop) {
		struct prop_hdr *p = is_prop_hdr(t->prop);
		if (p)
			check_bounds(p);
	}
	return t;
}

static struct tal_hdr *to_tal_hdr_or_null(const void *ctx)
{
	if (!ctx)
		return &null_parent.hdr;
	return to_tal_hdr(ctx);
}

static void *from_tal_hdr(const struct tal_hdr *hdr)
{
	return (void *)(hdr + 1);
}

static void *from_tal_hdr_or_null(const struct tal_hdr *hdr)
{
	if (hdr == &null_parent.hdr)
		return NULL;
	return from_tal_hdr(hdr);
}

#ifdef TAL_DEBUG
static struct tal_hdr *debug_tal(struct tal_hdr *tal)
{
	tal_check(from_tal_hdr_or_null(tal), "TAL_DEBUG ");
	return tal;
}
#else
static struct tal_hdr *debug_tal(struct tal_hdr *tal)
{
	return tal;
}
#endif

static void notify(const struct tal_hdr *ctx,
		   enum tal_notify_type type, const void *info,
		   int saved_errno)
{
        const char *ptr;
	const struct prop_hdr *p;

        for (ptr = ctx->prop; ptr && (p = is_prop_hdr(ptr)) != NULL; ptr = p->next) {
		struct notifier *n;

                if (p->type != NOTIFIER)
			continue;
		n = (struct notifier *)p;
		if (n->types & type) {
			errno = saved_errno;
			if (n->types & NOTIFY_IS_DESTRUCTOR) {
				/* Blatt this notifier in case it tries to
				 * tal_del_destructor() from inside */
				union notifier_cb cb = n->u;
				/* It's a union, so this NULLs destroy2 too! */
				n->u.destroy = NULL;
				if (n->types & NOTIFY_EXTRA_ARG)
					cb.destroy2(from_tal_hdr(ctx),
						    EXTRA_ARG(n));
				else
					cb.destroy(from_tal_hdr(ctx));
			} else
				n->u.notifyfn(from_tal_hdr_or_null(ctx), type,
					      (void *)info);
		}
	}
}

static void *allocate(size_t size)
{
	void *ret = allocfn(size);
	if (!ret)
		call_error("allocation failed");
	else
		update_bounds(ret, size);
	return ret;
}

/* Returns a pointer to the pointer: can cast (*ret) to a (struct prop_ptr *) */
static char **find_property_ptr(struct tal_hdr *t, enum prop_type type)
{
	char **ptr;
        struct prop_hdr *p;

	/* NAME is special, as it can be a literal: see find_name_property */
	assert(type != NAME);
	for (ptr = &t->prop; *ptr; ptr = &p->next) {
		if (!is_prop_hdr(*ptr))
			break;
		p = (struct prop_hdr *)*ptr;
                if (p->type == type)
                        return ptr;
	}
	return NULL;
}

/* This is special:
 * NULL - not found
 * *literal: true - char **, pointer to literal pointer.
 * *literal: false - struct prop_hdr **, pointer to header ptr.
 */
static char **find_name_property(struct tal_hdr *t, bool *literal)
{
	char **ptr;
        struct prop_hdr *p;

	for (ptr = &t->prop; *ptr; ptr = &p->next) {
		if (!is_prop_hdr(*ptr)) {
			*literal = true;
			return ptr;
		}
		p = (struct prop_hdr *)*ptr;
                if (p->type == NAME) {
			*literal = false;
                        return ptr;
		}
	}
	return NULL;
}

static void *find_property(struct tal_hdr *parent, enum prop_type type)
{
        char **ptr = find_property_ptr(parent, type);

        if (ptr)
                return (struct prop_hdr *)*ptr;
        return NULL;
}

static void init_property(struct prop_hdr *hdr,
			  struct tal_hdr *parent,
			  enum prop_type type)
{
	hdr->type = type;
	hdr->next = parent->prop;
	parent->prop = (char *)hdr;
}

static struct notifier *add_notifier_property(struct tal_hdr *t,
					      enum tal_notify_type types,
					      void (*fn)(void *,
							 enum tal_notify_type,
							 void *),
					      void *extra_arg)
{
	struct notifier *prop;

	if (types & NOTIFY_EXTRA_ARG)
		prop = allocate(sizeof(struct notifier_extra_arg));
	else
		prop = allocate(sizeof(struct notifier));

	if (prop) {
		init_property(&prop->hdr, t, NOTIFIER);
		prop->types = types;
		prop->u.notifyfn = fn;
		if (types & NOTIFY_EXTRA_ARG)
			EXTRA_ARG(prop) = extra_arg;
	}
	return prop;
}

static enum tal_notify_type del_notifier_property(struct tal_hdr *t,
						  void (*fn)(tal_t *,
							     enum tal_notify_type,
							     void *),
						  bool match_extra_arg,
						  void *extra_arg)
{
	char **ptr;
	struct prop_hdr *p;

	for (ptr = &t->prop; *ptr; ptr = &p->next) {
		struct notifier *n;
		enum tal_notify_type types;

		p = is_prop_hdr(*ptr);
		if (!p)
			break;

                if (p->type != NOTIFIER)
			continue;
		n = (struct notifier *)p;
		if (n->u.notifyfn != fn)
			continue;

		types = n->types;
		if ((types & NOTIFY_EXTRA_ARG)
		    && match_extra_arg
		    && extra_arg != EXTRA_ARG(n))
			continue;

		*ptr = p->next;
		freefn(p);
		return types & ~(NOTIFY_IS_DESTRUCTOR|NOTIFY_EXTRA_ARG);
        }
        return 0;
}

static struct name *add_name_property(struct tal_hdr *t, const char *name)
{
	struct name *prop;

	prop = allocate(sizeof(*prop) + strlen(name) + 1);
	if (prop) {
		init_property(&prop->hdr, t, NAME);
		strcpy(prop->name, name);
	}
	return prop;
}

static struct children *add_child_property(struct tal_hdr *parent,
					   struct tal_hdr *child UNNEEDED)
{
	struct children *prop = allocate(sizeof(*prop));
	if (prop) {
		init_property(&prop->hdr, parent, CHILDREN);
		prop->parent = parent;
		list_head_init(&prop->children);
	}
	return prop;
}

static bool add_child(struct tal_hdr *parent, struct tal_hdr *child)
{
	struct children *children = find_property(parent, CHILDREN);

        if (!children) {
		children = add_child_property(parent, child);
		if (!children)
			return false;
	}
	list_add(&children->children, &child->list);
	child->parent_child = (intptr_t)children ^ TAL_PTR_OBFUSTICATOR;
	return true;
}

static void del_tree(struct tal_hdr *t, const tal_t *orig, int saved_errno)
{
	struct prop_hdr *prop;
	char *ptr, *next;

	assert(!taken(from_tal_hdr(t)));

        /* Already being destroyed?  Don't loop. */
        if (unlikely(get_destroying_bit(t->parent_child)))
                return;

        set_destroying_bit(&t->parent_child);

	/* Call free notifiers. */
	notify(t, TAL_NOTIFY_FREE, (tal_t *)orig, saved_errno);

	/* Now free children and groups. */
	prop = find_property(t, CHILDREN);
	if (prop) {
		struct tal_hdr *i;
		struct children *c = (struct children *)prop;

		while ((i = list_top(&c->children, struct tal_hdr, list))) {
			list_del(&i->list);
			del_tree(i, orig, saved_errno);
		}
	}

        /* Finally free our properties. */
	for (ptr = t->prop; ptr && (prop = is_prop_hdr(ptr)); ptr = next) {
                next = prop->next;
		freefn(ptr);
        }
        freefn(t);
}

/* Don't have compiler complain we're returning NULL if we promised not to! */
static void *null_alloc_failed(void)
{
#ifdef CCAN_TAL_NEVER_RETURN_NULL
	abort();
#else
	return NULL;
#endif /* CCAN_TAL_NEVER_RETURN_NULL */
}

void *tal_alloc_(const tal_t *ctx, size_t size, bool clear, const char *label)
{
        struct tal_hdr *child, *parent = debug_tal(to_tal_hdr_or_null(ctx));

        child = allocate(sizeof(struct tal_hdr) + size);
	if (!child)
		return null_alloc_failed();

	if (clear)
		memset(from_tal_hdr(child), 0, size);
        child->prop = (void *)label;
	child->bytelen = size;

        if (!add_child(parent, child)) {
		freefn(child);
		return null_alloc_failed();
	}
	debug_tal(parent);
	if (notifiers)
		notify(parent, TAL_NOTIFY_ADD_CHILD, from_tal_hdr(child), 0);
	return from_tal_hdr(debug_tal(child));
}

static bool adjust_size(size_t *size, size_t count)
{
	const size_t extra = sizeof(struct tal_hdr);

	/* Multiplication wrap */
        if (count && unlikely(*size * count / *size != count))
		goto overflow;

        *size *= count;

        /* Make sure we don't wrap adding header. */
        if (*size + extra < extra)
		goto overflow;
	return true;
overflow:
	call_error("allocation size overflow");
	return false;
}

void *tal_alloc_arr_(const tal_t *ctx, size_t size, size_t count, bool clear,
		     const char *label)
{
	if (!adjust_size(&size, count))
		return null_alloc_failed();

	return tal_alloc_(ctx, size, clear, label);
}

void *tal_free(const tal_t *ctx)
{
        if (ctx) {
		struct tal_hdr *t;
		int saved_errno = errno;
		t = debug_tal(to_tal_hdr(ctx));
		if (unlikely(get_destroying_bit(t->parent_child)))
			return NULL;
		if (notifiers)
			notify(ignore_destroying_bit(t->parent_child)->parent,
			       TAL_NOTIFY_DEL_CHILD, ctx, saved_errno);
		list_del(&t->list);
		del_tree(t, ctx, saved_errno);
		errno = saved_errno;
	}
	return NULL;
}

void *tal_steal_(const tal_t *new_parent, const tal_t *ctx)
{
        if (ctx) {
		struct tal_hdr *newpar, *t, *old_parent;

                newpar = debug_tal(to_tal_hdr_or_null(new_parent));
                t = debug_tal(to_tal_hdr(ctx));

                /* Unlink it from old parent. */
		list_del(&t->list);
		old_parent = ignore_destroying_bit(t->parent_child)->parent;

                if (unlikely(!add_child(newpar, t))) {
			/* We can always add to old parent, because it has a
			 * children property already. */
			if (!add_child(old_parent, t))
				abort();
			return NULL;
		}
		debug_tal(newpar);
		if (notifiers)
			notify(t, TAL_NOTIFY_STEAL, new_parent, 0);
        }
        return (void *)ctx;
}

bool tal_add_destructor_(const tal_t *ctx, void (*destroy)(void *me))
{
	tal_t *t = debug_tal(to_tal_hdr(ctx));
	return add_notifier_property(t, TAL_NOTIFY_FREE|NOTIFY_IS_DESTRUCTOR,
				     (void *)destroy, NULL);
}

bool tal_add_destructor2_(const tal_t *ctx, void (*destroy)(void *me, void *arg),
			  void *arg)
{
	tal_t *t = debug_tal(to_tal_hdr(ctx));
	return add_notifier_property(t, TAL_NOTIFY_FREE|NOTIFY_IS_DESTRUCTOR
				     |NOTIFY_EXTRA_ARG,
				     (void *)destroy, arg);
}

/* We could support notifiers with an extra arg, but we didn't add to API */
bool tal_add_notifier_(const tal_t *ctx, enum tal_notify_type types,
		       void (*callback)(tal_t *, enum tal_notify_type, void *))
{
	struct tal_hdr *t = debug_tal(to_tal_hdr_or_null(ctx));
	struct notifier *n;

	assert(types);
	assert((types & ~(TAL_NOTIFY_FREE | TAL_NOTIFY_STEAL | TAL_NOTIFY_MOVE
			  | TAL_NOTIFY_RESIZE | TAL_NOTIFY_RENAME
			  | TAL_NOTIFY_ADD_CHILD | TAL_NOTIFY_DEL_CHILD
			  | TAL_NOTIFY_ADD_NOTIFIER
			  | TAL_NOTIFY_DEL_NOTIFIER)) == 0);

	/* Don't call notifier about itself: set types after! */
        n = add_notifier_property(t, 0, callback, NULL);
	if (unlikely(!n))
		return false;

	if (notifiers)
		notify(t, TAL_NOTIFY_ADD_NOTIFIER, callback, 0);

	n->types = types;
	if (types != TAL_NOTIFY_FREE)
		notifiers++;
	return true;
}

bool tal_del_notifier_(const tal_t *ctx,
		       void (*callback)(tal_t *, enum tal_notify_type, void *),
		       bool match_extra_arg, void *extra_arg)
{
	struct tal_hdr *t = debug_tal(to_tal_hdr_or_null(ctx));
	enum tal_notify_type types;

        types = del_notifier_property(t, callback, match_extra_arg, extra_arg);
	if (types) {
		notify(t, TAL_NOTIFY_DEL_NOTIFIER, callback, 0);
		if (types != TAL_NOTIFY_FREE)
			notifiers--;
		return true;
	}
	return false;
}

bool tal_del_destructor_(const tal_t *ctx, void (*destroy)(void *me))
{
	return tal_del_notifier_(ctx, (void *)destroy, false, NULL);
}

bool tal_del_destructor2_(const tal_t *ctx, void (*destroy)(void *me, void *arg),
			  void *arg)
{
	return tal_del_notifier_(ctx, (void *)destroy, true, arg);
}

bool tal_set_name_(tal_t *ctx, const char *name, bool literal)
{
        struct tal_hdr *t = debug_tal(to_tal_hdr(ctx));
	bool was_literal;
	char **nptr;

        /* Get rid of any old name */
	nptr = find_name_property(t, &was_literal);
	if (nptr) {
		if (was_literal)
			*nptr = NULL;
		else {
			struct name *oldname;

			oldname = (struct name *)*nptr;
			*nptr = oldname->hdr.next;
			freefn(oldname);
		}
        }

        if (literal && name[0]) {
		char **ptr;
		struct prop_hdr *prop;

                /* Append literal. */
		for (ptr = &t->prop; *ptr; ptr = &prop->next) {
			prop = is_prop_hdr(*ptr);
			if (!prop)
				break;
		}
                *ptr = (char *)name;
        } else if (!add_name_property(t, name))
		return false;

	debug_tal(t);
	if (notifiers)
		notify(t, TAL_NOTIFY_RENAME, name, 0);
	return true;
}

const char *tal_name(const tal_t *t)
{
	char **nptr;
	bool literal;

	nptr = find_name_property(debug_tal(to_tal_hdr(t)), &literal);
	if (!nptr)
		return NULL;
	if (literal)
		return *nptr;

	return ((struct name *)(*nptr))->name;
}

size_t tal_bytelen(const tal_t *ptr)
{
	/* NULL -> null_parent which has bytelen 0 */
	struct tal_hdr *t = debug_tal(to_tal_hdr_or_null(ptr));

	return t->bytelen;
}

/* Start one past first child: make stopping natural in circ. list. */
static struct tal_hdr *first_child(struct tal_hdr *parent)
{
	struct children *child;

	child = find_property(parent, CHILDREN);
        if (!child)
                return NULL;

	return list_top(&child->children, struct tal_hdr, list);
}

tal_t *tal_first(const tal_t *root)
{
        struct tal_hdr *c, *t = debug_tal(to_tal_hdr_or_null(root));

	c = first_child(t);
	if (!c)
		return NULL;
	return from_tal_hdr(c);
}

tal_t *tal_next(const tal_t *prev)
{
        struct tal_hdr *next, *prevhdr = debug_tal(to_tal_hdr(prev));
	struct list_head *head;

	head = &ignore_destroying_bit(prevhdr->parent_child)->children;
	next = list_next(head, prevhdr, list);
	if (!next)
		return NULL;
	return from_tal_hdr(next);
}

tal_t *tal_parent(const tal_t *ctx)
{
        struct tal_hdr *t;

	if (!ctx)
		return NULL;

	t = debug_tal(to_tal_hdr(ctx));
	if (ignore_destroying_bit(t->parent_child)->parent == &null_parent.hdr)
		return NULL;
        return from_tal_hdr(ignore_destroying_bit(t->parent_child)->parent);
}

bool tal_resize_(tal_t **ctxp, size_t size, size_t count, bool clear)
{
        struct tal_hdr *old_t, *t;
        struct children *child;

        old_t = debug_tal(to_tal_hdr(*ctxp));

	if (!adjust_size(&size, count))
		return false;

        t = resizefn(old_t, sizeof(struct tal_hdr) + size);
	if (!t) {
		call_error("Reallocation failure");
		return false;
	}

	/* Clear between old end and new end. */
	if (clear && size > t->bytelen) {
		char *old_end = (char *)(t + 1) + t->bytelen;
		memset(old_end, 0, size - t->bytelen);
	}

	/* Update length. */
	t->bytelen = size;
	update_bounds(t, sizeof(struct tal_hdr) + size);

	/* If it didn't move, we're done! */
        if (t != old_t) {
		/* Fix up linked list pointers. */
		t->list.next->prev = t->list.prev->next = &t->list;

		/* Copy take() property. */
		if (taken(from_tal_hdr(old_t)))
			take(from_tal_hdr(t));

		/* Fix up child property's parent pointer. */
		child = find_property(t, CHILDREN);
		if (child) {
			assert(child->parent == old_t);
			child->parent = t;
		}
		*ctxp = from_tal_hdr(debug_tal(t));
		if (notifiers)
			notify(t, TAL_NOTIFY_MOVE, from_tal_hdr(old_t), 0);
	}
	if (notifiers)
		notify(t, TAL_NOTIFY_RESIZE, (void *)size, 0);

	return true;
}

bool tal_expand_(tal_t **ctxp, const void *src, size_t size, size_t count)
{
	size_t old_len;
	bool ret = false;

	old_len = debug_tal(to_tal_hdr(*ctxp))->bytelen;

	/* Check for additive overflow */
	if (old_len + count * size < old_len) {
		call_error("dup size overflow");
		goto out;
	}

	/* Don't point src inside thing we're expanding! */
	assert(src < *ctxp
	       || (char *)src >= (char *)(*ctxp) + old_len);

	if (!tal_resize_(ctxp, size, old_len/size + count, false))
		goto out;

	memcpy((char *)*ctxp + old_len, src, count * size);
	ret = true;

out:
	if (taken(src))
		tal_free(src);
	return ret;
}

void *tal_dup_(const tal_t *ctx, const void *p, size_t size,
	       size_t n, size_t extra, bool nullok, const char *label)
{
	void *ret;
	size_t nbytes = size;

	if (nullok && p == NULL) {
		/* take(NULL) works. */
		(void)taken(p);
		return NULL;
	}
	
	if (!adjust_size(&nbytes, n)) {
		if (taken(p))
			tal_free(p);
		return NULL;
	}

	/* Beware addition overflow! */
	if (n + extra < n) {
		call_error("dup size overflow");
		if (taken(p))
			tal_free(p);
		return NULL;
	}

	if (taken(p)) {
		if (unlikely(!p))
			return NULL;
		if (unlikely(!tal_resize_((void **)&p, size, n + extra, false)))
			return tal_free(p);
		if (unlikely(!tal_steal(ctx, p)))
			return tal_free(p);
		return (void *)p;
	}

	ret = tal_alloc_arr_(ctx, size, n + extra, false, label);
	if (ret && p)
		memcpy(ret, p, nbytes);
	return ret;
}

void *tal_dup_talarr_(const tal_t *ctx, const tal_t *src TAKES, const char *label)
{
	return tal_dup_(ctx, src, 1, tal_bytelen(src), 0, true, label);
}

void tal_set_backend(void *(*alloc_fn)(size_t size),
		     void *(*resize_fn)(void *, size_t size),
		     void (*free_fn)(void *),
		     void (*error_fn)(const char *msg))
{
	if (alloc_fn)
		allocfn = alloc_fn;
	if (resize_fn)
		resizefn = resize_fn;
	if (free_fn)
		freefn = free_fn;
	if (error_fn)
		errorfn = error_fn;
}

#ifdef CCAN_TAL_DEBUG
static void dump_node(unsigned int indent, const struct tal_hdr *t)
{
	unsigned int i;
        const struct prop_hdr *prop;
	const char *ptr;

	for (i = 0; i < indent; i++)
		fprintf(stderr, "  ");
	fprintf(stderr, "%p len=%zu", t, t->bytelen);
        for (ptr = t->prop; ptr; ptr = prop->next) {
		struct children *c;
		struct name *n;
		struct notifier *no;
                prop = is_prop_hdr(ptr);
		if (!prop) {
			fprintf(stderr, " \"%s\"", ptr);
			break;
		}
		switch (prop->type) {
		case CHILDREN:
			c = (struct children *)prop;
			fprintf(stderr, " CHILDREN(%p):parent=%p,children={%p,%p}",
			       prop, c->parent,
			       c->children.n.prev, c->children.n.next);
			break;
		case NAME:
			n = (struct name *)prop;
			fprintf(stderr, " NAME(%p):%s", prop, n->name);
			break;
		case NOTIFIER:
			no = (struct notifier *)prop;
			fprintf(stderr, " NOTIFIER(%p):fn=%p", prop, no->u.notifyfn);
			break;
		default:
			fprintf(stderr, " **UNKNOWN(%p):%i**", prop, prop->type);
		}
	}
	fprintf(stderr, "\n");
}

static void tal_dump_(unsigned int level, const struct tal_hdr *t)
{
        struct children *children;

	dump_node(level, t);

	children = find_property((struct tal_hdr *)t, CHILDREN);
	if (children) {
		struct tal_hdr *i;

		list_for_each(&children->children, i, list)
			tal_dump_(level + 1, i);
	}
}

void tal_dump(void)
{
	tal_dump_(0, &null_parent.hdr);
}
#endif /* CCAN_TAL_DEBUG */

#ifndef NDEBUG
static bool check_err(struct tal_hdr *t, const char *errorstr,
		      const char *errmsg)
{
	if (errorstr) {
		/* Try not to malloc: it may be corrupted. */
		char msg[strlen(errorstr) + 20 + strlen(errmsg) + 1];
		sprintf(msg, "%s:%p %s", errorstr, from_tal_hdr(t), errmsg);
		call_error(msg);
	}
	return false;
}

static bool check_node(struct children *parent_child,
		       struct tal_hdr *t, const char *errorstr)
{
	struct prop_hdr *prop;
	char *p;
	struct name *name = NULL;
	struct children *children = NULL;

	if (!in_bounds(t))
		return check_err(t, errorstr, "invalid pointer");

	if (ignore_destroying_bit(t->parent_child) != parent_child)
		return check_err(t, errorstr, "incorrect parent");

	for (p = t->prop; p; p = prop->next) {
		prop = is_prop_hdr(p);
		if (!prop) {
			if (name)
				return check_err(t, errorstr,
						 "has extra literal");
			break;
		}
		if (!in_bounds(prop))
			return check_err(t, errorstr,
					 "has bad property pointer");

		switch (prop->type) {
		case CHILDREN:
			if (children)
				return check_err(t, errorstr,
						 "has two child nodes");
			children = (struct children *)prop;
			break;
		case NOTIFIER:
			break;
		case NAME:
			if (name)
				return check_err(t, errorstr,
						 "has two names");
			name = (struct name *)prop;
			break;
		default:
			return check_err(t, errorstr, "has unknown property");
		}
	}
	if (children) {
		struct tal_hdr *i;

		if (!list_check(&children->children, errorstr))
			return false;
		list_for_each(&children->children, i, list) {
			if (!check_node(children, i, errorstr))
				return false;
		}
	}
	return true;
}

bool tal_check(const tal_t *ctx, const char *errorstr)
{
	struct tal_hdr *t = to_tal_hdr_or_null(ctx);

	return check_node(ignore_destroying_bit(t->parent_child), t, errorstr);
}
#else /* NDEBUG */
bool tal_check(const tal_t *ctx, const char *errorstr)
{
	return true;
}
#endif

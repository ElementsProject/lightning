/* Licensed under LGPL - see LICENSE file for details */
#include <ccan/tal/talloc/talloc.h>
#include <ccan/take/take.h>
#include <errno.h>
#include <assert.h>

static void (*errorfn)(const char *msg) = (void *)abort;

static void COLD call_error(const char *msg)
{
	errorfn(msg);
}

static void *error_on_null(void *p, const char *msg)
{
	if (!p)
		call_error(msg);
	return p;
}

void *tal_talloc_(const tal_t *ctx, size_t bytes, bool clear,
		  const char *label)
{
	void *ret;

	if (clear)
		ret = _talloc_zero(ctx, bytes, label);
	else
		ret = talloc_named_const(ctx, bytes, label);

	return error_on_null(ret, "allocation failure");
}

void *tal_talloc_arr_(const tal_t *ctx, size_t bytes, size_t count, bool clear,
		      const char *label)
{
	void *ret;

	if (clear)
		ret = _talloc_zero_array(ctx, bytes, count, label);
	else
		ret = _talloc_array(ctx, bytes, count, label);

	return error_on_null(ret, "array allocation failure");
}

void *tal_talloc_free_(const tal_t *ctx)
{
	int saved_errno = errno;
	talloc_free((void *)ctx);
	errno = saved_errno;
	return NULL;
}

bool tal_talloc_set_name_(tal_t *ctx, const char *name, bool literal)
{
	if (!literal) {
		name = talloc_strdup(ctx, name);
		if (!name) {
			call_error("set_name allocation failure");
			return false;
		}
	}
	talloc_set_name_const(ctx, name);
	return true;
}

const char *tal_talloc_name_(const tal_t *ctx)
{
	const char *p = talloc_get_name(ctx);
	if (p && unlikely(strcmp(p, "UNNAMED") == 0))
		p = NULL;
	return p;
}

static bool adjust_size(size_t *size, size_t count)
{
	/* Multiplication wrap */
        if (count && unlikely(*size * count / *size != count))
		goto overflow;

        *size *= count;

        /* Make sure we don't wrap adding header. */
        if (*size + 1024 < 1024)
		goto overflow;
	return true;
overflow:
	call_error("allocation size overflow");
	return false;
}

void *tal_talloc_dup_(const tal_t *ctx, const void *p, size_t size,
		      size_t n, size_t extra, const char *label)
{
	void *ret;
	size_t nbytes = size;

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
		if (unlikely(!tal_talloc_resize_((void **)&p, size, n + extra)))
			return tal_free(p);
		if (unlikely(!tal_steal(ctx, p)))
			return tal_free(p);
		return (void *)p;
	}

	ret = tal_talloc_arr_(ctx, size, n + extra, false, label);
	if (ret)
		memcpy(ret, p, nbytes);
	return ret;
}

bool tal_talloc_resize_(tal_t **ctxp, size_t size, size_t count)
{
	tal_t *newp;

	if (unlikely(count == 0)) {
		/* Don't free it! */
		newp = talloc_size(talloc_parent(*ctxp), 0);
		if (!newp) {
			call_error("Resize failure");
			return false;
		}
		talloc_free(*ctxp);
		*ctxp = newp;
		return true;
	}

	/* count is unsigned, not size_t, so check for overflow here! */
	if ((unsigned)count != count) {
		call_error("Resize overflos");
		return false;
	}

	newp = _talloc_realloc_array(NULL, *ctxp, size, count, NULL);
	if (!newp) {
		call_error("Resize failure");
		return false;
	}
	*ctxp = newp;
	return true;
}

bool tal_talloc_expand_(tal_t **ctxp, const void *src, size_t size, size_t count)
{
	bool ret = false;
	size_t old_count = talloc_get_size(*ctxp) / size;

	/* Check for additive overflow */
	if (old_count + count < count) {
		call_error("dup size overflow");
		goto out;
	}

	/* Don't point src inside thing we're expanding! */
	assert(src < *ctxp
	       || (char *)src >= (char *)(*ctxp) + (size * old_count));

	if (!tal_talloc_resize_(ctxp, size, old_count + count))
		goto out;

	memcpy((char *)*ctxp + size * old_count, src, count * size);
	ret = true;

out:
	if (taken(src))
		tal_free(src);
	return ret;
}

/* Sucky inline hash table implementation, to avoid deps. */
#define HTABLE_BITS 10
struct destructor {
	struct destructor *next;
	const tal_t *ctx;
	void (*destroy)(void *me);
};
static struct destructor *destr_hash[1 << HTABLE_BITS];

static unsigned int hash_ptr(const void *p)
{
	unsigned long h = (unsigned long)p / sizeof(void *);

	return (h ^ (h >> HTABLE_BITS)) & ((1 << HTABLE_BITS) - 1);
}

static int tal_talloc_destroy(const tal_t *ctx)
{
	struct destructor **d = &destr_hash[hash_ptr(ctx)];
	while (*d) {
		if ((*d)->ctx == ctx) {
			struct destructor *this = *d;
			this->destroy((void *)ctx);
			*d = this->next;
			talloc_free(this);
		}
	}
	return 0;
}

bool tal_talloc_add_destructor_(const tal_t *ctx, void (*destroy)(void *me))
{
	struct destructor *d = talloc(ctx, struct destructor);
	if (!d)
		return false;

	d->next = destr_hash[hash_ptr(ctx)];
	d->ctx = ctx;
	d->destroy = destroy;
	destr_hash[hash_ptr(ctx)] = d;
	talloc_set_destructor(ctx, tal_talloc_destroy);
	return true;
}

bool tal_talloc_del_destructor_(const tal_t *ctx, void (*destroy)(void *me))
{
	struct destructor **d = &destr_hash[hash_ptr(ctx)];

	while (*d) {
		if ((*d)->ctx == ctx && (*d)->destroy == destroy) {
			struct destructor *this = *d;
			*d = this->next;
			talloc_free(this);
			return true;
		}
		d = &(*d)->next;
	}
	return false;
}

void tal_talloc_set_backend_(void *(*alloc_fn)(size_t size),
			     void *(*resize_fn)(void *, size_t size),
			     void (*free_fn)(void *),
			     void (*error_fn)(const char *msg))
{
	assert(!alloc_fn);
	assert(!resize_fn);
	assert(!free_fn);
	errorfn = error_fn;
	talloc_set_abort_fn(error_fn);
}

bool tal_talloc_check_(const tal_t *ctx, const char *errorstr)
{
	/* We can't really check, but this iterates (and may abort). */
	return !ctx || talloc_total_blocks(ctx) >= 1;
}

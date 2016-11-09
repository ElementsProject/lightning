/* tal/talloc can't implement tal_first/tal_next. */
#ifdef TAL_USE_TALLOC
static inline bool no_children(const void *ctx)
{
	return talloc_total_blocks(ctx) == 1;
}

static inline bool single_child(const void *ctx, const void *child)
{
	return talloc_total_blocks(ctx) == 2 && tal_parent(child) == ctx;
}
#else
static inline bool no_children(const void *ctx)
{
	return !tal_first(ctx);
}

static inline bool single_child(const void *ctx, const void *child)
{
	return tal_first(ctx) == child && !tal_next(child) && !tal_first(child);
}
#endif

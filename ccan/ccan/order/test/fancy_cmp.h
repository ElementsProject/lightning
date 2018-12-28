#ifndef _FANCY_CMP_H
#define _FANCY_CMP_H

struct cmp_info {
	unsigned xcode;
	int offset;
};

struct item {
	unsigned value;
	const char *str;
};

static inline int fancy_cmp(const struct item *a, const struct item *b,
			    struct cmp_info *ctx)
{
	unsigned vala = a->value ^ ctx->xcode;
	unsigned valb = b->value ^ ctx->xcode;
	const char *stra, *strb;

	if (vala < valb)
		return -1;
	else if (valb < vala)
		return 1;

	stra = a->str + ctx->offset;
	strb = b->str + ctx->offset;

	return strcmp(stra, strb);
}

static inline int fancy_cmp_noctx(const void *av, const void *bv)
{
	const struct item *a = (const struct item *)av;
	const struct item *b = (const struct item *)bv;
	struct cmp_info ctx_default = {
		.xcode = 0x1234,
		.offset = 3,
	};
	total_order(default_order, struct item, struct cmp_info *) = {
		fancy_cmp, &ctx_default,
	};

	return default_order.cb(a, b, default_order.ctx);
}

#endif /* _FANCY_CMP_H */

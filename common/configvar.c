#include "config.h"
#include <assert.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/configvar.h>
#include <common/utils.h>
#include <unistd.h>

struct configvar *configvar_new(const tal_t *ctx,
				enum configvar_src src,
				const char *file,
				size_t linenum,
				const char *configline)
{
	struct configvar *cv = tal(ctx, struct configvar);
	cv->file = tal_strdup_or_null(cv, file);
	cv->src = src;
	cv->linenum = linenum;
	cv->configline = tal_strdup(cv, configline);
	cv->overridden = false;
	cv->optvar = NULL;
	/* We fill in cv->optvar and cv->optarg when parsing! */
	return cv;
}

const struct opt_table *configvar_unparsed(struct configvar *cv)
{
	const struct opt_table *ot;

	if (cv->src == CONFIGVAR_CMDLINE_SHORT) {
		ot = opt_find_short(cv->configline[0]);
		cv->optarg = NULL;
	} else {
		ot = opt_find_long(cv->configline, cast_const2(const char **, &cv->optarg));
	}
	if (!ot)
		return NULL;

	/* We get called multiple times, but we're expected to always
	 * finish the cv vars, even if they're added at the last minute
	 * on the cmdline, so we check this is only done once, and we
	 * do it even if we're not going to use it now. */
	if (!cv->optvar) {
		/* optvar is up to the = (i.e. one char before optarg) */
		if (!cv->optarg)
			cv->optvar = cv->configline;
		else
			cv->optvar = tal_strndup(cv, cv->configline,
						 cv->optarg - cv->configline - 1);
	}
	return ot;
}

static void trim_whitespace(char *s)
{
	size_t len = strlen(s);

	while (len > 0 && cisspace(s[len - 1]))
		len--;
	s[len] = '\0';
}

const char *configvar_parse(struct configvar *cv,
			    bool early,
			    bool full_knowledge,
			    bool developer)
{
	const struct opt_table *ot;

	ot = configvar_unparsed(cv);
	if (!ot) {
		/* Do we ignore unknown entries? */
		if (!full_knowledge)
			return NULL;
		return "unknown option";
	}

	if ((ot->type & OPT_DEV) && !developer)
		return "requires --developer";

	/* If we're early and we want late, or vv, ignore. */
	if (!!(ot->type & OPT_EARLY) != early)
		return NULL;

	if (ot->type & OPT_NOARG) {
		/* MULTI doesn't make sense with single args */
		assert(!(ot->type & OPT_MULTI));
		if (cv->optarg)
			return "doesn't allow an argument";
		return ot->cb(ot->u.arg);
	} else {
		if (!cv->optarg)
			return "requires an argument";
		if (!(ot->type & OPT_KEEP_WHITESPACE))
			trim_whitespace(cv->optarg);
		return ot->cb_arg(cv->optarg, ot->u.arg);
	}
}

/* This is O(N^2) but nobody cares */
void configvar_finalize_overrides(struct configvar **cvs)
{
	/* Map to options: two different names can be the same option,
	 * given aliases! */
	const struct opt_table **opts;

	opts = tal_arr(tmpctx, const struct opt_table *, tal_count(cvs));
	for (size_t i = 0; i < tal_count(cvs); i++) {
		opts[i] = opt_find_long(cvs[i]->optvar, NULL);
		/* If you're allowed multiple, they don't override */
		if (opts[i]->type & OPT_MULTI)
			continue;
		for (size_t j = 0; j < i; j++) {
			if (opts[j] == opts[i])
				cvs[j]->overridden = true;
		}
	}
}

void configvar_remove(struct configvar ***cvs,
		      const char *name,
		      enum configvar_src src,
		      const char *optarg)
{
	/* We remove all from this source, potentially restoring an overridden */
	ssize_t prev = -1;
	bool removed;

	removed = false;
	for (size_t i = 0; i < tal_count(*cvs); i++) {
		/* This can happen if plugin fails during startup! */
		if ((*cvs)[i]->optvar == NULL)
			continue;
		if (!streq((*cvs)[i]->optvar, name))
			continue;
		if (optarg && !streq((*cvs)[i]->optarg, optarg))
			continue;

		if ((*cvs)[i]->src == src) {
			tal_free((*cvs)[i]);
			tal_arr_remove(cvs, i);
			i--;
			removed = true;
			continue;
		}
		/* Wrong type, correct name. */
		prev = i;
	}

	/* Unmark prev if we removed overriding ones.  If it's multi,
	 * this is a noop. */
	if (removed && prev != -1)
		(*cvs)[prev]->overridden = false;
}

struct configvar *configvar_dup(const tal_t *ctx, const struct configvar *cv)
{
	struct configvar *ret;

	if (taken(cv))
		return tal_steal(ctx, cast_const(struct configvar *, cv));

	ret = tal_dup(ctx, struct configvar, cv);
	if (ret->file)
		ret->file = tal_strdup(ret, ret->file);
	if (ret->configline)
		ret->configline = tal_strdup(ret, ret->configline);
	if (ret->optvar) {
		ret->optvar = tal_strdup(ret, ret->optvar);
		/* Optarg, if non-NULL, points into cmdline! */
		if (ret->optarg) {
			size_t off = cv->optarg - cv->configline;
			assert(off < strlen(cv->configline));
			ret->optarg = ret->configline + off;
		}
	}
	return ret;
}

struct configvar **configvar_join(const tal_t *ctx,
				  struct configvar **first,
				  struct configvar **second)
{
	struct configvar **cvs;
	size_t n = tal_count(first);

	if (taken(first)) {
		cvs = tal_steal(ctx, first);
		tal_resize(&cvs, n + tal_count(second));
	} else {
		cvs = tal_arr(ctx, struct configvar *, n + tal_count(second));
		for (size_t i = 0; i < n; i++) {
			cvs[i] = configvar_dup(cvs, first[i]);
		}
	}
	if (taken(second)) {
		for (size_t i = 0; i < tal_count(second); i++)
			cvs[n + i] = tal_steal(cvs, second[i]);
		tal_free(second);
	} else {
		for (size_t i = 0; i < tal_count(second); i++)
			cvs[n + i] = configvar_dup(cvs, second[i]);
	}

	return cvs;
}

static struct configvar *configvar_iter(struct configvar **cvs,
					const char **names,
					const struct configvar *firstcv)
{
	for (size_t i = 0; i < tal_count(cvs); i++) {
		/* Wait until we reach firstcv, if any */
		if (firstcv) {
			if (cvs[i] == firstcv)
				firstcv = NULL;
			continue;
		}
		for (size_t j = 0; j < tal_count(names); j++) {
			/* In case we iterate before initialization! */
			if (!cvs[i]->optvar)
				continue;
			if (streq(cvs[i]->optvar, names[j]) && !cvs[i]->overridden)
				return cvs[i];
		}
	}
	return NULL;
}

struct configvar *configvar_first(struct configvar **cvs, const char **names)
{
	return configvar_iter(cvs, names, NULL);
}

struct configvar *configvar_next(struct configvar **cvs,
				 const struct configvar *cv,
				 const char **names)
{
	return configvar_iter(cvs, names, cv);
}

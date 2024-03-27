#ifndef LIGHTNING_COMMON_CONFIGVAR_H
#define LIGHTNING_COMMON_CONFIGVAR_H
#include "config.h"
#include <ccan/opt/opt.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* There are five possible sources of config options:
 * 1. The cmdline (and the cmdline, but it's a short option!)
 * 2. An explicitly named config (--conf=) (and its includes)
 * 3. An implied config (~/.lightning/config) (and includes)
 * 4. A network config ((~/.lightning/<network>/config) (and includes)
 * 5. A plugin start parameter.
 *
 * Turns out we care: you can't set network in a network config for
 * example.
 */
enum configvar_src {
	CONFIGVAR_CMDLINE,
	CONFIGVAR_CMDLINE_SHORT,
	CONFIGVAR_EXPLICIT_CONF,
	CONFIGVAR_BASE_CONF,
	CONFIGVAR_NETWORK_CONF,
	CONFIGVAR_PLUGIN_START,
};

/* This represents the configuration variables specified; they are
 * matched with ccan/option's opt_table which contains the
 * available options. */
struct configvar {
	/* NULL if CONFIGVAR_CMDLINE* or CONFIGVAR_PLUGIN_START */
	const char *file;
	/* 1-based line number (unused if !file) */
	u32 linenum;
	/* Where did we get this from? */
	enum configvar_src src;
	/* Never NULL, the whole line */
	const char *configline;

	/* These are filled in by configvar_parse */
	/* The variable name (without any =) */
	const char *optvar;
	/* NULL for no-arg options, otherwise points after =. */
	const char *optarg;
	/* Was this overridden by a following option? */
	bool overridden;
};

/* Set if multiple options accumulate (for listconfigs) */
#define OPT_MULTI (1 << OPT_USER_START)
/* Set if developer-only */
#define OPT_DEV (1 << (OPT_USER_START+1))
/* Doesn't return, so don't show in listconfigs */
#define OPT_EXITS (1 << (OPT_USER_START+2))
/* listconfigs should treat as a literal number */
#define OPT_SHOWINT (1 << (OPT_USER_START+3))
/* listconfigs should treat as a literal msat number */
#define OPT_SHOWMSATS (1 << (OPT_USER_START+4))
/* listconfigs should treat as a literal boolean `true` or `false` */
#define OPT_SHOWBOOL (1 << (OPT_USER_START+5))
/* Can be changed at runtime: cb will get called with NULL for `check`! */
#define OPT_DYNAMIC (1 << (OPT_USER_START+6))

/* Use this instead of opt_register_*_arg if you want OPT_* from above */
#define clnopt_witharg(names, type, cb, show, arg, desc)		\
	_opt_register((names),						\
		      OPT_CB_ARG((cb), (type), (show), (arg)),		\
		      (arg), (desc))

#define clnopt_noarg(names, type, cb, arg, desc)			\
	_opt_register((names),						\
		      OPT_CB_NOARG((cb), (type), (arg)),		\
		      (arg), (desc))

/**
 * configvar_new: allocate a fresh configvar
 * @ctx: parent to tallocate off
 * @src: where this came from
 * @file: filename (or NULL if cmdline)
 * @linenum: 1-based line number (or 0 for cmdline)
 * @configline: literal option (for argv[], after `--`)
 *
 * optvar/optarg/multi/overridden are only set by configvar_parse.
 */
struct configvar *configvar_new(const tal_t *ctx,
				enum configvar_src src,
				const char *file TAKES,
				size_t linenum,
				const char *configline TAKES)
	NON_NULL_ARGS(5);

/**
 * configvar_dup: copy a configvar
 * @ctx: parent to tallocate off
 * @cv: configvar to copy.
 */
struct configvar *configvar_dup(const tal_t *ctx,
				const struct configvar *cv TAKES)
	NON_NULL_ARGS(2);

/**
 * configvar_join: join two configvar arrays
 * @ctx: parent to tallocate off
 * @first: configvars to copy first
 * @second: configvars to copy second.
 */
struct configvar **configvar_join(const tal_t *ctx,
				  struct configvar **first TAKES,
				  struct configvar **second TAKES);

/**
 * configvar_parse: parse this configuration variable
 * @cv: the configuration setting.
 * @early: if we're doing early parsing.
 * @full_knowledge: error if we don't know this option.
 * @developer: if we're in developer mode (allow OPT_DEV options).
 *
 * This returns a string if parsing failed: if early_and_incomplete is
 * set, it doesn't complain about unknown options, and only parses
 * OPT_EARLY options.  Otherwise it parses all non-OPT_EARLY options,
 * and returns an error if they don't exist.
 *
 * On NULL return (success), cv->optvar, cv->optarg, cv->mult are set.
 */
const char *configvar_parse(struct configvar *cv,
			    bool early,
			    bool full_knowledge,
			    bool developer)
	NON_NULL_ARGS(1);

/**
 * configvar_unparsed: set up configuration variable, but don't parse it
 * @cv: the configuration setting.
 *
 * This returns the opt_table which matches this configvar, if any,
 * and if successful initializes cv->optvar and cv->optarg.
 */
const struct opt_table *configvar_unparsed(struct configvar *cv)
	NON_NULL_ARGS(1);

/**
 * configvar_finalize_overrides: figure out which vars were overridden
 * @cvs: the tal_arr of configuration settings.
 *
 * Any non-multi variables are overridden by successive ones.  Sets
 * cv->overridden for each configvar.
 */
void configvar_finalize_overrides(struct configvar **cvs);

/**
 * configvar_remove: remove the last configvar with this name if any.
 * @cvs: pointer to tal_arr of configuration settings.
 * @name: name to remove.
 * @src: source type to remove.
 * @optarg: if non-NULL, the argument to match too.
 *
 * We have to un-override the now-last setting, if any.
 */
void configvar_remove(struct configvar ***cvs,
		      const char *name,
		      enum configvar_src src,
		      const char *optarg)
	NON_NULL_ARGS(1, 2);

/**
 * configvar_first: get the first non-overridden configvar of this name.
 * @cvs: the tal_arr of configuration settings.
 * @names: the tal_arr() of names to look for.
 *
 * Returns NULL if it wasn't set.
 */
struct configvar *configvar_first(struct configvar **cvs, const char **names);

/**
 * configvar_next: get the next non-overridden configvar of same name.
 * @cvs: the tal_arr of configuration settings.
 * @prev: the non-NULL return from configvar_first/configvar_next
 * @names: the tal_arr() of names to look for.
 *
 * This can only return non-NULL for OPT_MULTI options which are actually
 * specified multiple times.
 */
struct configvar *configvar_next(struct configvar **cvs,
				 const struct configvar *prev,
				 const char **names);

#endif /* LIGHTNING_COMMON_CONFIGVAR_H */

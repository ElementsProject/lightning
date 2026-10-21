#ifndef LIGHTNING_CONNECTD_DNS_H
#define LIGHTNING_CONNECTD_DNS_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <stdint.h>

struct timers;
struct wireaddr;

/* What we hand to the callback: exactly one of `addrs` (non-empty, allocated
 * off tmpctx) or `err` (a human-readable string off tmpctx) is set. */
typedef void (*dns_result_cb)(void *cb_arg,
			      const struct wireaddr *addrs,
			      const char *err);

struct dns_lookup;

/*~ Resolve `hostname`:`port` without ever blocking the io loop: the lookup
 * runs in a forked child which reports the results back down a pipe, which
 * we read from the main loop.  cb is called from an io loop callback, once
 * per lookup, as long as @ctx (our parent) is still around: if @ctx is
 * freed first, cb never runs (the child may linger until its own timeout,
 * but its results go nowhere, and having closed every other fd it
 * inherited it holds nothing else open meanwhile).
 *
 * At most DNS_MAX_CONCURRENT_LOOKUPS (10) resolvers run at once: extra
 * lookups queue FIFO and start as earlier children exit.  A lookup not
 * finished within 30 seconds (queueing included) is failed; if it already
 * has a child, that child is killed.  Returns the lookup (a start failure
 * is reported through cb, never by returning NULL). */
struct dns_lookup *async_dns_resolve(const tal_t *ctx,
				     struct timers *timers,
				     const char *hostname,
				     u16 port,
				     dns_result_cb cb,
				     void *cb_arg);
#endif /* LIGHTNING_CONNECTD_DNS_H */

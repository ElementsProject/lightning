#ifndef LIGHTNING_LIGHTNINGD_MEMDUMP_H
#define LIGHTNING_LIGHTNINGD_MEMDUMP_H
#include "config.h"

struct command;
struct subd;
struct subd_req;

struct leak_detect {
	struct command *cmd;
	size_t num_outstanding_requests;
	const char **leakers;
};

/* Start a leak request: decrements num_outstanding_requests when freed. */
void start_leak_request(const struct subd_req *req,
			struct leak_detect *leak_detect);

/* Yep, found a leak in this subd. */
void report_subd_memleak(struct leak_detect *leak_detect, struct subd *leaker);

#endif /* LIGHTNING_LIGHTNINGD_MEMDUMP_H */

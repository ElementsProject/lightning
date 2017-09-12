#ifndef LIGHTNING_COMMON_STATUS_H
#define LIGHTNING_COMMON_STATUS_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

struct daemon_conn;

/* Simple status reporting API. */
void status_setup_sync(int fd);
void status_setup_async(struct daemon_conn *master);

/* Convenient context, frees up after every status_update/failed */
extern const void *trc;

/* Special status code for tracing messages. */
#define STATUS_TRACE 0x7FFF

/* Failure codes always have high bit set. */
#define STATUS_FAIL 0x8000

/* These are always followed by an ASCII string. */
enum status_fail {
	/*
	 * These errors shouldn't happen:
	 */
	/* Master daemon sent unknown/malformed command, or fd failed */
	STATUS_FAIL_MASTER_IO = STATUS_FAIL,

	/* Hsmd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_HSM_IO,

	/* Gossipd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_GOSSIP_IO,

	/* Other internal error. */
	STATUS_FAIL_INTERNAL_ERROR,

	/*
	 * These errors happen when the other peer misbehaves:
	 */
	/* I/O failure (probably they closed the socket) */
	STATUS_FAIL_PEER_IO,
	/* Peer did something else wrong */
	STATUS_FAIL_PEER_BAD
};

/* Send a message (frees the message). */
void status_send_sync(const u8 *msg);
/* Send a printf-style debugging trace. */
void status_trace(const char *fmt, ...) PRINTF_FMT(1,2);
/* Send a failure status code with printf-style msg, and exit. */
void status_failed(enum status_fail, const char *fmt, ...) PRINTF_FMT(2,3) NORETURN;

/* Helper for master failures: sends STATUS_FAIL_MASTER_IO.
 * msg NULL == read failure. */
void master_badmsg(u32 type_expected, const u8 *msg);

#endif /* LIGHTNING_COMMON_STATUS_H */

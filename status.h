#ifndef LIGHTNING_STATUS_H
#define LIGHTNING_STATUS_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

/* Simple status reporting API. */
void status_setup(int fd);

/* Convenient context, frees up after every status_update/failed */
extern const void *trc;

/* Special status code for tracing messages. */
#define STATUS_TRACE 0x7FFF

/* Failure codes always have high bit set. */
#define STATUS_FAIL 0x8000

/* Send a message (frees the message). */
void status_send(const u8 *msg);
/* Send a file descriptor (closes fd). */
void status_send_fd(int fd);
/* Send a printf-style debugging trace. */
void status_trace(const char *fmt, ...) PRINTF_FMT(1,2);
/* Send a failure status code with printf-style msg, and exit. */
void status_failed(u16 code, const char *fmt, ...) PRINTF_FMT(2,3) NORETURN;

#endif /* LIGHTNING_STATUS_H */

/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_TAL_STACK_H
#define CCAN_TAL_STACK_H

#include <ccan/tal/tal.h>

/**
 * tal_newframe - allocate and return a new nested tal context
 *
 * Allocates and push a new tal context on top of the stack.
 * The context must be freed using tal_free() which will also pop it
 * off the stack, which will also free all its nested contextes, if any.
 *
 * NOTE: this function is not threadsafe.
 *
 * Example:
 *	tal_t *ctx = tal_newframe();
 *      // ... do something with ctx ...
 *	tal_free(ctx);
 */
#define tal_newframe(void) tal_newframe_(TAL_LABEL(tal_stack, ""));

tal_t *tal_newframe_(const char *label);

/**
 * tal_curframe - return the current 'tal_stack frame'
 *
 * Returns the context currently on top of the stack. The initial context
 * (before any tal_newframe() call) is the tal 'NULL' context.
 *
 * NOTE: this function is not threadsafe.
 */
tal_t *tal_curframe(void);
#endif /* CCAN_TAL_STACK_H */

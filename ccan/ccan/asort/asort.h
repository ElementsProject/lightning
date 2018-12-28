/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_ASORT_H
#define CCAN_ASORT_H
#include "config.h"
#include <ccan/order/order.h>
#include <stdlib.h>

/**
 * asort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @cmp: pointer to comparison function
 * @ctx: a context pointer for the cmp function
 *
 * This function does a sort on the given array.  The resulting array
 * will be in ascending sorted order by the provided comparison function.
 *
 * The @cmp function should exactly match the type of the @base and
 * @ctx arguments.  Otherwise it can take three const void *.
 */
#define asort(base, num, cmp, ctx)					\
_asort((base), (num), sizeof(*(base)),					\
       total_order_cast((cmp), *(base), (ctx)), (ctx))

#if HAVE_QSORT_R_PRIVATE_LAST
#define _asort(b, n, s, cmp, ctx) qsort_r(b, n, s, cmp, ctx)
#else
void _asort(void *base, size_t nmemb, size_t size,
	    _total_order_cb compar, void *ctx);
#endif

#endif /* CCAN_ASORT_H */

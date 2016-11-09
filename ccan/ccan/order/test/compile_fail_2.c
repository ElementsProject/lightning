#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ccan/order/order.h>

#include "fancy_cmp.h"

#ifdef FAIL
typedef int ctx_t;
#else
typedef struct cmp_info ctx_t;
#endif

int main(void)
{
	total_order_cb(cb0, struct item, struct cmp_info *) = fancy_cmp;
	_total_order_cb cb1 = total_order_cast(fancy_cmp, struct item,
					       ctx_t *);

	printf("%p %p\n", cb0, cb1);

	exit(0);

}

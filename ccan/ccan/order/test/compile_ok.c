#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ccan/order/order.h>

#include "fancy_cmp.h"

int main(void)
{
	total_order_cb(cb0, struct item, struct cmp_info *) = fancy_cmp;
	_total_order_cb cb1 = total_order_cast(fancy_cmp,
					       struct item, struct cmp_info *);
	total_order_noctx_cb cb_noctx = fancy_cmp_noctx;

	printf("%p %p %p\n", cb0, cb1, cb_noctx);

	exit(0);
}

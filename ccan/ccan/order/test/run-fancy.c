#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ccan/order/order.h>

#include <ccan/tap/tap.h>

#include "fancy_cmp.h"

int main(void)
{
	struct item item1 = {
		.value = 0,
		.str = "aaa",
	};
	struct item item2 = {
		.value = 0,
		.str = "abb",
	};
	struct item item3 = {
		.value = 0x1000,
		.str = "baa",
	};
	struct cmp_info ctx1 = {
		.xcode = 0,
		.offset = 0,
	};
	struct cmp_info ctx2 = {
		.xcode = 0x1000,
		.offset = 1,
	};
	total_order(order1, struct item, struct cmp_info *) = {
		fancy_cmp, &ctx1,
	};
	total_order(order2, struct item, struct cmp_info *) = {
		fancy_cmp, &ctx2,
	};

	plan_tests(18);

	ok1(total_order_cmp(order1, &item1, &item1) == 0);
	ok1(total_order_cmp(order1, &item2, &item2) == 0);
	ok1(total_order_cmp(order1, &item3, &item3) == 0);

	ok1(total_order_cmp(order1, &item1, &item2) == -1);
	ok1(total_order_cmp(order1, &item2, &item3) == -1);
	ok1(total_order_cmp(order1, &item1, &item3) == -1);

	ok1(total_order_cmp(order1, &item2, &item1) == 1);
	ok1(total_order_cmp(order1, &item3, &item2) == 1);
	ok1(total_order_cmp(order1, &item3, &item1) == 1);


	ok1(total_order_cmp(order2, &item1, &item1) == 0);
	ok1(total_order_cmp(order2, &item2, &item2) == 0);
	ok1(total_order_cmp(order2, &item3, &item3) == 0);

	ok1(total_order_cmp(order2, &item1, &item2) == 1);
	ok1(total_order_cmp(order2, &item2, &item3) == 1);
	ok1(total_order_cmp(order2, &item1, &item3) == 1);

	ok1(total_order_cmp(order2, &item2, &item1) == -1);
	ok1(total_order_cmp(order2, &item3, &item2) == -1);
	ok1(total_order_cmp(order2, &item3, &item1) == -1);
	
	exit(0);
}

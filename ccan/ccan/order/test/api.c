#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <float.h>
#include <math.h>

#include <ccan/array_size/array_size.h>

#include <ccan/order/order.h>
#include <ccan/tap/tap.h>

#include <ccan/asort/asort.h>

#define QSORT_SCALAR(t, oname, ...)					\
	{								\
		t arr0[] = { __VA_ARGS__ };				\
		const int num = ARRAY_SIZE(arr0);			\
		t arr1[num], arr2[num];					\
		int i;							\
									\
		/* Intialize arr1 in reverse order */			\
		for (i = 0; i < num; i++)				\
			arr1[i] = arr0[num-i-1];			\
									\
		memcpy(arr2, arr1, sizeof(arr1));			\
		qsort(arr2, num, sizeof(t), order_##oname##_noctx);	\
		ok(memcmp(arr2, arr0, sizeof(arr0)) == 0,		\
		   "qsort order_%s_noctx", #oname);			\
									\
		qsort(arr2, num, sizeof(t), order_##oname##_reverse_noctx); \
		ok(memcmp(arr2, arr1, sizeof(arr1)) == 0,		\
		   "qsort order_%s_reverse_noctx", #oname);		\
	}

#define ASORT_SCALAR(t, oname, ...)					\
	{								\
		t arr0[] = { __VA_ARGS__ };				\
		const int num = ARRAY_SIZE(arr0);			\
		t arr1[num], arr2[num];					\
		int i;							\
									\
		/* Intialize arr1 in reverse order */			\
		for (i = 0; i < num; i++)				\
			arr1[i] = arr0[num-i-1];			\
									\
		memcpy(arr2, arr1, sizeof(arr1));			\
		asort(arr2, num, order_##oname, NULL);			\
		ok(memcmp(arr2, arr0, sizeof(arr0)) == 0,		\
		   "asort order_%s", #oname);				\
									\
		asort(arr2, num, order_##oname##_reverse, NULL);	\
		ok(memcmp(arr2, arr1, sizeof(arr1)) == 0,		\
		   "asort order_%s_reverse", #oname);			\
	}

#define ASORT_STRUCT_BY_SCALAR(t, oname, ...)				\
	{								\
		t arrbase[] = { __VA_ARGS__ };				\
		struct tstruct {					\
			char dummy0[5];					\
			t val;						\
			long dummy1;					\
		};							\
		const int num = ARRAY_SIZE(arrbase);			\
		struct tstruct arr0[num], arr1[num], arr2[num];		\
		int i;							\
		total_order_by_field(order, oname, struct tstruct, val); \
		total_order_by_field(rorder, oname##_reverse,		\
				     struct tstruct, val);		\
									\
		/* Set up dummy structures */				\
		memset(arr0, 0, sizeof(arr0));				\
		for (i = 0; i < num; i++) {				\
			arr0[i].dummy1 = i;				\
			strcpy(arr0[i].dummy0, "abc");			\
			arr0[i].val = arrbase[i];			\
		}							\
									\
		/* Intialize arr1 in reverse order */			\
		for (i = 0; i < num; i++)				\
			arr1[i] = arr0[num-i-1];			\
									\
		memcpy(arr2, arr1, sizeof(arr1));			\
		asort(arr2, num, order.cb, order.ctx);			\
		ok(memcmp(arr2, arr0, sizeof(arr0)) == 0,		\
		   "asort by field %s", #oname);			\
									\
		asort(arr2, num, rorder.cb, rorder.ctx);		\
		ok(memcmp(arr2, arr1, sizeof(arr1)) == 0,		\
		   "asort by field %s_reverse", #oname);		\
	}

#define TEST_SCALAR(t, oname, ...)					\
	{								\
		QSORT_SCALAR(t, oname, __VA_ARGS__);			\
		ASORT_SCALAR(t, oname, __VA_ARGS__);			\
		ASORT_STRUCT_BY_SCALAR(t, oname, __VA_ARGS__);		\
	}

int main(void)
{
	/* This is how many tests you plan to run */
	plan_tests(84);

	TEST_SCALAR(int8_t, s8, -128, -4, 0, 1, 2, 88, 126, 127);
	TEST_SCALAR(int16_t, s16, -32768, -4, 0, 1, 2, 88, 126, 32767);
	TEST_SCALAR(int32_t, s32, -2000000000, -4, 0, 1, 2, 88, 126,
		    2000000000);
	TEST_SCALAR(int64_t, s64, -999999999999999999LL, -2000000000, -4, 0,
		    1, 2, 88, 126, 2000000000, 999999999999999999LL);

	TEST_SCALAR(uint8_t, u8, 0, 1, 2, 88, 126, 127, -10, -1);
	TEST_SCALAR(uint16_t, u16, 0, 1, 2, 88, 126, 32767, -10, -1);
	TEST_SCALAR(uint32_t, u32, 0, 1, 2, 88, 126, 2000000000, -10, -1);
	TEST_SCALAR(uint64_t, u64, 0, 1, 2, 88, 126, 2000000000,
		    999999999999999999LL, -10, -1);

	TEST_SCALAR(int, int, INT_MIN, -10, -1, 0, 1, 10, INT_MAX);
	TEST_SCALAR(unsigned, uint, 0, 1, 10, INT_MAX, (unsigned)INT_MAX+1,
		    -10, -1);

	TEST_SCALAR(long, long, LONG_MIN, INT_MIN, -10, -1, 0, 1, 10, INT_MAX,
		    LONG_MAX);
	TEST_SCALAR(unsigned long, ulong, 0, 1, 10, INT_MAX,
		    (unsigned long)INT_MAX+1, LONG_MAX,
		    (unsigned long)LONG_MAX+1, -10, -1);

	TEST_SCALAR(float, float, -INFINITY, -FLT_MAX, -1.0, 0.0, FLT_MIN,
		  0.1, M_E, M_PI, 5.79, FLT_MAX, INFINITY);
	TEST_SCALAR(double, double, -INFINITY, -DBL_MAX, -FLT_MAX, -1.0, 0.0,
		  DBL_MIN, FLT_MIN, 0.1, M_E, M_PI, 5.79, FLT_MAX, DBL_MAX,
		  INFINITY);

	/* This exits depending on whether all tests passed */
	return exit_status();
}

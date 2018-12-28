/* CC0 license (public domain) - see LICENSE file for details */

#include <ccan/order/order.h>

#define SCALAR_ORDER(_oname, _type)					\
	int _order_##_oname(const void *a,				\
			    const void *b,				\
			    void *ctx)					\
	{								\
		ptrdiff_t offset = ptr2int(ctx);			\
		const _type *aa = (const _type *)((char *)a + offset);	\
		const _type *bb = (const _type *)((char *)b + offset);	\
									\
		if (*aa < *bb) {					\
			return -1;					\
		} else if (*aa > *bb) {					\
			return 1;					\
		} else {						\
			assert(*aa == *bb);				\
			return 0;					\
		}							\
	}								\
	int order_##_oname(const _type *a,				\
			   const _type *b,				\
			   void *ctx)					\
	{								\
		(void)ctx; return _order_##_oname(a, b, int2ptr(0));	\
	}								\
	int _order_##_oname##_reverse(const void *a,			\
				      const void *b,			\
				      void *ctx)			\
	{								\
		return -_order_##_oname(a, b, ctx);			\
	}								\
	int order_##_oname##_reverse(const _type *a,			\
				     const _type *b,			\
				     void *ctx)				\
	{								\
		(void)ctx;						\
		return _order_##_oname##_reverse(a, b, int2ptr(0));	\
	}								\
	int order_##_oname##_noctx(const void *a,			\
				   const void *b)			\
	{								\
		return _order_##_oname(a, b, int2ptr(0));		\
	}								\
	int order_##_oname##_reverse_noctx(const void *a,		\
					   const void *b)		\
	{								\
		return _order_##_oname##_reverse(a, b, int2ptr(0));	\
	}

SCALAR_ORDER(s8, int8_t)
SCALAR_ORDER(s16, int16_t)
SCALAR_ORDER(s32, int32_t)
SCALAR_ORDER(s64, int64_t)

SCALAR_ORDER(u8, uint8_t)
SCALAR_ORDER(u16, uint16_t)
SCALAR_ORDER(u32, uint32_t)
SCALAR_ORDER(u64, uint64_t)

SCALAR_ORDER(int, int)
SCALAR_ORDER(uint, unsigned int)
SCALAR_ORDER(long, long)
SCALAR_ORDER(ulong, unsigned long)
SCALAR_ORDER(size, size_t)
SCALAR_ORDER(ptrdiff, ptrdiff_t)

SCALAR_ORDER(float, float)
SCALAR_ORDER(double, double)

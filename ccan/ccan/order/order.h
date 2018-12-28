/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_ORDER_H
#define CCAN_ORDER_H

#include <stdint.h>
#include <assert.h>

#include <ccan/typesafe_cb/typesafe_cb.h>
#include <ccan/ptrint/ptrint.h>

typedef int (*_total_order_cb)(const void *, const void *, void *);
typedef int (*total_order_noctx_cb)(const void *, const void *);

#define total_order_cb(_name, _item, _ctx)		\
	int (*_name)(const __typeof__(_item) *,		\
		     const __typeof__(_item) *,		\
		     __typeof__(_ctx))

#define total_order_cast(cmp, item, ctx)				\
	typesafe_cb_cast(_total_order_cb, total_order_cb(, item, ctx),	\
			 (cmp))

struct _total_order {
	_total_order_cb cb;
	void *ctx;
};

#define total_order(_name, _item, _ctx)			\
	struct {					\
		total_order_cb(cb, _item, _ctx);	\
		_ctx ctx;				\
	} _name

#define total_order_cmp(_order, _a, _b)					\
	((_order).cb((_a), (_b), (_order).ctx))

#define _DECL_ONAME(_oname, _itype)					\
	extern int _order_##_oname(const void *, const void *, void *);	\
	extern int order_##_oname(const _itype *, const _itype *, void *); \
	extern int order_##_oname##_noctx(const void *, const void *);

#define _DECL_ONAME_BIDIR(_oname, _itype)				\
	_DECL_ONAME(_oname, _itype)					\
	_DECL_ONAME(_oname##_reverse, _itype)

_DECL_ONAME_BIDIR(s8, int8_t)
_DECL_ONAME_BIDIR(s16, int16_t)
_DECL_ONAME_BIDIR(s32, int32_t)
_DECL_ONAME_BIDIR(s64, int64_t)

_DECL_ONAME_BIDIR(u8, uint8_t)
_DECL_ONAME_BIDIR(u16, uint16_t)
_DECL_ONAME_BIDIR(u32, uint32_t)
_DECL_ONAME_BIDIR(u64, uint64_t)

_DECL_ONAME_BIDIR(int, int)
_DECL_ONAME_BIDIR(uint, unsigned int)
_DECL_ONAME_BIDIR(long, long)
_DECL_ONAME_BIDIR(ulong, unsigned long)
_DECL_ONAME_BIDIR(size, size_t)
_DECL_ONAME_BIDIR(ptrdiff, ptrdiff_t)

_DECL_ONAME_BIDIR(float, float)
_DECL_ONAME_BIDIR(double, double)

#undef _DECL_ONAME
#undef _DECL_ONAME_BIDIR

#define total_order_by_field(_name, _oname, _itype, _field)		\
	total_order(_name, _itype, ptrint_t *) = {			\
		(total_order_cb(, _itype,				\
				ptrint_t *))(_order_##_oname),		\
		int2ptr(offsetof(_itype, _field)),			\
	}

#endif /* CCAN_ORDER_H */

/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_CAST_H
#define CCAN_CAST_H
#include "config.h"
#include <stdint.h>
#include <ccan/build_assert/build_assert.h>

/**
 * cast_signed - cast a (const) char * to/from (const) signed/unsigned char *.
 * @type: some char * variant.
 * @expr: expression (of some char * variant) to cast.
 *
 * Some libraries insist on an unsigned char in various places; cast_signed
 * makes sure (with suitable compiler) that the expression you are casting
 * only differs in signed/unsigned, not in type or const-ness.
 */
#define cast_signed(type, expr)						\
	(0 ? BUILD_ASSERT_OR_ZERO(cast_sign_compatible(type, (expr))) :	\
	 (type)(expr))

/**
 * cast_const - remove a const qualifier from a pointer.
 * @type: some pointer type.
 * @expr: expression to cast.
 *
 * This ensures that you are only removing the const qualifier from an
 * expression.  The expression must otherwise match @type.
 *
 * We cast via intptr_t to suppress gcc's -Wcast-qual (which SAMBA
 * uses), and via the ? : so Sun CC doesn't complain about the result
 * not being constant.
 *
 * If @type is a pointer to a pointer, you must use cast_const2 (etc).
 *
 * Example:
 *	// Dumb open-coded strstr variant.
 *	static char *find_needle(const char *haystack)
 *	{
 *		size_t i;
 *		for (i = 0; i < strlen(haystack); i++)
 *		if (memcmp("needle", haystack+i, strlen("needle")) == 0)
 *			return cast_const(char *, haystack+i);
 *		return NULL;
 *	}
 */
#define cast_const(type, expr)						\
        (0 ? BUILD_ASSERT_OR_ZERO(cast_const_compat1((expr), type)) :   \
         (type)(intptr_t)(expr))

/**
 * cast_const2 - remove a const qualifier from a pointer to a pointer.
 * @type: some pointer to pointer type.
 * @expr: expression to cast.
 *
 * This ensures that you are only removing the const qualifier from an
 * expression.  The expression must otherwise match @type.
 */
#define cast_const2(type, expr)						\
        (0 ? BUILD_ASSERT_OR_ZERO(cast_const_compat2((expr), type)) :   \
	 (type)(intptr_t)(expr))

/**
 * cast_const3 - remove a const from a pointer to a pointer to a pointer..
 * @type: some pointer to pointer to pointer type.
 * @expr: expression to cast.
 *
 * This ensures that you are only removing the const qualifier from an
 * expression.  The expression must otherwise match @type.
 */
#define cast_const3(type, expr)						\
        (0 ? BUILD_ASSERT_OR_ZERO(cast_const_compat3((expr), type)) :   \
	 (type)(intptr_t)(expr))


/**
 * cast_static - explicit mimic of implicit cast.
 * @type: some type.
 * @expr: expression to cast.
 *
 * This ensures that the cast is not to or from a pointer: it can only be
 * an implicit cast, such as a pointer to a similar const pointer, or between
 * integral types.
 */
#if HAVE_COMPOUND_LITERALS
#define cast_static(type, expr)			\
	((struct { type x; }){(expr)}.x)
#else
#define cast_static(type, expr)			\
	((type)(expr))
#endif

/* Herein lies the gcc magic to evoke compile errors. */
#if HAVE_BUILTIN_CHOOSE_EXPR && HAVE_BUILTIN_TYPES_COMPATIBLE_P && HAVE_TYPEOF
#define cast_sign_compatible(t, e) \
  __builtin_choose_expr(						\
	  __builtin_types_compatible_p(__typeof__(t), char *) ||	\
	  __builtin_types_compatible_p(__typeof__(t), signed char *) || \
	  __builtin_types_compatible_p(__typeof__(t), unsigned char *), \
	  /* if type is not const qualified */				\
	  __builtin_types_compatible_p(__typeof__(e), char *) ||	\
	  __builtin_types_compatible_p(__typeof__(e), signed char *) || \
	  __builtin_types_compatible_p(__typeof__(e), unsigned char *), \
	  /* and if it is... */						\
	  __builtin_types_compatible_p(__typeof__(e), const char *) ||	\
	  __builtin_types_compatible_p(__typeof__(e), const signed char *) || \
	  __builtin_types_compatible_p(__typeof__(e), const unsigned char *) ||\
	  __builtin_types_compatible_p(__typeof__(e), char *) ||	\
	  __builtin_types_compatible_p(__typeof__(e), signed char *) ||	\
	  __builtin_types_compatible_p(__typeof__(e), unsigned char *)	\
	  )

#define cast_const_strip1(expr)			\
	__typeof__(*(union { int z; __typeof__(expr) x; }){0}.x)
#define cast_const_strip2(expr) \
	__typeof__(**(union { int z; __typeof__(expr) x; }){0}.x)
#define cast_const_strip3(expr) \
	__typeof__(***(union { int z; __typeof__(expr) x; }){0}.x)
#define cast_const_compat1(expr, type)					\
	__builtin_types_compatible_p(cast_const_strip1(expr),		\
				     cast_const_strip1(type))
#define cast_const_compat2(expr, type)					\
	__builtin_types_compatible_p(cast_const_strip2(expr),		\
				     cast_const_strip2(type))
#define cast_const_compat3(expr, type)					\
	__builtin_types_compatible_p(cast_const_strip3(expr),		\
				     cast_const_strip3(type))
#else
#define cast_sign_compatible(type, expr)		\
	(sizeof(*(type)0) == 1 && sizeof(*(expr)) == 1)
#define cast_const_compat1(expr, type)		(1)
#define cast_const_compat2(expr, type)		(1)
#define cast_const_compat3(expr, type)		(1)
#endif
#endif /* CCAN_CAST_H */

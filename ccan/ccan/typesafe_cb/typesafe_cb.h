/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_TYPESAFE_CB_H
#define CCAN_TYPESAFE_CB_H
#include "config.h"

#if HAVE_TYPEOF && HAVE_BUILTIN_CHOOSE_EXPR && HAVE_BUILTIN_TYPES_COMPATIBLE_P
/**
 * typesafe_cb_cast - only cast an expression if it matches a given type
 * @desttype: the type to cast to
 * @oktype: the type we allow
 * @expr: the expression to cast
 *
 * This macro is used to create functions which allow multiple types.
 * The result of this macro is used somewhere that a @desttype type is
 * expected: if @expr is exactly of type @oktype, then it will be
 * cast to @desttype type, otherwise left alone.
 *
 * This macro can be used in static initializers.
 *
 * This is merely useful for warnings: if the compiler does not
 * support the primitives required for typesafe_cb_cast(), it becomes an
 * unconditional cast, and the @oktype argument is not used.  In
 * particular, this means that @oktype can be a type which uses the
 * "typeof": it will not be evaluated if typeof is not supported.
 *
 * Example:
 *	// We can take either an unsigned long or a void *.
 *	void _set_some_value(void *val);
 *	#define set_some_value(e)			\
 *		_set_some_value(typesafe_cb_cast(void *, unsigned long, (e)))
 */
#define typesafe_cb_cast(desttype, oktype, expr)			\
	__builtin_choose_expr(						\
		__builtin_types_compatible_p(__typeof__(0?(expr):(expr)), \
					     oktype),			\
		(desttype)(expr), (expr))
#else
#define typesafe_cb_cast(desttype, oktype, expr) ((desttype)(expr))
#endif

/**
 * typesafe_cb_cast3 - only cast an expression if it matches given types
 * @desttype: the type to cast to
 * @ok1: the first type we allow
 * @ok2: the second type we allow
 * @ok3: the third type we allow
 * @expr: the expression to cast
 *
 * This is a convenient wrapper for multiple typesafe_cb_cast() calls.
 * You can chain them inside each other (ie. use typesafe_cb_cast()
 * for expr) if you need more than 3 arguments.
 *
 * Example:
 *	// We can take either a long, unsigned long, void * or a const void *.
 *	void _set_some_value(void *val);
 *	#define set_some_value(expr)					\
 *		_set_some_value(typesafe_cb_cast3(void *,,		\
 *					    long, unsigned long, const void *,\
 *					    (expr)))
 */
#define typesafe_cb_cast3(desttype, ok1, ok2, ok3, expr)		\
	typesafe_cb_cast(desttype, ok1,					\
			 typesafe_cb_cast(desttype, ok2,		\
					  typesafe_cb_cast(desttype, ok3, \
							   (expr))))

/**
 * typesafe_cb - cast a callback function if it matches the arg
 * @rtype: the return type of the callback function
 * @atype: the (pointer) type which the callback function expects.
 * @fn: the callback function to cast
 * @arg: the (pointer) argument to hand to the callback function.
 *
 * If a callback function takes a single argument, this macro does
 * appropriate casts to a function which takes a single atype argument if the
 * callback provided matches the @arg.
 *
 * It is assumed that @arg is of pointer type: usually @arg is passed
 * or assigned to a void * elsewhere anyway.
 *
 * Example:
 *	void _register_callback(void (*fn)(void *arg), void *arg);
 *	#define register_callback(fn, arg) \
 *		_register_callback(typesafe_cb(void, (fn), void*, (arg)), (arg))
 */
#define typesafe_cb(rtype, atype, fn, arg)			\
	typesafe_cb_cast(rtype (*)(atype),			\
			 rtype (*)(__typeof__(arg)),		\
			 (fn))

/**
 * typesafe_cb_preargs - cast a callback function if it matches the arg
 * @rtype: the return type of the callback function
 * @atype: the (pointer) type which the callback function expects.
 * @fn: the callback function to cast
 * @arg: the (pointer) argument to hand to the callback function.
 *
 * This is a version of typesafe_cb() for callbacks that take other arguments
 * before the @arg.
 *
 * Example:
 *	void _register_callback(void (*fn)(int, void *arg), void *arg);
 *	#define register_callback(fn, arg)				   \
 *		_register_callback(typesafe_cb_preargs(void, void *,	   \
 *				   (fn), (arg), int),			   \
 *				   (arg))
 */
#define typesafe_cb_preargs(rtype, atype, fn, arg, ...)			\
	typesafe_cb_cast(rtype (*)(__VA_ARGS__, atype),			\
			 rtype (*)(__VA_ARGS__, __typeof__(arg)),	\
			 (fn))

/**
 * typesafe_cb_postargs - cast a callback function if it matches the arg
 * @rtype: the return type of the callback function
 * @atype: the (pointer) type which the callback function expects.
 * @fn: the callback function to cast
 * @arg: the (pointer) argument to hand to the callback function.
 *
 * This is a version of typesafe_cb() for callbacks that take other arguments
 * after the @arg.
 *
 * Example:
 *	void _register_callback(void (*fn)(void *arg, int), void *arg);
 *	#define register_callback(fn, arg) \
 *		_register_callback(typesafe_cb_postargs(void, (fn), void *, \
 *				   (arg), int),				    \
 *				   (arg))
 */
#define typesafe_cb_postargs(rtype, atype, fn, arg, ...)		\
	typesafe_cb_cast(rtype (*)(atype, __VA_ARGS__),			\
			 rtype (*)(__typeof__(arg), __VA_ARGS__),	\
			 (fn))
#endif /* CCAN_CAST_IF_TYPE_H */

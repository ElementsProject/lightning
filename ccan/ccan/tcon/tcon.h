/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_TCON_H
#define CCAN_TCON_H
#include "config.h"

#include <stddef.h>

/**
 * TCON - declare a _tcon type containing canary variables.
 * @decls: the semi-colon separated list of type canaries.
 *
 * This declares a _tcon member for a structure.  It should be the
 * last element in your structure; with sufficient compiler support it
 * will not use any actual storage.  tcon_check() will compare
 * expressions with one of these "type canaries" to cause warnings if
 * the container is misused.
 *
 * A type of "void *" will allow tcon_check() to pass on any (pointer) type.
 *
 * Example:
 *	// Simply typesafe linked list.
 *	struct list_head {
 *		struct list_head *prev, *next;
 *	};
 *
 *	struct string_list {
 *		struct list_head raw;
 *		TCON(char *canary);
 *	};
 *
 *	// More complex: mapping from one type to another.
 *	struct map {
 *		void *contents;
 *	};
 *
 *	struct int_to_string_map {
 *		struct map raw;
 *		TCON(char *charp_canary; int int_canary);
 *	};
 */
#if HAVE_FLEXIBLE_ARRAY_MEMBER
#define TCON(decls) struct { decls; } _tcon[]
#else
#define TCON(decls) struct { decls; } _tcon[1]
#endif

/**
 * TCON_WRAP - declare a wrapper type containing a base type and type canaries
 * @basetype: the base type to wrap
 * @decls: the semi-colon separated list of type canaries.
 *
 * This expands to a new type which includes the given base type, and
 * also type canaries, similar to those created with TCON.
 *
 * The embedded base type value can be accessed using tcon_unwrap().
 *
 * Differences from using TCON()
 * - The wrapper type will take either the size of the base type, or
 *   the size of a single pointer, whichever is greater (regardless of
 *   compiler)
 * - A TCON_WRAP type may be included in another structure, and need
 *   not be the last element.
 *
 * A type of "void *" will allow tcon_check() to pass on any (pointer) type.
 *
 * Example:
 *	// Simply typesafe linked list.
 *	struct list_head {
 *		struct list_head *prev, *next;
 *	};
 *
 *	typedef TCON_WRAP(struct list_head, char *canary) string_list_t;
 *
 *	// More complex: mapping from one type to another.
 *	struct map {
 *		void *contents;
 *	};
 *
 *	typedef TCON_WRAP(struct map, char *charp_canary; int int_canary)
 *		int_to_string_map_t;
 */
#define TCON_WRAP(basetype, decls) \
	union {			   \
		basetype _base;	   \
		struct {	   \
			decls;	   \
		} *_tcon;	   \
	}

/**
 * TCON_WRAP_INIT - an initializer for a variable declared with TCON_WRAP
 * @...: Initializer for the base type (treated as variadic so commas
 *       can be included)
 *
 * Converts converts an initializer suitable for a base type into one
 * suitable for that type wrapped with TCON_WRAP.
 *
 * Example:
 *	TCON_WRAP(int, char *canary) canaried_int = TCON_WRAP_INIT(17);
 */
#define TCON_WRAP_INIT(...)			\
	{ ._base = __VA_ARGS__, }

/**
 * tcon_unwrap - Access the base type of a TCON_WRAP
 * @ptr: pointer to an object declared with TCON_WRAP
 *
 * tcon_unwrap() returns a pointer to the base type of the TCON_WRAP()
 * object pointer to by @ptr.
 *
 * Example:
 *	TCON_WRAP(int, char *canary) canaried_int;
 *
 *	*tcon_unwrap(&canaried_int) = 17;
 */
#define tcon_unwrap(ptr) (&((ptr)->_base))

/**
 * tcon_check - typecheck a typed container
 * @x: the structure containing the TCON.
 * @canary: which canary to check against.
 * @expr: the expression whose type must match the TCON (not evaluated)
 *
 * This macro is used to check that the expression is the type
 * expected for this structure (note the "useless" sizeof() argument
 * which contains this comparison with the type canary).
 *
 * It evaluates to @x so you can chain it.
 *
 * Example:
 *	#define tlist_add(h, n, member) \
 *		list_add(&tcon_check((h), canary, (n))->raw, &(n)->member)
 */
#define tcon_check(x, canary, expr)				\
	(sizeof((x)->_tcon[0].canary == (expr)) ? (x) : (x))

/**
 * tcon_check_ptr - typecheck a typed container
 * @x: the structure containing the TCON.
 * @canary: which canary to check against.
 * @expr: the expression whose type must match &TCON (not evaluated)
 *
 * This macro is used to check that the expression is a pointer to the type
 * expected for this structure (note the "useless" sizeof() argument
 * which contains this comparison with the type canary), or NULL.
 *
 * It evaluates to @x so you can chain it.
 */
#define tcon_check_ptr(x, canary, expr)				\
	(sizeof(&(x)->_tcon[0].canary == (expr)) ? (x) : (x))


/**
 * tcon_type - the type within a container (or void *)
 * @x: the structure containing the TCON.
 * @canary: which canary to check against.
 */
#if HAVE_TYPEOF
#define tcon_type(x, canary) __typeof__((x)->_tcon[0].canary)
#else
#define tcon_type(x, canary) void *
#endif

/**
 * tcon_sizeof - the size of type within a container
 * @x: the structure containing the TCON.
 * @canary: which canary to check against.
 */
#define tcon_sizeof(x, canary) sizeof((x)->_tcon[0].canary)

/**
 * TCON_VALUE - encode an integer value in a type canary
 * @canary: name of the value canary
 * @val: positive integer compile time constant value
 *
 * This macro can be included inside the declarations in a TCON() or
 * TCON_WRAP(), constructing a special "type" canary which encodes the
 * integer value @val (which must be a compile time constant, and a
 * positive integer in the range of size_t).
 */
#define TCON_VALUE(canary, val)	char _value_##canary[val]

/**
 * tcon_value - retrieve the value of a TCON_VALUE canary
 * @x: the structure containing the TCON
 * @canary: name of the value canary
 *
 * This macros expands to the value previously encoded into a TCON
 * using TCON_VALUE().
 */
#define tcon_value(x, canary)	tcon_sizeof(x, _value_##canary)

/**
 * tcon_ptr_type - pointer to the type within a container (or void *)
 * @x: the structure containing the TCON.
 * @canary: which canary to check against.
 */
#if HAVE_TYPEOF
#define tcon_ptr_type(x, canary) __typeof__(&(x)->_tcon[0].canary)
#else
#define tcon_ptr_type(x, canary) void *
#endif

/**
 * tcon_cast - cast to a canary type for this container (or void *)
 * @x: a structure containing the TCON.
 * @canary: which canary to cast to.
 * @expr: the value to cast
 *
 * This is used to cast to the correct type for this container.  If the
 * platform doesn't HAVE_TYPEOF, then it casts to void * (which will
 * cause a warning if the user doesn't expect a pointer type).
 */
#define tcon_cast(x, canary, expr) ((tcon_type((x), canary))(expr))
#define tcon_cast_ptr(x, canary, expr) ((tcon_ptr_type((x), canary))(expr))

/**
 * TCON_CONTAINER - encode information on a specific member of a
 *                  containing structure into a "type" canary
 * @canary: name of the container canary
 * @container: type of the container structure
 * @member: name of the member
 *
 * Used in the declarations in TCON() or TCON_WRAP(), encode a
 * "container canary".  This encodes the type of @container, the type
 * of @member within it (with sufficient compiler support) and the
 * offset of @member within @container.
 */
#if HAVE_TYPEOF
#define TCON_CONTAINER(canary, container, member)			\
	container _container_##canary;					\
	typeof(((container *)0)->member) _member_##canary;		\
	TCON_VALUE(_offset_##canary, offsetof(container, member))
#else
#define TCON_CONTAINER(canary, container, member)			\
	container _container_##canary;					\
	TCON_VALUE(_offset_##canary, offsetof(container, member))
#endif

/**
 * tcon_container_check
 * tcon_container_check_ptr
 * tcon_container_type
 * tcon_container_ptr_type
 * tcon_container_sizeof
 * tcon_container_cast
 * tcon_container_cast_ptr
 * @x: the structure containing the TCON.
 * @canary: which container canary to check against.
 *
 * As tcon_check / tcon_check_ptr / tcon_type / tcon_ptr_type /
 * tcon_sizeof / tcon_cast / tcon_cast_ptr, but use the type of the
 * "container" type declared with TCON_CONTAINER, instead of a simple
 * canary.
 */
#define tcon_container_check(x, canary, expr)		\
	tcon_check(x, _container_##canary, expr)
#define tcon_container_check_ptr(x, canary, expr)	\
	tcon_check_ptr(x, _container_##canary, expr)
#define tcon_container_type(x, canary)		\
	tcon_type(x, _container_##canary)
#define tcon_container_ptr_type(x, canary)	\
	tcon_ptr_type(x, _container_##canary)
#define tcon_container_sizeof(x, canary)	\
	tcon_sizeof(x, _container_##canary)
#define tcon_container_cast(x, canary, expr)	\
	tcon_cast(x, _container_##canary, expr)
#define tcon_container_cast_ptr(x, canary, expr)	\
	tcon_cast_ptr(x, _container_##canary, expr)

/**
 * tcon_member_check
 * tcon_member_check_ptr
 * tcon_member_type
 * tcon_member_ptr_type
 * tcon_member_sizeof
 * tcon_member_cast
 * tcon_member_cast_ptr
 * @x: the structure containing the TCON.
 * @canary: which container canary to check against.
 *
 * As tcon_check / tcon_check_ptr / tcon_type / tcon_ptr_type /
 * tcon_sizeof / tcon_cast / tcon_cast_ptr, but use the type of the
 * "member" type declared with TCON_CONTAINER, instead of a simple
 * canary.
 */
#define tcon_member_check(x, canary, expr)	\
	tcon_check(x, _member_##canary, expr)
#define tcon_member_check_ptr(x, canary, expr)		\
	tcon_check_ptr(x, _member_##canary, expr)
#define tcon_member_type(x, canary)		\
	tcon_type(x, _member_##canary)
#define tcon_member_ptr_type(x, canary)	\
	tcon_ptr_type(x, _member_##canary)
#define tcon_member_sizeof(x, canary)	\
	tcon_sizeof(x, _member_##canary)
#define tcon_member_cast(x, canary, expr)	\
	tcon_cast(x, _member_##canary, expr)
#define tcon_member_cast_ptr(x, canary, expr)	\
	tcon_cast_ptr(x, _member_##canary, expr)

/**
 * tcon_offset - the offset of a member within a container, as
 *               declared with TCON_CONTAINER
 * @x: the structure containing the TCON.
 * @canary: which container canary to check against.
 */
#define tcon_offset(x, canary)			\
	tcon_value((x), _offset_##canary)

/**
 * tcon_container_of - get pointer to enclosing structure based on a
 *                     container canary
 * @x: the structure containing the TCON
 * @canary: the name of the container canary
 * @member_ptr: pointer to a member of the container
 *
 * @member_ptr must be a pointer to the member of a container
 * structure previously recorded in @canary with TCON_CONTAINER.
 *
 * tcon_container_of() evaluates to a pointer to the container
 * structure.  With sufficient compiler support, the pointer will be
 * correctly typed, and the type of @member_ptr will be verified.
 * Note that const is discarded; a const @member_ptr still yields a
 * non-const container (unless @canary is const).
 *
 * Returns NULL if @member_ptr is NULL.
 */
#define tcon_container_of(x, canary, member_ptr)			\
	tcon_container_cast_ptr(					\
		tcon_member_check_ptr((x), canary, (member_ptr)),	\
		canary, tcon_container_of_((member_ptr),		\
					   tcon_offset((x), canary)))

static inline void *tcon_container_of_(const void *member_ptr, size_t offset)
{
	return member_ptr ? (char *)member_ptr - offset : NULL;
}


/**
 * tcon_member_of - get pointer to enclosed member structure based on a
 *                  container canary
 * @x: the structure containing the TCON
 * @canary: the name of the container canary
 * @container_ptr: pointer to a container
 *
 * @container_ptr must be a pointer to a container structure
 * previously recorded in @canary with TCON_CONTAINER.
 *
 * tcon_member_of() evaluates to a pointer to the member of the
 * container recorded in @canary. With sufficient compiler support,
 * the pointer will be correctly typed, and the type of @container_ptr
 * will be verified.
 *
 * Returns NULL if @container_ptr is NULL.
 */
#define tcon_member_of(x, canary, container_ptr)			\
	tcon_member_cast_ptr(						\
		tcon_container_check_ptr((x), canary, (container_ptr)),	\
		canary, tcon_member_of_((container_ptr),		\
					tcon_offset((x), canary)))
static inline void *tcon_member_of_(void *container_ptr, size_t offset)
{
	return container_ptr ? (char *)container_ptr + offset : NULL;
}


#endif /* CCAN_TCON_H */

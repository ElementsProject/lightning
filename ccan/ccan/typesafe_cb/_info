#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * typesafe_cb - macros for safe callbacks.
 *
 * The basis of the typesafe_cb header is typesafe_cb_cast(): a
 * conditional cast macro.   If an expression exactly matches a given
 * type, it is cast to the target type, otherwise it is left alone.
 *
 * This allows us to create functions which take a small number of
 * specific types, rather than being forced to use a void *.  In
 * particular, it is useful for creating typesafe callbacks as the
 * helpers typesafe_cb(), typesafe_cb_preargs() and
 * typesafe_cb_postargs() demonstrate.
 * 
 * The standard way of passing arguments to callback functions in C is
 * to use a void pointer, which the callback then casts back to the
 * expected type.  This unfortunately subverts the type checking the
 * compiler would perform if it were a direct call.  Here's an example:
 *
 *	static void my_callback(void *_obj)
 *	{
 *		struct obj *obj = _obj;
 *		...
 *	}
 *	...
 *		register_callback(my_callback, &my_obj);
 *
 * If we wanted to use the natural type for my_callback (ie. "void
 * my_callback(struct obj *obj)"), we could make register_callback()
 * take a void * as its first argument, but this would subvert all
 * type checking.  We really want register_callback() to accept only
 * the exactly correct function type to match the argument, or a
 * function which takes a void *.
 *
 * This is where typesafe_cb() comes in: it uses typesafe_cb_cast() to
 * cast the callback function if it matches the argument type:
 *
 *	void _register_callback(void (*cb)(void *arg), void *arg);
 *	#define register_callback(cb, arg)				\
 *		_register_callback(typesafe_cb(void, void *, (cb), (arg)), \
 *				   (arg))
 *
 * On compilers which don't support the extensions required
 * typesafe_cb_cast() and friend become an unconditional cast, so your
 * code will compile but you won't get type checking.
 *
 * Example:
 *	#include <ccan/typesafe_cb/typesafe_cb.h>
 *	#include <stdlib.h>
 *	#include <stdio.h>
 *
 *	// Generic callback infrastructure.
 *	struct callback {
 *		struct callback *next;
 *		int value;
 *		int (*callback)(int value, void *arg);
 *		void *arg;
 *	};
 *	static struct callback *callbacks;
 *	
 *	static void _register_callback(int value, int (*cb)(int, void *),
 *				       void *arg)
 *	{
 *		struct callback *new = malloc(sizeof(*new));
 *		new->next = callbacks;
 *		new->value = value;
 *		new->callback = cb;
 *		new->arg = arg;
 *		callbacks = new;
 *	}
 *	#define register_callback(value, cb, arg)			\
 *		_register_callback(value,				\
 *				   typesafe_cb_preargs(int, void *,	\
 *						       (cb), (arg), int),\
 *				   (arg))
 *	
 *	static struct callback *find_callback(int value)
 *	{
 *		struct callback *i;
 *	
 *		for (i = callbacks; i; i = i->next)
 *			if (i->value == value)
 *				return i;
 *		return NULL;
 *	}   
 *
 *	// Define several silly callbacks.  Note they don't use void *!
 *	#define DEF_CALLBACK(name, op)			\
 *		static int name(int val, int *arg)	\
 *		{					\
 *			printf("%s", #op);		\
 *			return val op *arg;		\
 *		}
 *	DEF_CALLBACK(multiply, *);
 *	DEF_CALLBACK(add, +);
 *	DEF_CALLBACK(divide, /);
 *	DEF_CALLBACK(sub, -);
 *	DEF_CALLBACK(or, |);
 *	DEF_CALLBACK(and, &);
 *	DEF_CALLBACK(xor, ^);
 *	DEF_CALLBACK(assign, =);
 *
 *	// Silly game to find the longest chain of values.
 *	int main(int argc, char *argv[])
 *	{
 *		int i, run = 1, num = argc > 1 ? atoi(argv[1]) : 0;
 *	
 *		for (i = 1; i < 1024;) {
 *			// Since run is an int, compiler checks "add" does too.
 *			register_callback(i++, add, &run);
 *			register_callback(i++, divide, &run);
 *			register_callback(i++, sub, &run);
 *			register_callback(i++, multiply, &run);
 *			register_callback(i++, or, &run);
 *			register_callback(i++, and, &run);
 *			register_callback(i++, xor, &run);
 *			register_callback(i++, assign, &run);
 *		}
 *	
 *		printf("%i ", num);
 *		while (run < 56) {
 *			struct callback *cb = find_callback(num % i);
 *			if (!cb) {
 *				printf("-> STOP\n");
 *				return 1;
 *			}
 *			num = cb->callback(num, cb->arg);
 *			printf("->%i ", num);
 *			run++;
 *		}
 *		printf("-> Winner!\n");
 *		return 0;
 *	}
 *
 * License: CC0 (Public domain)
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */
int main(int argc, char *argv[])
{
	if (argc != 2)
		return 1;

	if (strcmp(argv[1], "depends") == 0) {
		return 0;
	}

	return 1;
}

// Licensed under BSD-MIT: See LICENSE.
#ifndef CCAN_AUTODATA_H
#define CCAN_AUTODATA_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <stdlib.h>

#if HAVE_SECTION_START_STOP

/**
 * AUTODATA_TYPE - declare the type for a given autodata name.
 * @name: the name for this set of autodata
 * @type: the type this autodata points to
 *
 * This macro is usually placed in a header: it must preceed any
 * autodata functions in the file.
 *
 * Example:
 *	#include <ccan/autodata/autodata.h>
 *
 *	// My set of char pointers.
 *	AUTODATA_TYPE(names, char);
 */
#define AUTODATA_TYPE(name, type)					\
	typedef type autodata_##name##_;				\
	extern type *__start_xautodata_##name[], *__stop_xautodata_##name[]

/**
 * AUTODATA - add a pointer to this autodata set
 * @name: the name of the set of autodata
 * @ptr: the compile-time-known pointer
 *
 * This embeds @ptr into the binary, with the tag corresponding to
 * @name (which must look like a valid identifier, no punctuation!).
 * The type of @ptr must match that given by AUTODATA_TYPE.  It is
 * usually a file-level declaration.
 *
 * Example:
 *	// Put two char pointers into the names AUTODATA set.
 *	AUTODATA(names, "Arabella");
 *	AUTODATA(names, "Alex");
 */
#define AUTODATA(name, ptr) \
	static const autodata_##name##_ *NEEDED		\
	__attribute__((section("xautodata_" #name)))	\
	AUTODATA_VAR_(name, __LINE__) = (ptr);

/**
 * autodata_get - get an autodata set
 * @name: the name of the set of autodata
 * @nump: the number of items in the set.
 *
 * This extract the embedded pointers matching @name.  It may fail
 * if malloc() fails, or if there is no AUTODATA at all.
 *
 * The return will be a pointer to an array of @type pointers (from
 * AUTODATA_TYPE).
 *
 * Example:
 *	static void print_embedded_names(void)
 *	{
 *		unsigned int i;
 *		size_t num;
 *		char **n = autodata_get(names, &num);
 *
 *		for (i = 0; i < num; i++)
 *			printf("%s\n", n[i]);
 *	}
 */
#define autodata_get(name, nump)					\
	((autodata_##name##_ **)					\
	 autodata_get_section(__start_xautodata_##name,			\
			      __stop_xautodata_##name, (nump)))
#endif /* HAVE_SECTION_START_STOP */

/**
 * autodata_free - free the table returned by autodata_get()
 * @p: the table.
 */
void autodata_free(void *p);

/* Internal functions. */
#define AUTODATA_VAR__(name, line) autodata_##name##_##line
#define AUTODATA_VAR_(name, line) AUTODATA_VAR__(name, line)

#if HAVE_SECTION_START_STOP
void *autodata_get_section(void *start, void *stop, size_t *nump);
#else
#define AUTODATA_TYPE(name, type)					\
	typedef type autodata_##name##_;				\
	static const void *autodata_##name##_ex = &autodata_##name##_ex

#define AUTODATA_MAGIC ((long)0xFEEDA10DA7AF00D5ULL)
#define AUTODATA(name, ptr)						\
	static const autodata_##name##_ *NEEDED				\
	AUTODATA_VAR_(name, __LINE__)[4] =				\
	{ (void *)AUTODATA_MAGIC,					\
	  (void *)&AUTODATA_VAR_(name, __LINE__),			\
	  (ptr),							\
	  (void *)#name }

#define autodata_get(name, nump)					\
	((autodata_##name##_ **)					\
	 autodata_make_table(&autodata_##name##_ex, #name, (nump)))

void *autodata_make_table(const void *example, const char *name, size_t *nump);
#endif

#endif /* CCAN_AUTODATA_H */

/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_STR_TAL_H
#define CCAN_STR_TAL_H
#ifdef TAL_USE_TALLOC
#include <ccan/tal/talloc/talloc.h>
#else
#include <ccan/tal/tal.h>
#endif
#include <string.h>
#include <stdbool.h>

/**
 * tal_strdup - duplicate a string
 * @ctx: NULL, or tal allocated object to be parent.
 * @p: the string to copy (can be take(), must not be NULL).
 *
 * The returned string will have tal_count() == strlen() + 1.
 */
#define tal_strdup(ctx, p) tal_strdup_(ctx, p, TAL_LABEL(char, "[]"))
char *tal_strdup_(const tal_t *ctx, const char *p TAKES, const char *label)
	TAL_RETURN_PTR NON_NULL_ARGS(2);

/**
 * tal_strndup - duplicate a limited amount of a string.
 * @ctx: NULL, or tal allocated object to be parent.
 * @p: the string to copy (can be take(), must not be NULL).
 * @n: the maximum length to copy.
 *
 * Always gives a nul-terminated string, with strlen() <= @n.
 * The returned string will have tal_count() == strlen() + 1.
 */
#define tal_strndup(ctx, p, n) tal_strndup_(ctx, p, n, TAL_LABEL(char, "[]"))
char *tal_strndup_(const tal_t *ctx, const char *p TAKES, size_t n,
		   const char *label)
	TAL_RETURN_PTR NON_NULL_ARGS(2);

/**
 * tal_fmt - allocate a formatted string
 * @ctx: NULL, or tal allocated object to be parent.
 * @fmt: the printf-style format (can be take(), must not be NULL).
 *
 * The returned string will have tal_count() == strlen() + 1.
 */
#define tal_fmt(ctx, ...)				 \
	tal_fmt_(ctx, TAL_LABEL(char, "[]"), __VA_ARGS__)
char *tal_fmt_(const tal_t *ctx, const char *label, const char *fmt TAKES,
	       ...) PRINTF_FMT(3,4) TAL_RETURN_PTR NON_NULL_ARGS(3);

/**
 * tal_vfmt - allocate a formatted string (va_list version)
 * @ctx: NULL, or tal allocated object to be parent.
 * @fmt: the printf-style format (can be take(), must not be NULL).
 * @va: the va_list containing the format args.
 *
 * The returned string will have tal_count() == strlen() + 1.
 */
#define tal_vfmt(ctx, fmt, va)				\
	tal_vfmt_(ctx, fmt, va, TAL_LABEL(char, "[]"))
char *tal_vfmt_(const tal_t *ctx, const char *fmt TAKES, va_list ap,
		const char *label)
	PRINTF_FMT(2,0) TAL_RETURN_PTR NON_NULL_ARGS(2);

/**
 * tal_append_fmt - append a formatted string to a talloc string.
 * @baseptr: a pointer to the tal string to be appended to.
 * @fmt: the printf-style format (can be take(), must not be NULL).
 *
 * Returns false on allocation failure.
 * Otherwise tal_count(*@baseptr) == strlen(*@baseptr) + 1.
 */
bool tal_append_fmt(char **baseptr, const char *fmt TAKES, ...)
	PRINTF_FMT(2,3) NON_NULL_ARGS(2);

/**
 * tal_append_vfmt - append a formatted string to a talloc string (va_list)
 * @baseptr: a pointer to the tal string to be appended to.
 * @fmt: the printf-style format (can be take(), must not be NULL).
 * @va: the va_list containing the format args.
 *
 * Returns false on allocation failure.
 * Otherwise tal_count(*@baseptr) == strlen(*@baseptr) + 1.
 */
bool tal_append_vfmt(char **baseptr, const char *fmt TAKES, va_list ap)
	NON_NULL_ARGS(2);

/**
 * tal_strcat - join two strings together
 * @ctx: NULL, or tal allocated object to be parent.
 * @s1: the first string (can be take(), must not be NULL).
 * @s2: the second string (can be take(), must not be NULL).
 *
 * The returned string will have tal_count() == strlen() + 1.
 */
#define tal_strcat(ctx, s1, s2) tal_strcat_(ctx, s1, s2, TAL_LABEL(char, "[]"))
char *tal_strcat_(const tal_t *ctx, const char *s1 TAKES, const char *s2 TAKES,
		  const char *label) TAL_RETURN_PTR NON_NULL_ARGS(2,3);

enum strsplit {
	STR_EMPTY_OK,
	STR_NO_EMPTY
};

/**
 * tal_strsplit - Split string into an array of substrings
 * @ctx: the context to tal from (often NULL).
 * @string: the string to split (can be take(), must not be NULL).
 * @delims: delimiters where lines should be split (can be take(), must not be NULL).
 * @flags: whether to include empty substrings.
 *
 * This function splits a single string into multiple strings.
 *
 * If @string is take(), the returned array will point into the
 * mangled @string.
 *
 * Multiple delimiters result in empty substrings.  By definition, no
 * delimiters will appear in the substrings.
 *
 * The final char * in the array will be NULL, and tal_count() will
 * return the number of elements plus 1 (for that NULL).
 *
 * Example:
 *	#include <ccan/tal/str/str.h>
 *	...
 *	static unsigned int count_long_lines(const char *string)
 *	{
 *		char **lines;
 *		unsigned int i, long_lines = 0;
 *
 *		// Can only fail on out-of-memory.
 *		lines = tal_strsplit(NULL, string, "\n", STR_NO_EMPTY);
 *		for (i = 0; lines[i] != NULL; i++)
 *			if (strlen(lines[i]) > 80)
 *				long_lines++;
 *		tal_free(lines);
 *		return long_lines;
 *	}
 */
#define tal_strsplit(ctx, string, delims, flag)	\
	tal_strsplit_(ctx, string, delims, flag, TAL_LABEL(char *, "[]"))
char **tal_strsplit_(const tal_t *ctx,
		     const char *string TAKES,
		     const char *delims TAKES,
		     enum strsplit flag,
		     const char *label)
	TAL_RETURN_PTR NON_NULL_ARGS(2,3);

enum strjoin {
	STR_TRAIL,
	STR_NO_TRAIL
};

/**
 * tal_strjoin - Join an array of substrings into one long string
 * @ctx: the context to tal from (often NULL).
 * @strings: the NULL-terminated array of strings to join (can be take(), must not be NULL)
 * @delim: the delimiter to insert between the strings (can be take(), must not be NULL)
 * @flags: whether to add a delimieter to the end
 *
 * This function joins an array of strings into a single string.  The
 * return value is allocated using tal.  Each string in @strings is
 * followed by a copy of @delim.
 *
 * The returned string will have tal_count() == strlen() + 1.
 *
 * Example:
 *	// Append the string "--EOL" to each line.
 *	static char *append_to_all_lines(const char *string)
 *	{
 *		char **lines, *ret;
 *
 *		lines = tal_strsplit(NULL, string, "\n", STR_EMPTY_OK);
 *		ret = tal_strjoin(NULL, lines, "-- EOL\n", STR_TRAIL);
 *		tal_free(lines);
 *		return ret;
 *	}
 */
#define tal_strjoin(ctx, strings, delim, flags)				\
	tal_strjoin_(ctx, strings, delim, flags, TAL_LABEL(char, "[]"))
char *tal_strjoin_(const void *ctx,
		   char *strings[] TAKES,
		   const char *delim TAKES,
		   enum strjoin flags,
		   const char *label)
	TAL_RETURN_PTR NON_NULL_ARGS(2,3);

/**
 * tal_strreg - match/extract from a string via (extended) regular expressions.
 * @ctx: the context to tal from (often NULL)
 * @string: the string to try to match (can be take(), must not be NULL)
 * @regex: the regular expression to match (can be take(), must not be NULL)
 * ...: pointers to strings to allocate for subexpressions.
 *
 * Returns true if we matched, in which case any parenthesized
 * expressions in @regex are allocated and placed in the char **
 * arguments following @regex.  NULL arguments mean the match is not
 * saved.  The order of the strings is the order
 * of opening braces in the expression: in the case of repeated
 * expressions (eg "([a-z])*") the last one is saved, in the case of
 * non-existent matches (eg "([a-z]*)?") the pointer is set to NULL.
 *
 * Allocation failures or malformed regular expressions return false.
 * The allocated strings will have tal_count() == strlen() + 1.
 *
 * See Also:
 *	regcomp(3), regex(3).
 *
 * Example:
 *	// Given "My name is Rusty" outputs "Hello Rusty!\n"
 *	// Given "my first name is Rusty Russell" outputs "Hello Rusty Russell!\n"
 *	// Given "My name isnt Rusty Russell" outputs "Hello there!\n"
 *	int main(int argc, char *argv[])
 *	{
 *		char *person, *input;
 *
 *		(void)argc;
 *		// Join args and trim trailing space.
 *		input = tal_strjoin(NULL, argv+1, " ", STR_NO_TRAIL);
 *		if (tal_strreg(NULL, input,
 *			       "[Mm]y (first )?name is ([A-Za-z ]+)",
 *			       NULL, &person))
 *			printf("Hello %s!\n", person);
 *		else
 *			printf("Hello there!\n");
 *		return 0;
 *	}
 */
#define tal_strreg(ctx, string, ...)					\
	tal_strreg_(ctx, string, TAL_LABEL(char, "[]"), __VA_ARGS__)
bool tal_strreg_(const void *ctx, const char *string TAKES,
		 const char *label, const char *regex TAKES, ...)
	NON_NULL_ARGS(2,4);
#endif /* CCAN_STR_TAL_H */

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
 * @p: the string to copy (can be take()).
 */
char *tal_strdup(const tal_t *ctx, const char *p TAKES);

/**
 * tal_strndup - duplicate a limited amount of a string.
 * @ctx: NULL, or tal allocated object to be parent.
 * @p: the string to copy (can be take()).
 * @n: the maximum length to copy.
 *
 * Always gives a nul-terminated string, with strlen() <= @n.
 */
char *tal_strndup(const tal_t *ctx, const char *p TAKES, size_t n);

/**
 * tal_fmt - allocate a formatted string
 * @ctx: NULL, or tal allocated object to be parent.
 * @fmt: the printf-style format (can be take()).
 */
char *tal_fmt(const tal_t *ctx, const char *fmt TAKES, ...) PRINTF_FMT(2,3);

/**
 * tal_vfmt - allocate a formatted string (va_list version)
 * @ctx: NULL, or tal allocated object to be parent.
 * @fmt: the printf-style format (can be take()).
 * @va: the va_list containing the format args.
 */
char *tal_vfmt(const tal_t *ctx, const char *fmt TAKES, va_list ap)
	PRINTF_FMT(2,0);

/**
 * tal_append_fmt - append a formatted string to a talloc string.
 * @baseptr: a pointer to the tal string to be appended to.
 * @fmt: the printf-style format (can be take()).
 *
 * Returns false on allocation failure.
 */
bool tal_append_fmt(char **baseptr, const char *fmt TAKES, ...) PRINTF_FMT(2,3);

/**
 * tal_append_vfmt - append a formatted string to a talloc string (va_list)
 * @baseptr: a pointer to the tal string to be appended to.
 * @fmt: the printf-style format (can be take()).
 * @va: the va_list containing the format args.
 *
 * Returns false on allocation failure.
 */
bool tal_append_vfmt(char **baseptr, const char *fmt TAKES, va_list ap);

/**
 * tal_strcat - join two strings together
 * @ctx: NULL, or tal allocated object to be parent.
 * @s1: the first string (can be take()).
 * @s2: the second string (can be take()).
 */
char *tal_strcat(const tal_t *ctx, const char *s1 TAKES, const char *s2 TAKES);

enum strsplit {
	STR_EMPTY_OK,
	STR_NO_EMPTY
};

/**
 * tal_strsplit - Split string into an array of substrings
 * @ctx: the context to tal from (often NULL).
 * @string: the string to split (can be take()).
 * @delims: delimiters where lines should be split (can be take()).
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
char **tal_strsplit(const tal_t *ctx,
		    const char *string TAKES,
		    const char *delims TAKES,
		    enum strsplit flag);

enum strjoin {
	STR_TRAIL,
	STR_NO_TRAIL
};

/**
 * tal_strjoin - Join an array of substrings into one long string
 * @ctx: the context to tal from (often NULL).
 * @strings: the NULL-terminated array of strings to join (can be take())
 * @delim: the delimiter to insert between the strings (can be take())
 * @flags: whether to add a delimieter to the end
 *
 * This function joins an array of strings into a single string.  The
 * return value is allocated using tal.  Each string in @strings is
 * followed by a copy of @delim.
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
char *tal_strjoin(const void *ctx,
		  char *strings[] TAKES,
		  const char *delim TAKES,
		  enum strjoin flags);

/**
 * tal_strreg - match/extract from a string via (extended) regular expressions.
 * @ctx: the context to tal from (often NULL)
 * @string: the string to try to match (can be take())
 * @regex: the regular expression to match (can be take())
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
bool tal_strreg(const void *ctx, const char *string TAKES,
		const char *regex TAKES, ...);
#endif /* CCAN_STR_TAL_H */

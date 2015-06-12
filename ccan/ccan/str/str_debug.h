/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_STR_DEBUG_H
#define CCAN_STR_DEBUG_H

/* #define CCAN_STR_DEBUG 1 */

#ifdef CCAN_STR_DEBUG
/* Because we mug the real ones with macros, we need our own wrappers. */
int str_isalnum(int i);
int str_isalpha(int i);
int str_isascii(int i);
#if HAVE_ISBLANK
int str_isblank(int i);
#endif
int str_iscntrl(int i);
int str_isdigit(int i);
int str_isgraph(int i);
int str_islower(int i);
int str_isprint(int i);
int str_ispunct(int i);
int str_isspace(int i);
int str_isupper(int i);
int str_isxdigit(int i);

char *str_strstr(const char *haystack, const char *needle);
char *str_strchr(const char *s, int c);
char *str_strrchr(const char *s, int c);
#endif /* CCAN_STR_DEBUG */

#endif /* CCAN_STR_DEBUG_H */

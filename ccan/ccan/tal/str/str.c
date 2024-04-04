/* Licensed under BSD-MIT - see LICENSE file for details */
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include "str.h"
#include <sys/types.h>
#include <regex.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <ccan/str/str.h>

char *tal_strdup_(const tal_t *ctx, const char *p, const char *label)
{
	return tal_dup_arr_label(ctx, char, p, strlen(p) + 1, 0, label);
}

char *tal_strndup_(const tal_t *ctx, const char *p, size_t n, const char *label)
{
	size_t len = strnlen(p, n);
	char *ret;

	ret = tal_dup_arr_label(ctx, char, p, len, 1, label);
	if (ret)
		ret[len] = '\0';
	return ret;
}

char *tal_fmt_(const tal_t *ctx, const char *label, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = tal_vfmt_(ctx, fmt, ap, label);
	va_end(ap);

	return ret;
}

static bool do_vfmt(char **buf, size_t off, const char *fmt, va_list ap)
{
	/* A decent guess to start. */
	size_t max = strlen(fmt) * 2 + 1;
	bool ok;

	for (;;) {
		va_list ap2;
		int ret;

		if (!tal_resize(buf, off + max)) {
			ok = false;
			break;
		}

		va_copy(ap2, ap);
		ret = vsnprintf(*buf + off, max, fmt, ap2);
		va_end(ap2);

		if (ret < max) {
			ok = true;
			/* Make sure tal_count() is correct! */
			tal_resize(buf, off + ret + 1);
			break;
		}
		max *= 2;
	}

	if (taken(fmt))
		tal_free(fmt);
	return ok;
}

char *tal_vfmt_(const tal_t *ctx, const char *fmt, va_list ap, const char *label)
{
	char *buf;

	/* A decent guess to start. */
	buf = tal_arr_label(ctx, char, strlen(fmt) * 2, label);
	if (!do_vfmt(&buf, 0, fmt, ap))
		buf = tal_free(buf);
	return buf;
}

bool tal_append_vfmt(char **baseptr, const char *fmt, va_list ap)
{
	return do_vfmt(baseptr, strlen(*baseptr), fmt, ap);
}

bool tal_append_fmt(char **baseptr, const char *fmt, ...)
{
	va_list ap;
	bool ret;

	va_start(ap, fmt);
	ret = tal_append_vfmt(baseptr, fmt, ap);
	va_end(ap);

	return ret;
}

char *tal_strcat_(const tal_t *ctx, const char *s1, const char *s2,
		  const char *label)
{
	size_t len1, len2;
	char *ret;

	len1 = strlen(s1);
	len2 = strlen(s2);

	ret = tal_dup_arr_label(ctx, char, s1, len1, len2 + 1, label);
	if (likely(ret))
		memcpy(ret + len1, s2, len2 + 1);

	if (taken(s2))
		tal_free(s2);
	return ret;
}

char **tal_strsplit_(const tal_t *ctx,
		     const char *string, const char *delims, enum strsplit flags,
		     const char *label)
{
	char **parts, *str;
	size_t max = 64, num = 0;

	parts = tal_arr(ctx, char *, max + 1);
	if (unlikely(!parts)) {
		if (taken(string))
			tal_free(string);
		if (taken(delims))
			tal_free(delims);
		return parts;
	}
	str = tal_strdup(parts, string);
	if (unlikely(!str))
		goto fail;

	if (flags == STR_NO_EMPTY)
		str += strspn(str, delims);

	while (*str != '\0') {
		size_t len = strcspn(str, delims), dlen;

		parts[num] = str;
		dlen = strspn(str + len, delims);
		parts[num][len] = '\0';
		if (flags == STR_EMPTY_OK && dlen)
			dlen = 1;
		str += len + dlen;
		if (++num == max && !tal_resize(&parts, max*=2 + 1))
			goto fail;
	}
	parts[num] = NULL;

	/* Ensure that tal_count() is correct. */
	if (unlikely(!tal_resize(&parts, num+1)))
		goto fail;

	if (taken(delims))
		tal_free(delims);
	return parts;

fail:
#ifdef CCAN_TAL_NEVER_RETURN_NULL
	abort();
#else
	tal_free(parts);
	if (taken(delims))
		tal_free(delims);
	return NULL;
#endif
}

char *tal_strjoin_(const tal_t *ctx,
		   char *strings[], const char *delim, enum strjoin flags,
		   const char *label)
{
	unsigned int i;
	char *ret = NULL;
	size_t totlen = 0, dlen;

	dlen = strlen(delim);
	ret = tal_arr_label(ctx, char, dlen*2+1, label);
	if (!ret)
		goto fail;

	ret[0] = '\0';
	for (i = 0; strings[i]; i++) {
		size_t len = strlen(strings[i]);

		if (flags == STR_NO_TRAIL && !strings[i+1])
			dlen = 0;
		if (!tal_resize(&ret, totlen + len + dlen + 1))
			goto fail;
		memcpy(ret + totlen, strings[i], len);
		totlen += len;
		memcpy(ret + totlen, delim, dlen);
		totlen += dlen;
	}
	ret[totlen] = '\0';
	/* Make sure tal_count() is correct! */
	tal_resize(&ret, totlen+1);
out:
	if (taken(strings))
		tal_free(strings);
	if (taken(delim))
		tal_free(delim);
	return ret;
fail:
	ret = tal_free(ret);
	goto out;
}

static size_t count_open_braces(const char *string)
{
#if 1
	size_t num = 0, esc = 0;

	while (*string) {
		if (*string == '\\')
			esc++;
		else {
			/* An odd number of \ means it's escaped. */
			if (*string == '(' && (esc & 1) == 0)
				num++;
			esc = 0;
		}
		string++;
	}
	return num;
#else
	return strcount(string, "(");
#endif
}

bool tal_strreg_(const tal_t *ctx, const char *string, const char *label,
		 const char *regex, ...)
{
	size_t nmatch = 1 + count_open_braces(regex);
	regmatch_t matches[nmatch];
	regex_t r;
	bool ret = false;
	unsigned int i;
	va_list ap;

	if (regcomp(&r, regex, REG_EXTENDED) != 0)
		goto fail_no_re;

	if (regexec(&r, string, nmatch, matches, 0) != 0)
		goto fail;

	ret = true;
	va_start(ap, regex);
	for (i = 1; i < nmatch; i++) {
		char **arg = va_arg(ap, char **);
		if (arg) {
			/* eg. ([a-z])? can give "no match". */
			if (matches[i].rm_so == -1)
				*arg = NULL;
			else {
				*arg = tal_strndup_(ctx,
						    string + matches[i].rm_so,
						    matches[i].rm_eo
						    - matches[i].rm_so,
						    label);
				/* FIXME: If we fail, we set some and leak! */
				if (!*arg) {
					ret = false;
					break;
				}
			}
		}
	}
	va_end(ap);
fail:
	regfree(&r);
fail_no_re:
	if (taken(regex))
		tal_free(regex);
	if (taken(string))
		tal_free(string);
	return ret;
}

/*	$Id$ */
/*
 * Copyright (c) 2008, Natacha Porté
 * Copyright (c) 2011, Vicent Martí
 * Copyright (c) 2014, Xavier Mendez, Devin Torres and the Hoedown authors
 * Copyright (c) 2016--2017, 2021 Kristaps Dzonsons
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

#define VALID_URIS_SZ	6

/*
 * List of URI prefixes that are considered "valid".
 */
static const char *const valid_uris[VALID_URIS_SZ] = {
	"http://", 
	"https://", 
	"/", 
	"#", 
	"ftp://", 
	"mailto:"
};

/* 
 * Verify that a URL has a safe protocol.
 */
static int
halink_is_safe(const char *data, size_t size)
{
	size_t	 i, len;

	for (i = 0; i < VALID_URIS_SZ; ++i) {
		len = strlen(valid_uris[i]);
		if (size > len &&
		    strncasecmp(data, valid_uris[i], len) == 0 &&
		    isalnum((unsigned char)data[len]))
			return 1;
	}

	return 0;
}

/*
 * Find the end of a hyperlink.
 * Returns the position of the end.
 */
static size_t
autolink_delim(char *data,
	size_t link_end, size_t max_rewind, size_t size)
{
	char	 cclose, copen = 0;
	size_t	 closing, opening, i, new_end;

	for (i = 0; i < link_end; ++i)
		if (data[i] == '<') {
			link_end = i;
			break;
		}

	while (link_end > 0) 
		if (strchr("?!.,:", data[link_end - 1]) != NULL)
			link_end--;
		else if (data[link_end - 1] == ';') {
			new_end = link_end - 2;

			while (new_end > 0 && 
			       isalpha((unsigned char)data[new_end]))
				new_end--;

			if (new_end < link_end - 2 && 
			    data[new_end] == '&')
				link_end = new_end;
			else
				link_end--;
		} else 
			break;

	if (link_end == 0)
		return 0;

	cclose = data[link_end - 1];

	switch (cclose) {
	case '"':
		copen = '"'; 
		break;
	case '\'':
		copen = '\''; 
		break;
	case ')':
		copen = '('; 
		break;
	case ']':
		copen = '['; 
		break;
	case '}':
		copen = '{'; 
		break;
	}

	if (copen != 0) {
		closing = opening = i = 0;

		/* 
		 * Try to close the final punctuation sign in this same
		 * line; if we managed to close it outside of the URL,
		 * that means that it's not part of the URL. If it
		 * closes inside the URL, that means it is part of the
		 * URL.
		 *
		 * Examples:
		 *
		 * foo http://www.pokemon.com/Pikachu_(Electric) bar
		 * => http://www.pokemon.com/Pikachu_(Electric)
		 *
		 * foo (http://www.pokemon.com/Pikachu_(Electric)) bar
		 * => http://www.pokemon.com/Pikachu_(Electric)
		 *
		 * foo http://www.pokemon.com/Pikachu_(Electric)) bar
		 * => http://www.pokemon.com/Pikachu_(Electric))
		 *
		 * (foo http://www.pokemon.com/Pikachu_(Electric)) bar
		 * => foo http://www.pokemon.com/Pikachu_(Electric)
		 */

		while (i < link_end) {
			if (data[i] == copen)
				opening++;
			else if (data[i] == cclose)
				closing++;
			i++;
		}

		if (closing != opening)
			link_end--;
	}

	return link_end;
}

/*
 * To make sure that a domain is well-formed.
 * Returns zero on failure, non-zero on success.
 * XXX: this function needs to be replaced.
 */
static size_t
check_domain(char *data, size_t size)
{
	size_t	 i, np = 0;

	if (!isalnum((unsigned char)data[0]))
		return 0;

	for (i = 1; i < size - 1; ++i) {
		if (strchr(".:", data[i]) != NULL) 
			np++;
		else if (!isalnum((unsigned char)data[i]) && 
			 data[i] != '-') 
			break;
	}

	/* A valid domain needs to have at least a dot. */

	return np ? i : 0;
}

/* 
 * Search for the next www link in data.
 */
ssize_t
halink_www(size_t *rewind_p, struct lowdown_buf *link,
	char *data, size_t max_rewind, size_t size)
{
	size_t link_end;

	if (max_rewind > 0 && 
	   !ispunct((unsigned char)data[-1]) && 
	   !isspace((unsigned char)data[-1]))
		return 0;

	if (size < 4 || memcmp(data, "www.", strlen("www.")) != 0)
		return 0;

	link_end = check_domain(data, size);

	if (link_end == 0)
		return 0;

	while (link_end < size && 
	       !isspace((unsigned char)data[link_end]))
		link_end++;

	link_end = autolink_delim(data, link_end, max_rewind, size);

	if (link_end == 0)
		return 0;

	if (!hbuf_put(link, data, link_end))
		return -1;
	*rewind_p = 0;

	return link_end;
}

/* 
 * Search for the next email in data.
 */
ssize_t
halink_email(size_t *rewind_p, struct lowdown_buf *link, 
	char *data, size_t max_rewind, size_t size)
{
	size_t	 link_end, rewind;
	int	 nb = 0, np = 0;
	char	 c;

	for (rewind = 0; rewind < max_rewind; ++rewind) {
		c = data[-1 - rewind];

		if (isalnum((unsigned char)c))
			continue;

		if (strchr(".+-_", c) != NULL)
			continue;

		break;
	}

	if (rewind == 0)
		return 0;

	for (link_end = 0; link_end < size; ++link_end) {
		c = data[link_end];

		if (isalnum(c))
			continue;

		if (c == '@')
			nb++;
		else if (c == '.' && link_end < size - 1)
			np++;
		else if (c != '-' && c != '_')
			break;
	}

	if (link_end < 2 || nb != 1 || np == 0 ||
	    !isalpha((unsigned char)data[link_end - 1]))
		return 0;

	link_end = autolink_delim(data, link_end, max_rewind, size);

	if (link_end == 0)
		return 0;

	if (!hbuf_put(link, data - rewind, link_end + rewind))
		return -1;
	*rewind_p = rewind;

	return link_end;
}

/* 
 * Search for the next URL in data.
 */
ssize_t
halink_url(size_t *rewind_p, struct lowdown_buf *link,
	char *data, size_t max_rewind, size_t size)
{
	size_t link_end, rewind = 0, domain_len;

	if (size < 4 || data[1] != '/' || data[2] != '/')
		return 0;

	while (rewind < max_rewind && 
	       isalpha((unsigned char)data[-1 - rewind]))
		rewind++;

	if (!halink_is_safe(data - rewind, size + rewind))
		return 0;

	link_end = strlen("://");

	domain_len = check_domain(data + link_end, size - link_end);

	if (domain_len == 0)
		return 0;

	link_end += domain_len;
	while (link_end < size && 
	       !isspace((unsigned char)data[link_end]))
		link_end++;

	link_end = autolink_delim(data, link_end, max_rewind, size);

	if (link_end == 0)
		return 0;

	if (!hbuf_put(link, data - rewind, link_end + rewind))
		return -1;
	*rewind_p = rewind;

	return link_end;
}

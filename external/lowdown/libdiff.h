/*
 * Copyright (c) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 * Copyright (c) 2018 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef DIFF_H
#define DIFF_H

typedef	int (*diff_cmp)(const void *, const void *);

enum 	difft {
	DIFF_ADD,
	DIFF_DELETE,
	DIFF_COMMON
};

struct	diff_ses {
	size_t		 originIdx; /* if >0, index+1 in origin array */
	size_t	 	 targetIdx; /* if >0, index+1 in target array */
	enum difft	 type; /* type of edit */
	const void	*e; /* pointer to object */
};

struct	diff {
	const void	**lcs; /* longest common subsequence */
	size_t		  lcssz;
	struct diff_ses	 *ses; /* shortest edit script */
	size_t	    	  sessz;
	size_t		  editdist; /* edit distance */
};

int	diff(struct diff *, diff_cmp, size_t,
		const void *, size_t, const void *, size_t);

#endif /* ! DIFF_H */

/*	$Id$ */
/*
 * Copyright (c) 2020, Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "extern.h"

struct ent {
	const char 	*iso; /* html entity */
	uint32_t	 unicode; /* decimal unicode */
	const char	*nroff; /* -ms/-man */
	const char	*tex; /* latex */
	/**
	 * For latex: if zero, escape as-is.  If just TEX_ENT_ASCII,
	 * don't escape at all.  If just TEX_ENT_MATH, pass as math mode
	 * escaped.  If both TEX_ENT_ASCII and TEX_ENT_MATH, pass as
	 * math mode and don't escape.
	 */
	unsigned char	 texflags;
};

static const struct ent ents[] = {
	{ "AElig", 	198,	"AE",	"AE{}",		0 },
	{ "Aacute", 	193,	"'A",	"'{A}",		0 },
	{ "Acirc", 	194,	"^A",	"^{A}",		0 },
	{ "Agrave", 	192,	"`A",	"`{A}",		0 },
	{ "Alpha",	913,	"*A",	"A",		TEX_ENT_ASCII },
	{ "Aring", 	197,	"oA",	"AA{}",		0 },
	{ "Atilde", 	195,	"~A",	"~{A}",		0 },
	{ "Auml", 	196,	":A",	"\"{A}",	0 },
	{ "Beta",	914,	"*B",	"B",		TEX_ENT_ASCII },
	{ "Ccedil", 	199,	",C",	"c{C}",		0 },
	{ "Chi",	935,	"*X",	"X",		TEX_ENT_ASCII },
	{ "Dagger",	8225,	"dg",	"ddag{}",	0 },
	{ "Delta",	916,	"*D",	"Delta",	TEX_ENT_MATH },
	{ "ETH", 	208,	"-D",	"DH{}",		0 },
	{ "Eacute", 	201,	"'E",	"'{E}",		0 },
	{ "Ecirc", 	202,	"^E",	"^{E}",		0 },
	{ "Egrave", 	200,	"`E",	"`{E}",		0 },
	{ "Epsilon",	917,	"*E",	"E",		TEX_ENT_ASCII },
	{ "Eta",	919,	"*Y",	"E",		TEX_ENT_ASCII },
	{ "Euml", 	203,	":E",	"\"{E}",	0 },
	{ "Gamma",	915,	"*G",	"Gamma",	TEX_ENT_MATH },
	{ "Iacute", 	205,	"'I",	"'{I}",		0 },
	{ "Icirc", 	206,	"^I",	"^{I}",		0 },
	{ "Igrave", 	204,	"`I",	"`{I}",		0 },
	{ "Iota",	921,	"*I",	"I",		TEX_ENT_ASCII },
	{ "Iuml", 	207,	":I",	"\"{I}",	0 },
	{ "Kappa",	922,	"*K",	"K",		TEX_ENT_ASCII },
	{ "Lambda",	923,	"*L",	"Lambda",	TEX_ENT_MATH },
	{ "Mu",		924,	"*M",	"M",		TEX_ENT_ASCII },
	{ "Ntilde", 	209,	"~N",	"~{N}",		0 },
	{ "Nu",		925,	"*N",	"N",		TEX_ENT_ASCII },
	{ "OElig",	338,	"OE",	"OE{}",		0 },
	{ "Oacute", 	211,	"'O",	"'{O}",		0 },
	{ "Ocirc", 	212,	"^O",	"^{O}",		0 },
	{ "Ograve", 	210,	"`O",	"`{O}",		0 },
	{ "Omega",	937,	"*W",	"Omega",	TEX_ENT_MATH },
	{ "Omicron",	927,	"*O",	"O",		TEX_ENT_ASCII },
	{ "Oslash", 	216,	"/O",	"O{}",		0 },
	{ "Otilde", 	213,	"~O",	"~{O}",		0 },
	{ "Ouml", 	214,	":O",	"\"{O}",	0 },
	{ "Phi",	934,	"*F",	"Phi",		TEX_ENT_MATH },
	{ "Pi",		928,	"*P",	"Pi",		TEX_ENT_MATH },
	{ "Prime",	8243,	NULL,	"^{\\prime\\prime}", TEX_ENT_MATH | TEX_ENT_ASCII },
	{ "Psi",	936,	"*Q",	"Psi",		TEX_ENT_MATH },
	{ "Rho",	929,	"*R",	"R",		TEX_ENT_ASCII },
	{ "Scaron",	352,	"vS",	"v{S}",		0 },
	{ "Sigma",	931,	"*S",	"Sigma",	TEX_ENT_MATH },
	{ "THORN", 	222,	"TP",	"TH{}",		0 },
	{ "Tau",	932,	"*T",	"T",		TEX_ENT_ASCII },
	{ "Theta",	920,	"*H",	"Theta",	TEX_ENT_MATH },
	{ "Uacute", 	218,	"'U",	"'{U}",		0 },
	{ "Ucirc", 	219,	"^U",	"^{U}",		0 },
	{ "Ugrave", 	217,	"`U",	"`{U}",		0 },
	{ "Upsilon",	933,	"*U",	"Upsilon",	TEX_ENT_MATH },
	{ "Uuml", 	220,	":U",	"\"{U}",	0 },
	{ "Xi",		926,	"*C",	"Xi",		TEX_ENT_MATH },
	{ "Yacute", 	221,	"'Y",	"'{Y}",		0 },
	{ "Yuml",	376,	":Y",	"\"{Y}",	0 },
	{ "Zeta",	918,	"*Z",	"Z",		TEX_ENT_ASCII },
	{ "aacute", 	225,	"'a",	"'{a}",		0 },
	{ "acirc", 	226,	"^a",	"^{a}",		0 },
	{ "acute", 	180,	"'",	"'{}",		0 },
	{ "aelig", 	230,	"ae",	"ae{}",		0 },
	{ "agrave", 	224,	"`a",	"`{a}",		0 },
	{ "alefsym",	8501,	"Ah",	"aleph",	TEX_ENT_MATH },
	{ "alpha",	945,	"*a",	"alpha",	TEX_ENT_MATH },
	{ "amp",	38,	NULL,	"&{}",		0 },
	{ "and",	8743,	"AN",	"wedge",	TEX_ENT_MATH },
	{ "ang",	8736,	"/_",	"angle",	TEX_ENT_MATH },
	{ "aring", 	229,	"oa",	"aa{}",		0 },
	{ "asymp",	8776,	"|=",	"asymp",	TEX_ENT_MATH },
	{ "atilde", 	227,	"~a",	"~{a}",		0 },
	{ "auml", 	228,	":a",	"\"{a}",	0 },
	{ "bdquo",	8222,	NULL,	NULL,		0 }, /* XXX */
	{ "beta",	946,	"*b",	"beta",		TEX_ENT_MATH },
	{ "brvbar", 	166,	NULL,	"textbrokenbar{}",	0 },
	{ "bull",	8226,	"bu",	"textbullet{}",	0 },
	{ "cap",	8745,	"ca",	"cap",		TEX_ENT_MATH },
	{ "ccedil", 	231,	",c",	"c{c}",		0 },
	{ "cedil", 	184,	"ac",	"c{}",		0 },
	{ "cent", 	162,	"ct",	"textcent{}",	0 },
	{ "chi",	967,	"*x",	"chi",		TEX_ENT_MATH },
	{ "circ",	710,	"a^",	"^{}",		0 },
	{ "cong",	8773,	"=~",	"cong",		TEX_ENT_MATH },
	{ "copy", 	169,	"co",	"copyright{}",	0 },
	{ "crarr",	8629,	NULL,	NULL,		0 }, /* XXX */
	{ "cup",	8746,	"cu",	"cup",		TEX_ENT_MATH },
	{ "curren", 	164,	NULL,	"textcurrency{}", 0 },
	{ "dArr",	8659,	NULL,	"Downarrow",	TEX_ENT_MATH },
	{ "dagger",	8224,	"dg",	"dag{}",	0 },
	{ "darr",	8595,	"da",	"downarrow",	TEX_ENT_MATH },
	{ "deg", 	176,	"de",	"textdegree{}",	0 },
	{ "delta",	948,	"*d",	"delta",	TEX_ENT_MATH },
	{ "divide", 	247,	"tdi",	"div",		TEX_ENT_MATH },
	{ "eacute", 	233,	"'e",	"'{e}",		0 },
	{ "ecirc", 	234,	"^e",	"^{e}",		0 },
	{ "egrave", 	232,	"`e",	"`{e}",		0 },
	{ "empty",	8709,	"es",	"emptyset",	TEX_ENT_MATH },
	{ "emsp",	8195,	NULL,	"hspace{1em}",	0 },
	{ "ensp",	8194,	NULL,	"hspace{0.5em}", 0 },
	{ "epsilon",	949,	"*e",	"epsilon",	TEX_ENT_MATH },
	{ "equiv",	8801,	"==",	"equiv",	TEX_ENT_MATH },
	{ "eta",	951,	"*y",	"eta",		TEX_ENT_MATH },
	{ "eth", 	240,	"Sd",	"dh{}",		0 },
	{ "euml", 	235,	":e",	"\"{e}",	0 },
	{ "euro",	8364,	"Eu",	"texteuro{}",	0 },
	{ "exist",	8707,	"te",	"exists",	TEX_ENT_MATH },
	{ "fnof",	402,	NULL,	"f",		TEX_ENT_MATH },
	{ "forall",	8704,	NULL,	"forall",	TEX_ENT_MATH },
	{ "frac12", 	189,	"12",	"sfrac{1}{2}",	TEX_ENT_MATH },
	{ "frac14", 	188,	"14",	"sfrac{1}{4}",	TEX_ENT_MATH },
	{ "frac34", 	190,	"34",	"sfrac{3}{4}",	TEX_ENT_MATH },
	{ "frasl",	8260,	NULL,	NULL,		0 }, /* XXX */
	{ "gamma",	947,	"*g",	"gamma",	TEX_ENT_MATH },
	{ "ge",		8805,	">=",	"geq",		TEX_ENT_MATH },
	{ "gt",		62,	NULL,	"textgreater{}", 0 },
	{ "hArr",	8660,	NULL,	"Leftrightarrow", TEX_ENT_MATH },
	{ "harr",	8596,	"<>",	"leftrightarrow", TEX_ENT_MATH },
	{ "hellip",	8230,	NULL,	"ldots{}",	0 },
	{ "iacute", 	237,	"'i",	"'{i}",		0 },
	{ "icirc", 	238,	"^i",	"^{i}",		0 },
	{ "iexcl", 	161,	"r!",	"textexclamdown{}", 0 },
	{ "igrave", 	236,	"`i",	"`{i}",		0 },
	{ "image",	8465,	NULL,	"Im",		TEX_ENT_MATH },
	{ "infin",	8734,	"if",	"infty",	TEX_ENT_MATH },
	{ "int",	8747,	"integral", "int",		TEX_ENT_MATH },
	{ "iota",	953,	"*i",	"iota",		TEX_ENT_MATH },
	{ "iquest", 	191,	"r?",	"textquestiondown{}", 0 },
	{ "isin",	8712,	NULL,	"in",		TEX_ENT_MATH },
	{ "iuml", 	239,	":i",	"\"{i}",	0 },
	{ "kappa",	954,	"*k",	"kappa",	TEX_ENT_MATH },
	{ "lArr",	8656,	NULL,	"Leftarrow",	TEX_ENT_MATH },
	{ "lambda",	955,	"*l",	"lambda",	TEX_ENT_MATH },
	{ "lang",	9001,	"la",	"langle",	TEX_ENT_MATH },
	{ "laquo", 	171,	"Fo",	"guillemetleft{}", 0 },
	{ "larr",	8592,	"<-",	"leftarrow",	TEX_ENT_MATH },
	{ "lceil",	8968,	NULL,	"lceil",	TEX_ENT_MATH },
	{ "ldquo",	8220,	"lq",	"``",		TEX_ENT_ASCII },
	{ "le",		8804,	NULL,	"leq",		TEX_ENT_MATH },
	{ "lfloor",	8970,	"lf",	"lfloor",	TEX_ENT_MATH },
	{ "lowast",	8727,	NULL,	"_\\ast",	TEX_ENT_MATH },
	{ "lrm",	8206,	NULL,	NULL,		0 }, /* XXX */
	{ "lsaquo",	8249,	NULL,	NULL,		0 },
	{ "lsquo",	8216,	"oq",	"`",		TEX_ENT_ASCII },
	{ "lt",		60,	NULL,	"textless{}",	0 },
	{ "macr", 	175,	NULL,	"={}",		0 },
	{ "mdash",	8212,	"em",	"---",		TEX_ENT_ASCII },
	{ "micro", 	181,	NULL,	"textmu{}",	0 },
	{ "middot", 	183,	NULL,	"textperiodcentered{}", 0 },
	{ "minus",	8722,	"mi",	"-{}",		0 },
	{ "mu",		956,	"*m",	"mu",		TEX_ENT_MATH },
	{ "nabla",	8711,	NULL,	"nabla",	TEX_ENT_MATH },
	{ "nbsp", 	160,	"~",	"~",		TEX_ENT_ASCII },
	{ "ndash",	8211,	"en",	"--",		TEX_ENT_ASCII },
	{ "ne",		8800,	"!=",	"not=",		TEX_ENT_MATH },
	{ "ni",		8715,	NULL,	"ni",		TEX_ENT_MATH },
	{ "not", 	172,	"no",	"lnot",		TEX_ENT_MATH },
	{ "notin",	8713,	NULL,	"not\\in",	TEX_ENT_MATH },
	{ "nsub",	8836,	NULL,	"not\\subset",	TEX_ENT_MATH },
	{ "ntilde", 	241,	"~n",	"~{n}",		0 },
	{ "nu",		957,	"*n",	"nu",		TEX_ENT_MATH },
	{ "oacute", 	243,	"'o",	"'{o}",		0 },
	{ "ocirc", 	244,	"^o",	"^{o}",		0 },
	{ "oelig",	339,	"oe",	"oe{}",		0 },
	{ "ograve", 	242,	"`o",	"`{o}",		0 },
	{ "oline",	8254,	NULL,	"ominus",	TEX_ENT_MATH },
	{ "omega",	969,	"*w",	"omega",	TEX_ENT_MATH },
	{ "omicron",	959,	"*o",	"omicron",	TEX_ENT_MATH },
	{ "oplus",	8853,	NULL,	"oplus",	TEX_ENT_MATH },
	{ "or",		8744,	"OR",	"vee",		TEX_ENT_MATH },
	{ "ordf", 	170,	NULL,	"textordfeminine{}", 0 },
	{ "ordm", 	186,	NULL,	"textordmasculine{}", 0 },
	{ "oslash", 	248,	"/o",	"oslash",	TEX_ENT_MATH },
	{ "otilde", 	245,	"~o",	"~{o}",		0 },
	{ "otimes",	8855,	NULL,	"otimes",	TEX_ENT_MATH },
	{ "ouml", 	246,	":o",	"\"{o}",	0 },
	{ "para", 	182,	NULL,	"P{}",		0 },
	{ "part",	8706,	"pd",	"partial",	TEX_ENT_MATH },
	{ "permil",	8240,	NULL,	"textperthousand{}", 0 },
	{ "perp",	8869,	NULL,	"perp",		TEX_ENT_MATH },
	{ "phi",	966,	"*f",	"phi",		TEX_ENT_MATH },
	{ "pi",		960,	"*p",	"pi",		TEX_ENT_MATH },
	{ "piv",	982,	"+p",	"varpi",	TEX_ENT_MATH },
	{ "plusmn", 	177,	"+-",	"pm",		TEX_ENT_MATH },
	{ "pound", 	163,	NULL,	"pounds{}",	0 },
	{ "prime",	8242,	NULL,	"^\\prime{}",	TEX_ENT_MATH | TEX_ENT_ASCII },
	{ "prod",	8719,	"poduct", "prod",	TEX_ENT_MATH },
	{ "prop",	8733,	NULL,	"propto",	TEX_ENT_MATH },
	{ "psi",	968,	"*q",	"psi",		TEX_ENT_MATH },
	{ "quot",	34,	NULL,	"\"",		TEX_ENT_ASCII },
	{ "rArr",	8658,	NULL,	"Rightarrow",	TEX_ENT_MATH },
	{ "radic",	8730,	NULL,	"surd",		TEX_ENT_MATH },
	{ "rang",	9002,	"ra",	"rangle",	TEX_ENT_MATH },
	{ "raquo", 	187,	"Fc",	"guillemotright{}", 0 },
	{ "rarr",	8594,	"->",	"rightarrow",	TEX_ENT_MATH },
	{ "rceil",	8969,	NULL,	"rceil",	TEX_ENT_MATH },
	{ "rdquo",	8221,	"rq",	"''",		TEX_ENT_ASCII },
	{ "real",	8476,	NULL,	"Re",		TEX_ENT_MATH },
	{ "reg", 	174,	"rg",	"textregistered{}", 0 },
	{ "rfloor",	8971,	"rf",	"rfloor",	TEX_ENT_MATH },
	{ "rho",	961,	"*r",	"rho",		TEX_ENT_MATH },
	{ "rlm",	8207,	NULL,	NULL,		0 }, /* XXX */
	{ "rsaquo",	8250,	NULL,	NULL,		0 }, /* XXX */
	{ "rsquo",	8217,	"cq",	"'",		TEX_ENT_ASCII },
	{ "sbquo",	8218,	NULL,	NULL,		0 }, /* XXX */
	{ "scaron",	353,	"vs",	"v{s}",		0 },
	{ "sdot",	8901,	NULL,	"cdot",		TEX_ENT_MATH },
	{ "sect", 	167,	"sc",	"S{}",		0 },
	{ "shy", 	173,	NULL,	"-{}",		0 },
	{ "sigma",	963,	"*s",	"sigma",	TEX_ENT_MATH },
	{ "sigmaf",	962,	"ts",	"sigmav",	TEX_ENT_MATH }, /* XXX?? */
	{ "sim",	8764,	"ap",	"sim",		TEX_ENT_MATH },
	{ "sub",	8834,	"sb",	"subset",	TEX_ENT_MATH },
	{ "sube",	8838,	"ib",	"subseteq",	TEX_ENT_MATH },
	{ "sum",	8721,	"sum",	"sum",		TEX_ENT_MATH },
	{ "sup",	8835,	"sp",	"supset",	TEX_ENT_MATH },
	{ "sup1", 	185,	"S1",	"$^1$",		TEX_ENT_ASCII },
	{ "sup2", 	178,	"S2",	"$^2$",		TEX_ENT_ASCII },
	{ "sup3", 	179,	"S3",	"$^3$",		TEX_ENT_ASCII },
	{ "supe",	8839,	"ip",	"supseteq",	TEX_ENT_MATH },
	{ "szlig", 	223,	"ss",	"ss{}",		0 },
	{ "tau",	964,	"*t",	"tau",		TEX_ENT_MATH },
	{ "there4",	8756,	"3d",	"therefore",	TEX_ENT_MATH },
	{ "theta",	952,	"*h",	"theta",	TEX_ENT_MATH },
	{ "thetasym",	977,	"+h",	"vartheta",	TEX_ENT_MATH }, /* XXX?? */
	{ "thinsp",	8201,	NULL,	"hspace{0.167em}", 0 },
	{ "thorn", 	254,	"Tp",	"th{}",		0 },
	{ "tilde",	732,	"ti",	"~{}",		0 },
	{ "times", 	215,	"mu",	"times",	TEX_ENT_MATH },
	{ "trade",	8482,	"tm",	"texttrademark{}", 0 },
	{ "uArr",	8657,	NULL,	"Uparrow",	TEX_ENT_MATH },
	{ "uacute", 	250,	"'u",	"'{u}",		0 },
	{ "uarr",	8593,	"ua",	"uparrow",	TEX_ENT_MATH },
	{ "ucirc", 	251,	"^u",	"^{u}",		0 },
	{ "ugrave", 	249,	"`u",	"`{u}",		0 },
	{ "uml", 	168,	"ad",	"\"{}",		0 },
	{ "upsih",	978,	NULL,	NULL,		0 }, /* XXX */
	{ "upsilon",	965,	"*u",	"upsilon",	TEX_ENT_MATH },
	{ "uuml", 	252,	":u",	"\"{u}",	0 },
	{ "weierp",	8472,	"wp",	"wp",		TEX_ENT_MATH },
	{ "xi",		958,	"*c",	"xi",		TEX_ENT_MATH },
	{ "yacute", 	253,	"'y",	"'{y}",		0 },
	{ "yen", 	165,	"Ye",	"textyen{}",	0 },
	{ "yuml", 	255,	":y",	"\"{y}",	0 },
	{ "zeta",	950,	"*z",	"zeta",		TEX_ENT_MATH },
	{ "zwj",	8205,	NULL,	NULL,		0 }, /* XXX */
	{ "zwnj",	8204,	NULL,	NULL,		0 }, /* XXX */
	{ NULL, 	0,	NULL,	NULL,		0 }
};

static int32_t
entity_find_num(const struct lowdown_buf *buf)
{
	char			 b[32];
	char			*ep;
	unsigned long long	 ulval;
	int			 base;

	if (buf->size < 4)
		return -1;

	/* Copy a hex or decimal value. */

	if (buf->data[2] == 'x' || buf->data[2] == 'X') {
		if (buf->size < 5)
			return -1;
		if (buf->size - 4 > sizeof(b) - 1)
			return -1;
		memcpy(b, buf->data + 3, buf->size - 4);
		b[buf->size - 4] = '\0';
		base = 16;
	} else {
		if (buf->size - 3 > sizeof(b) - 1)
			return -1;
		memcpy(b, buf->data + 2, buf->size - 3);
		b[buf->size - 3] = '\0';
		base = 10;
	}

	/* 
	 * Convert within the given base.
	 * This calling syntax is from OpenBSD's strtoull(3).
	 */

	errno = 0;
	ulval = strtoull(b, &ep, base);
	if (b[0] == '\0' || *ep != '\0')
		return -1;
	if (errno == ERANGE && ulval == ULLONG_MAX)
		return -1;
	if (ulval > INT32_MAX)
		return -1;

	return (int32_t)ulval;
}

/*
 * Convert a named entity to a unicode codepoint.
 * Return -1 on failure.
 */
static const struct ent *
entity_find_named(const struct lowdown_buf *buf)
{
	char	 b[32];
	size_t	 i;

	/* 
	 * Copy into NUL-terminated buffer for easy strcmp().
	 * We omit the leading '&' and trailing ';'.
	 */

	if (buf->size - 2 > sizeof(b) - 1)
		return NULL;
	memcpy(b, buf->data + 1, buf->size - 2);
	b[buf->size - 2] = '\0';

	/* TODO: can be trivially sped up by using a binary search. */

	for (i = 0; ents[i].iso != NULL; i++)
		if (strcmp(b, ents[i].iso) == 0)
			return &ents[i];

	return NULL;
}

/*
 * Basic sanity of HTML entity.
 * Needs to be &xyz;
 * Return zero on failure, non-zero on success.
 */
static int
entity_sane(const struct lowdown_buf *buf)
{

	if (buf->size < 3 ||
	    buf->data[0] != '&' ||
	    buf->data[buf->size - 1] != ';')
		return 0;
	return 1;
}

/*
 * Look up an entity and return its decimal value or -1 on failure (bad
 * formatting or couldn't find entity).
 * Handles both numeric (decimal and hex) and common named ones.
 */
int32_t
entity_find_iso(const struct lowdown_buf *buf)
{
	const struct ent *e;

	if (!entity_sane(buf))
		return -1;

	if (buf->data[1] == '#')
		return entity_find_num(buf);

	if ((e = entity_find_named(buf)) == NULL)
		return -1;

	assert(e->unicode < INT32_MAX);
	return e->unicode;
}

/**
 * Look for the roff entity corresponding to "buf".  If will either
 * return a special character (which must be escaped using the usual
 * \(xx or whatever) or NULL.  If NULL and "iso" is -1, the character
 * couldn't be found.  If NULL and "iso" is >= 0, "iso" is a unicode
 * character number that must be further escaped.
 */
const char *
entity_find_nroff(const struct lowdown_buf *buf, int32_t *iso)
{
	const struct ent	*e;
	size_t			 i;

	*iso = -1;

	if (!entity_sane(buf))
		return NULL;

	if (buf->data[1] == '#') {
		if ((*iso = entity_find_num(buf)) == -1)
			return NULL;
		for (i = 0; ents[i].iso != NULL; i++)
			if ((int32_t)ents[i].unicode == *iso)
				return ents[i].nroff;
		return NULL;
	}

	if ((e = entity_find_named(buf)) == NULL)
		return NULL;

	assert(e->unicode < INT32_MAX);
	*iso = e->unicode;
	return e->nroff;
}

/*
 * Looks for the TeX entity corresponding to "buf".
 * If "buf" is a numerical code, looks it up by number; if an HTML (ISO)
 * code, looks it up by that.
 * Returns the entity or NULL on failure.
 * On success, sets the TeX flags.
 */
const char *
entity_find_tex(const struct lowdown_buf *buf, unsigned char *fl)
{
	const struct ent	*e;
	int32_t			 unicode;
	size_t			 i;

	if (!entity_sane(buf))
		return NULL;

	if (buf->data[1] == '#') {
		if ((unicode = entity_find_num(buf)) == -1)
			return NULL;
		for (i = 0; ents[i].iso != NULL; i++)
			if ((int32_t)ents[i].unicode == unicode) {
				*fl = ents[i].texflags;
				return ents[i].tex;
			}
		return NULL;
	}

	if ((e = entity_find_named(buf)) == NULL)
		return NULL;

	assert(e->unicode < INT32_MAX);
	*fl = e->texflags;
	return e->tex;
}

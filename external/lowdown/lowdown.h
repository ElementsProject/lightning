/*	$Id$ */
/*
 * Copyright (c) 2017--2021 Kristaps Dzonsons <kristaps@bsd.lv>
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
 / OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef LOWDOWN_H
#define LOWDOWN_H

/*
 * All of this is documented in lowdown.3.
 * If it's not documented, don't use it.
 * Or report it as a bug.
 */

/* We need this for compilation on musl systems. */

#ifndef __BEGIN_DECLS
# ifdef __cplusplus
#  define       __BEGIN_DECLS           extern "C" {
# else
#  define       __BEGIN_DECLS
# endif
#endif
#ifndef __END_DECLS
# ifdef __cplusplus
#  define       __END_DECLS             }
# else
#  define       __END_DECLS
# endif
#endif

enum	lowdown_type {
	LOWDOWN_GEMINI,
	LOWDOWN_HTML,
	LOWDOWN_LATEX,
	LOWDOWN_MAN,
	LOWDOWN_NROFF,
	LOWDOWN_FODT,
	LOWDOWN_TERM,
	LOWDOWN_TREE,
	LOWDOWN_NULL
};

/*
 * All types of Markdown nodes that lowdown understands.
 */
enum	lowdown_rndrt {
	LOWDOWN_ROOT,
	LOWDOWN_BLOCKCODE,
	LOWDOWN_BLOCKQUOTE,
	LOWDOWN_DEFINITION,
	LOWDOWN_DEFINITION_TITLE,
	LOWDOWN_DEFINITION_DATA,
	LOWDOWN_HEADER,
	LOWDOWN_HRULE,
	LOWDOWN_LIST,
	LOWDOWN_LISTITEM,
	LOWDOWN_PARAGRAPH,
	LOWDOWN_TABLE_BLOCK,
	LOWDOWN_TABLE_HEADER,
	LOWDOWN_TABLE_BODY,
	LOWDOWN_TABLE_ROW,
	LOWDOWN_TABLE_CELL,
	LOWDOWN_BLOCKHTML,
	LOWDOWN_LINK_AUTO,
	LOWDOWN_CODESPAN,
	LOWDOWN_DOUBLE_EMPHASIS,
	LOWDOWN_EMPHASIS,
	LOWDOWN_HIGHLIGHT,
	LOWDOWN_IMAGE,
	LOWDOWN_LINEBREAK,
	LOWDOWN_LINK,
	LOWDOWN_TRIPLE_EMPHASIS,
	LOWDOWN_STRIKETHROUGH,
	LOWDOWN_SUPERSCRIPT,
	LOWDOWN_FOOTNOTE,
	LOWDOWN_MATH_BLOCK,
	LOWDOWN_RAW_HTML,
	LOWDOWN_ENTITY,
	LOWDOWN_NORMAL_TEXT,
	LOWDOWN_DOC_HEADER,
	LOWDOWN_META,
	LOWDOWN__MAX
};

struct	lowdown_buf {
	char		*data;	/* actual character data */
	size_t		 size;	/* size of the string */
	size_t		 maxsize; /* allocated size (0 = volatile) */
	size_t		 unit;	/* realloc unit size (0 = read-only) */
	int 		 buffer_free; /* obj should be freed */
};

TAILQ_HEAD(lowdown_nodeq, lowdown_node);

enum 	htbl_flags {
	HTBL_FL_ALIGN_LEFT = 1,
	HTBL_FL_ALIGN_RIGHT = 2,
	HTBL_FL_ALIGN_CENTER = 3,
	HTBL_FL_ALIGNMASK = 3,
	HTBL_FL_HEADER = 4
};

enum 	halink_type {
	HALINK_NONE, /* used internally when it is not an autolink */
	HALINK_NORMAL,
	HALINK_EMAIL
};

enum	hlist_fl {
	HLIST_FL_ORDERED = (1 << 0), /* <ol> list item */
	HLIST_FL_BLOCK = (1 << 1), /* <li> containing block data */
	HLIST_FL_UNORDERED = (1 << 2), /* <ul> list item */
	HLIST_FL_DEF = (1 << 3), /* <dl> list item */
	HLIST_FL_CHECKED = (1 << 4), /* <li> with checked box */
	HLIST_FL_UNCHECKED = (1 << 5), /* <li> with unchecked box */
};

/*
 * Meta-data keys and values.
 * Both of these are non-NULL (but possibly empty).
 */
struct	lowdown_meta {
	char		*key;
	char		*value;
	TAILQ_ENTRY(lowdown_meta) entries;
};

TAILQ_HEAD(lowdown_metaq, lowdown_meta);

enum	lowdown_chng {
	LOWDOWN_CHNG_NONE = 0,
	LOWDOWN_CHNG_INSERT,
	LOWDOWN_CHNG_DELETE,
};

struct	rndr_meta {
	struct lowdown_buf key;
};

struct	rndr_paragraph {
	size_t lines;
	int beoln;
};

struct	rndr_normal_text {
	struct lowdown_buf text;
};

struct	rndr_entity {
	struct lowdown_buf text;
};

struct	rndr_autolink {
	struct lowdown_buf link;
	enum halink_type type;
};

struct	rndr_raw_html {
	struct lowdown_buf text;
};

struct	rndr_link {
	struct lowdown_buf link;
	struct lowdown_buf title;
	struct lowdown_buf attr_cls;
	struct lowdown_buf attr_id;
};

struct	rndr_blockcode {
	struct lowdown_buf text;
	struct lowdown_buf lang;
};

struct	rndr_definition {
	enum hlist_fl flags;
};

struct	rndr_codespan {
	struct lowdown_buf text;
};

struct	rndr_table{
	size_t columns;
};

struct	rndr_table_header {
	enum htbl_flags *flags;
	size_t columns;
};

struct	rndr_table_cell {
	enum htbl_flags flags;
	size_t col;
	size_t columns;
};

struct	rndr_blockhtml {
	struct lowdown_buf text;
};

struct	rndr_list {
	enum hlist_fl flags;
	size_t start;
};

struct	rndr_listitem {
	enum hlist_fl flags;
	size_t num;
};

struct	rndr_header{
	size_t level;
	struct lowdown_buf attr_cls;
	struct lowdown_buf attr_id;
};

struct	rndr_image {
	struct lowdown_buf link;
	struct lowdown_buf title;
	struct lowdown_buf dims;
	struct lowdown_buf alt;
	struct lowdown_buf attr_width;
	struct lowdown_buf attr_height;
	struct lowdown_buf attr_cls;
	struct lowdown_buf attr_id;
};

struct rndr_math {
	struct lowdown_buf text;
	int blockmode;
};

/*
 * Node parsed from input document.
 * Each node is part of the parse tree.
 */
struct	lowdown_node {
	enum lowdown_rndrt	 type;
	enum lowdown_chng	 chng; /* change type */
	size_t			 id; /* unique identifier */
	union {
		struct rndr_meta rndr_meta;
		struct rndr_list rndr_list; 
		struct rndr_paragraph rndr_paragraph;
		struct rndr_listitem rndr_listitem; 
		struct rndr_header rndr_header; 
		struct rndr_normal_text rndr_normal_text; 
		struct rndr_entity rndr_entity; 
		struct rndr_autolink rndr_autolink; 
		struct rndr_raw_html rndr_raw_html; 
		struct rndr_link rndr_link; 
		struct rndr_blockcode rndr_blockcode; 
		struct rndr_definition rndr_definition; 
		struct rndr_codespan rndr_codespan; 
		struct rndr_table rndr_table; 
		struct rndr_table_header rndr_table_header; 
		struct rndr_table_cell rndr_table_cell; 
		struct rndr_image rndr_image;
		struct rndr_math rndr_math;
		struct rndr_blockhtml rndr_blockhtml;
	};
	struct lowdown_node *parent;
	struct lowdown_nodeq children;
	TAILQ_ENTRY(lowdown_node) entries;
};

struct	lowdown_opts_odt {
	const char		*sty;
};

struct	lowdown_opts {
	enum lowdown_type	  type;
	union {
		struct lowdown_opts_odt odt;
	};
	size_t			  maxdepth;
	size_t			  cols;
	size_t			  hmargin;
	size_t			  vmargin;
	unsigned int		  feat;
#define LOWDOWN_TABLES		  0x01
#define LOWDOWN_FENCED		  0x02
#define LOWDOWN_FOOTNOTES	  0x04
#define LOWDOWN_AUTOLINK	  0x08
#define LOWDOWN_STRIKE		  0x10
/* Omitted 			  0x20 */
#define LOWDOWN_HILITE		  0x40
/* Omitted 			  0x80 */
#define LOWDOWN_SUPER		  0x100
#define LOWDOWN_MATH		  0x200
#define LOWDOWN_NOINTEM		  0x400
/* Disabled LOWDOWN_MATHEXP	  0x1000 */
#define LOWDOWN_NOCODEIND	  0x2000
#define	LOWDOWN_METADATA	  0x4000
#define	LOWDOWN_COMMONMARK	  0x8000
#define	LOWDOWN_DEFLIST		  0x10000
#define	LOWDOWN_IMG_EXT	 	  0x20000 /* -> LOWDOWN_ATTRS */
#define LOWDOWN_TASKLIST	  0x40000
#define LOWDOWN_ATTRS		  0x80000
	unsigned int		  oflags;
#define	LOWDOWN_GEMINI_LINK_END	  0x8000 /* links at end */
#define	LOWDOWN_GEMINI_LINK_IN	  0x10000 /* links inline */
#define	LOWDOWN_GEMINI_LINK_NOREF 0x200000 /* for !inline, no names */
#define	LOWDOWN_GEMINI_LINK_ROMAN 0x400000 /* roman link names */
#define	LOWDOWN_HTML_NUM_ENT	  0x1000 /* use &#nn; if possible */
#define	LOWDOWN_HTML_OWASP	  0x800 /* use OWASP escaping */
#define	LOWDOWN_ODT_SKIP_HTML	  0x2000000 /* skip all HTML */
#define	LOWDOWN_SMARTY	  	  0x40 /* smart typography */
#define	LOWDOWN_TERM_NOANSI	  0x1000000 /* no ANSI escapes at all */
#define	LOWDOWN_TERM_NOCOLOUR	  0x800000 /* no ANSI colours */
#define LOWDOWN_GEMINI_METADATA	  0x100000 /* show metadata */
#define LOWDOWN_HTML_ESCAPE	  0x02 /* escape HTML (if not skip) */
#define LOWDOWN_HTML_HARD_WRAP	  0x04 /* paragraph line breaks */
#define LOWDOWN_HTML_HEAD_IDS	  0x100 /* <hN id="the_name"> */
#define LOWDOWN_HTML_SKIP_HTML	  0x01 /* skip all HTML */
#define LOWDOWN_LATEX_NUMBERED	  0x4000 /* numbered sections */
#define LOWDOWN_LATEX_SKIP_HTML	  0x2000 /* skip all HTML */
#define LOWDOWN_NROFF_GROFF	  0x20 /* use groff extensions */
/* Disable LOWDOWN_NROFF_HARD_WRAP 0x10 */
#define LOWDOWN_NROFF_NOLINK	  0x80000 /* don't show URLs */
#define LOWDOWN_NROFF_NUMBERED	  0x80 /* numbered section headers */
#define LOWDOWN_NROFF_SHORTLINK	  0x40000 /* shorten URLs */
#define LOWDOWN_NROFF_SKIP_HTML	  0x08 /* skip all HTML */
#define LOWDOWN_STANDALONE	  0x200 /* emit complete document */
#define LOWDOWN_TERM_NOLINK	  0x20000 /* don't show URLs */
#define LOWDOWN_TERM_SHORTLINK	  0x400 /* shorten URLs */
	char			**meta;
	size_t			  metasz;
	char			**metaovr;
	size_t			  metaovrsz;
};

struct lowdown_doc;

__BEGIN_DECLS

/*
 * High-level functions.
 * These use the "lowdown_opts" to determine how to parse and render
 * content, and extract that content from a buffer, file, or descriptor.
 */
int	 lowdown_buf(const struct lowdown_opts *, 
		const char *, size_t,
		char **, size_t *, struct lowdown_metaq *);
int	 lowdown_buf_diff(const struct lowdown_opts *, 
		const char *, size_t, const char *, size_t,
		char **, size_t *);
int	 lowdown_file(const struct lowdown_opts *, 
		FILE *, char **, size_t *, struct lowdown_metaq *);
int	 lowdown_file_diff(const struct lowdown_opts *, FILE *, 
		FILE *, char **, size_t *);

/* 
 * Low-level functions.
 * These actually parse and render the AST from a buffer in various
 * ways.
 */

struct lowdown_buf
	*lowdown_buf_new(size_t) __attribute__((malloc));
void	 lowdown_buf_free(struct lowdown_buf *);

struct lowdown_doc
	*lowdown_doc_new(const struct lowdown_opts *);
struct lowdown_node
	*lowdown_doc_parse(struct lowdown_doc *, size_t *,
		const char *, size_t, struct lowdown_metaq *);
struct lowdown_node
	*lowdown_diff(const struct lowdown_node *,
		const struct lowdown_node *, size_t *);
void	 lowdown_doc_free(struct lowdown_doc *);
void	 lowdown_metaq_free(struct lowdown_metaq *);

void 	 lowdown_node_free(struct lowdown_node *);

void	 lowdown_html_free(void *);
void	*lowdown_html_new(const struct lowdown_opts *);
int 	 lowdown_html_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

void	 lowdown_gemini_free(void *);
void	*lowdown_gemini_new(const struct lowdown_opts *);
int 	 lowdown_gemini_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

void	 lowdown_term_free(void *);
void	*lowdown_term_new(const struct lowdown_opts *);
int 	 lowdown_term_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

void	 lowdown_nroff_free(void *);
void	*lowdown_nroff_new(const struct lowdown_opts *);
int 	 lowdown_nroff_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

int 	 lowdown_tree_rndr(struct lowdown_buf *, 
		const struct lowdown_node *);

void	 lowdown_latex_free(void *);
void	*lowdown_latex_new(const struct lowdown_opts *);
int 	 lowdown_latex_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

void	 lowdown_odt_free(void *);
void	*lowdown_odt_new(const struct lowdown_opts *);
int 	 lowdown_odt_rndr(struct lowdown_buf *, void *, 
		const struct lowdown_node *);

__END_DECLS

#endif /* !LOWDOWN_H */

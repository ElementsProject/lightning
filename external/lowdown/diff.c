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
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <float.h>
#include <math.h>
#if HAVE_MD5
# include <md5.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowdown.h"
#include "libdiff.h"
#include "extern.h"

/*
 * If "node" is not NULL, this represents our match attempts for a
 * single node in a node tree.  We basically use "optmatch" and "opt" to
 * keep trying to find the most optimal candidate in the other tree,
 * which ends up being "match".
 */
struct	xnode {
	char		 		 sig[MD5_DIGEST_STRING_LENGTH];
	double		 		 weight; /* queue weight */
	const struct lowdown_node 	*node; /* basis node */
	const struct lowdown_node 	*match; /* matching node */
	size_t		 		 opt; /* match optimality */
	const struct lowdown_node 	*optmatch; /* current optimal */
};

/*
 * A map of all nodes in the current tree by their ID.  A map can have
 * holes (in which case the xnode's "node" is NULL) since we collapse
 * adjacent text nodes as a preprocess.
 */
struct	xmap {
	struct xnode	*nodes; /* holey table */
	size_t		 maxsize; /* size of "nodes" */
	size_t		 maxid; /* max node id */
	size_t		 maxnodes; /* non-NULL count */
	double		 maxweight; /* node weight */
};

/*
 * Queue of nodes.  This is used in creating the priority queue of next
 * nodes to parse.
 */
struct	pnode {
	const struct lowdown_node	*node; /* priority node */
	TAILQ_ENTRY(pnode) 	 	 entries;
};

/*
 * Convenience structure to hold maps we use when merging together the
 * trees.
 */
struct	merger {
	const struct xmap *xoldmap; /* source xnodes */
	const struct xmap *xnewmap; /* destination xnodes */
	size_t		   id; /* maxid in new tree */
};

TAILQ_HEAD(pnodeq, pnode);

/*
 * A node used in computing the shortest edit script.
 */
struct	sesnode {
	char		*buf; /* buffer */
	size_t		 bufsz; /* length of buffer (less NUL) */
	int		 tailsp; /* whether there's trailing space */
	int		 headsp; /* whether there's leading space */
};

static void
MD5Updatebuf(MD5_CTX *ctx, const struct lowdown_buf *v)
{

	assert(v != NULL);
	MD5Update(ctx, (const uint8_t *)v->data, v->size);
}

static void
MD5Updatev(MD5_CTX *ctx, const void *v, size_t sz)
{

	assert(v != NULL);
	MD5Update(ctx, (const unsigned char *)v, sz);
}

/*
 * If this returns non-zero, the node should be considered opaque and
 * we will not do any difference processing within it.  It will still be
 * marked with weight and signature from child nodes and interior data.
 */
static int
is_opaque(const struct lowdown_node *n)
{

	assert(n != NULL);
	return n->type == LOWDOWN_TABLE_BLOCK ||
		n->type == LOWDOWN_META;
}

/*
 * Assign signatures and weights.
 * This is defined by "Phase 2" in sec. 5.2., along with the specific
 * heuristics given in the "Tuning" section.
 * We use the MD5 algorithm for computing hashes.
 * Returns the weight of the node rooted at "n".
 * If "parent" is not NULL, its hash is updated with the hash computed
 * for the current "n" and its children.
 * Return <0 on failure.
 */
static double
assign_sigs(MD5_CTX *parent, struct xmap *map, 
	const struct lowdown_node *n, int ign)
{
	const struct lowdown_node	*nn;
	ssize_t				 weight = -1;
	MD5_CTX				 ctx;
	double				 v = 0.0, vv;
	struct xnode			*xn;
	struct xnode			 xntmp;
	void				*pp;
	int				 ign_chld = ign;

	/* 
	 * Get our node slot unless we're ignoring the node.
	 * Ignoring comes when a parent in our chain is opaque.
	 */

	if (!ign) {
		if (n->id >= map->maxsize) {
			pp = recallocarray(map->nodes, map->maxsize, 
				n->id + 64, sizeof(struct xnode));
			if (pp == NULL)
				return -1.0;
			map->nodes = pp;
			map->maxsize = n->id + 64;
		}
		xn = &map->nodes[n->id];
		assert(xn->node == NULL);
		assert(xn->weight == 0.0);
		xn->node = n;
		if (n->id > map->maxid)
			map->maxid = n->id;
		assert(map->maxid < map->maxsize);
		map->maxnodes++;
		ign_chld = is_opaque(n);
	}

	/* Recursive step. */

	MD5Init(&ctx);
	MD5Updatev(&ctx, &n->type, sizeof(enum lowdown_rndrt));

	TAILQ_FOREACH(nn, &n->children, entries) {
		if ((vv = assign_sigs(&ctx, map, nn, ign_chld)) < 0.0)
			return vv;
		v += vv;
	}

	/* Re-assign "xn": child might have reallocated. */

	memset(&xntmp, 0, sizeof(struct xnode));
	xn = ign ? &xntmp : &map->nodes[n->id];
	xn->weight = v;

	/*
	 * Compute our weight.
	 * The weight is either the log of the contained text length for
	 * leaf nodes or the accumulated sub-element weight for
	 * non-terminal nodes plus one.
	 */

	switch (n->type) {
	case LOWDOWN_BLOCKCODE:
		weight = n->rndr_blockcode.text.size;
		break;
	case LOWDOWN_BLOCKHTML:
		weight = n->rndr_blockhtml.text.size;
		break;
	case LOWDOWN_LINK_AUTO:
		weight = n->rndr_autolink.link.size;
		break;
	case LOWDOWN_CODESPAN:
		weight = n->rndr_codespan.text.size;
		break;
	case LOWDOWN_META:
		weight = n->rndr_meta.key.size;
		break;
	case LOWDOWN_IMAGE:
		weight = n->rndr_image.link.size +
			n->rndr_image.title.size +
			n->rndr_image.dims.size +
			n->rndr_image.alt.size;
		break;
	case LOWDOWN_RAW_HTML:
		weight = n->rndr_raw_html.text.size;
		break;
	case LOWDOWN_NORMAL_TEXT:
		weight = n->rndr_normal_text.text.size;
		break;
	case LOWDOWN_ENTITY:
		weight = n->rndr_entity.text.size;
		break;
	default:
		break;
	}

	/* Weight can be zero if text size is zero. */

	if (weight >= 0)
		xn->weight = 1.0 + (weight == 0 ? 0.0 : log(weight));
	else
		xn->weight += 1.0;

	/*
	 * Augment our signature from our attributes.
	 * This depends upon the node.
	 * Avoid using attributes that are "mutable" relative to the
	 * generated output, e.g., list display numbers.
	 */

	switch (n->type) {
	case LOWDOWN_LIST:
		MD5Updatev(&ctx, &n->rndr_list.flags, 
			sizeof(enum hlist_fl));
		break;
	case LOWDOWN_LISTITEM:
		MD5Updatev(&ctx, &n->rndr_listitem.flags, 
			sizeof(enum hlist_fl));
		MD5Updatev(&ctx, &n->rndr_listitem.num, 
			sizeof(size_t));
		break;
	case LOWDOWN_HEADER:
		MD5Updatev(&ctx, &n->rndr_header.level, 
			sizeof(size_t));
		break;
	case LOWDOWN_NORMAL_TEXT:
		MD5Updatebuf(&ctx, &n->rndr_normal_text.text);
		break;
	case LOWDOWN_META:
		MD5Updatebuf(&ctx, &n->rndr_meta.key);
		break;
	case LOWDOWN_ENTITY:
		MD5Updatebuf(&ctx, &n->rndr_entity.text);
		break;
	case LOWDOWN_LINK_AUTO:
		MD5Updatebuf(&ctx, &n->rndr_autolink.link);
		MD5Updatev(&ctx, &n->rndr_autolink.type, 
			sizeof(enum halink_type));
		break;
	case LOWDOWN_RAW_HTML:
		MD5Updatebuf(&ctx, &n->rndr_raw_html.text);
		break;
	case LOWDOWN_LINK:
		MD5Updatebuf(&ctx, &n->rndr_link.link);
		MD5Updatebuf(&ctx, &n->rndr_link.title);
		break;
	case LOWDOWN_BLOCKCODE:
		MD5Updatebuf(&ctx, &n->rndr_blockcode.text);
		MD5Updatebuf(&ctx, &n->rndr_blockcode.lang);
		break;
	case LOWDOWN_CODESPAN:
		MD5Updatebuf(&ctx, &n->rndr_codespan.text);
		break;
	case LOWDOWN_TABLE_HEADER:
		MD5Updatev(&ctx, &n->rndr_table_header.columns,
			sizeof(size_t));
		break;
	case LOWDOWN_TABLE_CELL:
		MD5Updatev(&ctx, &n->rndr_table_cell.flags,
			sizeof(enum htbl_flags));
		MD5Updatev(&ctx, &n->rndr_table_cell.col,
			sizeof(size_t));
		break;
	case LOWDOWN_IMAGE:
		MD5Updatebuf(&ctx, &n->rndr_image.link);
		MD5Updatebuf(&ctx, &n->rndr_image.title);
		MD5Updatebuf(&ctx, &n->rndr_image.dims);
		MD5Updatebuf(&ctx, &n->rndr_image.alt);
		break;
	case LOWDOWN_MATH_BLOCK:
		MD5Updatev(&ctx, &n->rndr_math.blockmode, 
			sizeof(int));
		break;
	case LOWDOWN_BLOCKHTML:
		MD5Updatebuf(&ctx, &n->rndr_blockhtml.text);
		break;
	default:
		break;
	}

	MD5End(&ctx, xn->sig);

	if (parent != NULL)
		MD5Update(parent, (uint8_t *)xn->sig, 
			MD5_DIGEST_STRING_LENGTH - 1);

	if (xn->weight > map->maxweight)
		map->maxweight = xn->weight;

	assert(isfinite(xn->weight));
	assert(isnormal(xn->weight));
	assert(xn->weight > 0.0);
	return xn->weight;
}

/*
 * Enqueue "n" into a priority queue "pq".
 * Priority is given to weights; and if weights are equal, then
 * proximity to the parse root given by a pre-order identity.
 * FIXME: use a priority heap.
 * Return zero on failure, non-zero on success.
 */
static int
pqueue(const struct lowdown_node *n, 
	struct xmap *map, struct pnodeq *pq)
{
	struct pnode	*p, *pp;
	struct xnode	*xnew, *xold;

	if ((p = malloc(sizeof(struct pnode))) == NULL)
		return 0;
	p->node = n;

	xnew = &map->nodes[n->id];
	assert(xnew != NULL);
	assert(xnew->node != NULL);

	TAILQ_FOREACH(pp, pq, entries) {
		xold = &map->nodes[pp->node->id];
		assert(xold->node != NULL);
		if (xnew->weight >= xold->weight)
			break;
	}

	if (pp == NULL) {
		TAILQ_INSERT_TAIL(pq, p, entries);
		return 1;
	} else if (xnew->weight > xold->weight) {
		TAILQ_INSERT_BEFORE(pp, p, entries);
		return 1;
	}

	for (; pp != NULL; pp = TAILQ_NEXT(pp, entries)) {
		assert(p->node->id != pp->node->id);
		if (p->node->id < pp->node->id)
			break;
	}

	if (pp == NULL) 
		TAILQ_INSERT_TAIL(pq, p, entries);
	else
		TAILQ_INSERT_BEFORE(pp, p, entries);
	return 1;
}

/*
 * Candidate optimality between "xnew" and "xold" as described in "Phase
 * 3" of sec. 5.2.
 * This also uses the heuristic described in "Tuning" for how many
 * levels to search upward.
 */
static size_t
optimality(struct xnode *xnew, struct xmap *xnewmap,
	struct xnode *xold, struct xmap *xoldmap)
{
	size_t	 opt = 1, d, i = 0;

	/* Height: log(n) * W/W_0 or at least 1. */

	d = ceil(log(xnewmap->maxnodes) * 
		xnew->weight / xnewmap->maxweight);

	if (d == 0)
		d = 1;
	
	/* FIXME: are we supposed to bound to "d"? */

	while (xnew->node->parent != NULL &&
	       xold->node->parent != NULL && i < d) {
		xnew = &xnewmap->nodes[xnew->node->parent->id];
		xold = &xoldmap->nodes[xold->node->parent->id];
		if (xnew->match != NULL && xnew->match == xold->node) 
			opt++;
		i++;
	}

	return opt;
}

/*
 * Compute the candidacy of "xnew" to "xold" as described in "Phase 3"
 * of sec. 5.2 and using the optimality() function as a basis.
 * If "xnew" does not have a match assigned (no prior candidacy), assign
 * it immediately to "xold".
 * If it does, then compute the optimality and select the greater of the
 * two optimalities.
 * As an extension to the paper, if the optimalities are equal, use the
 * "closer" node to the current identifier.
 */
static void
candidate(struct xnode *xnew, struct xmap *xnewmap,
	struct xnode *xold, struct xmap *xoldmap)
{
	size_t		 opt;
	long long	 dnew, dold;

	assert(xnew->node != NULL);
	assert(xold->node != NULL);

	if (xnew->optmatch == NULL) {
		xnew->optmatch = xold->node;
		xnew->opt = optimality(xnew, xnewmap, xold, xoldmap);
		return;
	}

	opt = optimality(xnew, xnewmap, xold, xoldmap);

	if (opt == xnew->opt) {
		/*
		 * Use a simple norm over the identifier space.
		 * Choose the lesser of the norms.
		 */
		dold = llabs((long long)
			(xnew->optmatch->id - xnew->node->id));
		dnew = llabs((long long)
			(xold->node->id - xnew->node->id));
		if (dold > dnew) {
			xnew->optmatch = xold->node;
			xnew->opt = opt;
		}
	} else if (opt > xnew->opt) {
		xnew->optmatch = xold->node;
		xnew->opt = opt;
	} 
}

/*
 * Do the two internal nodes equal each other?
 * This depends upon the node type.
 * By default, all similarly-labelled (typed) nodes are equal.
 */
static int
match_eq(const struct lowdown_node *n1, 
	const struct lowdown_node *n2)
{

	if (n1->type != n2->type)
		return 0;

	switch (n1->type) {
	case LOWDOWN_LINK:
		if (!hbuf_eq
		    (&n1->rndr_link.link, &n2->rndr_link.link))
			return 0;
		if (!hbuf_eq
		    (&n1->rndr_link.title, &n2->rndr_link.title))
			return 0;
		break;
	case LOWDOWN_HEADER:
		if (n1->rndr_header.level != n2->rndr_header.level)
			return 0;
		break;
	case LOWDOWN_META:
		if (!hbuf_eq
		    (&n1->rndr_meta.key, &n2->rndr_meta.key))
			return 0;
		break;
	case LOWDOWN_LISTITEM:
		if (n1->rndr_listitem.num != n2->rndr_listitem.num)
			return 0;
		if (n1->rndr_listitem.flags != n2->rndr_listitem.flags)
			return 0;
		break;
	default:
		break;
	}

	return 1;
}

/*
 * Return non-zero if this node is the only child.
 */
static int
match_singleton(const struct lowdown_node *n)
{

	if (n->parent == NULL)
		return 1;
	return TAILQ_NEXT(n, entries) == 
	       TAILQ_PREV(n, lowdown_nodeq, entries);
}

/*
 * Algorithm to "propogate up" according to "Phase 3" of sec. 5.2.
 * This also uses the heuristic described in "Tuning" for how many
 * levels to search upward.
 * I augment this by making singleton children pass upward.
 * FIXME: right now, this doesn't clobber existing upward matches.  Is
 * that correct behaviour?
 */
static void
match_up(struct xnode *xnew, struct xmap *xnewmap,
	struct xnode *xold, struct xmap *xoldmap)
{
	size_t	 d, i = 0;

	/* Height: log(n) * W/W_0 or at least 1. */

	d = ceil(log(xnewmap->maxnodes) * 
		xnew->weight / xnewmap->maxweight);
	if (d == 0)
		d = 1;

	while (xnew->node->parent != NULL &&
	       xold->node->parent != NULL && i < d) {
		/* Are the "labels" the same? */
		if (!match_eq(xnew->node->parent, xold->node->parent))
			break;
		xnew = &xnewmap->nodes[xnew->node->parent->id];
		xold = &xoldmap->nodes[xold->node->parent->id];
		if (xold->match != NULL || xnew->match != NULL)
			break;
		xnew->match = xold->node;
		xold->match = xnew->node;
		i++;
	}

	if (i != d)
		return;

	/* 
	 * Pass up singletons.
	 * This is an extension of the algorithm.
	 */

	while (xnew->node->parent != NULL &&
	       xold->node->parent != NULL) {
		if (!match_singleton(xnew->node) ||
		    !match_singleton(xold->node))
			break;
		if (!match_eq(xnew->node->parent, xold->node->parent))
			break;
		xnew = &xnewmap->nodes[xnew->node->parent->id];
		xold = &xoldmap->nodes[xold->node->parent->id];
		if (xold->match != NULL || xnew->match != NULL)
			break;
		xnew->match = xold->node;
		xold->match = xnew->node;
	}
}

/*
 * Algorithm that "propogates down" according to "Phase 3" of sec. 5.2.
 * This (recursively) makes sure that a matched tree has all of the
 * subtree nodes also matched.
 */
static void
match_down(struct xnode *xnew, struct xmap *xnewmap,
	struct xnode *xold, struct xmap *xoldmap)
{
	struct lowdown_node *nnew, *nold;

	/* 
	 * If we're matching into a component that has already been
	 * matched, we're in the subtree proper (the subtree root is
	 * checked that it's not already matched) and the fact that this
	 * is within a match indicates we're more the "larger" of the
	 * matches, so unset its match status.
	 */

	if (xold->match != NULL) {
		assert(xold->node == 
			xnewmap->nodes[xold->match->id].match);
		xnewmap->nodes[xold->match->id].match = NULL;
		xold->match = NULL;
	}

	assert(xnew->match == NULL);
	assert(xold->match == NULL);

	xnew->match = xold->node;
	xold->match = xnew->node;

	if (is_opaque(xnew->node)) {
		assert(is_opaque(xold->node));
		return;
	}

	nnew = TAILQ_FIRST(&xnew->node->children);
	nold = TAILQ_FIRST(&xold->node->children);

	while (nnew != NULL) {
		assert(NULL != nold);
		xnew = &xnewmap->nodes[nnew->id];
		xold = &xoldmap->nodes[nold->id];
		match_down(xnew, xnewmap, xold, xoldmap);
		nnew = TAILQ_NEXT(nnew, entries);
		nold = TAILQ_NEXT(nold, entries);
	}
	assert(nold == NULL);
}

/*
 * Clone a single node and all of its "attributes".
 * That is, its type and "leaf node" data.
 * Assign the identifier as given.
 * Note that some attributes, such as the table column array, aren't
 * copied.
 * We'll re-create those later.
 */
static struct lowdown_node *
node_clone(const struct lowdown_node *v, size_t id)
{
	struct lowdown_node	*n;
	int			 rc = 1;
	size_t			 i;

	if ((n = calloc(1, sizeof(struct lowdown_node))) == NULL)
		return NULL;

	TAILQ_INIT(&n->children);
	n->type = v->type;
	n->id = id;

	switch (n->type) {
	case LOWDOWN_DEFINITION:
		n->rndr_definition.flags =
			v->rndr_definition.flags;
		break;
	case LOWDOWN_META:
		rc = hbuf_clone(&v->rndr_meta.key, 
			&n->rndr_meta.key);
		break;
	case LOWDOWN_LIST:
		n->rndr_list.flags = v->rndr_list.flags;
		break;
	case LOWDOWN_LISTITEM:
		n->rndr_listitem.flags = v->rndr_listitem.flags;
		n->rndr_listitem.num = v->rndr_listitem.num;
		break;
	case LOWDOWN_HEADER:
		n->rndr_header.level = v->rndr_header.level;
		break;
	case LOWDOWN_NORMAL_TEXT:
		rc = hbuf_clone(&v->rndr_normal_text.text,
			&n->rndr_normal_text.text);
		break;
	case LOWDOWN_ENTITY:
		rc = hbuf_clone(&v->rndr_entity.text,
			&n->rndr_entity.text);
		break;
	case LOWDOWN_LINK_AUTO:
		rc = hbuf_clone(&v->rndr_autolink.link,
			&n->rndr_autolink.link);
		n->rndr_autolink.type = v->rndr_autolink.type;
		break;
	case LOWDOWN_RAW_HTML:
		rc = hbuf_clone(&v->rndr_raw_html.text,
			&n->rndr_raw_html.text);
		break;
	case LOWDOWN_LINK:
		rc = hbuf_clone(&v->rndr_link.link,
			&n->rndr_link.link) &&
		     hbuf_clone(&v->rndr_link.title,
			&n->rndr_link.title);
		break;
	case LOWDOWN_BLOCKCODE:
		rc = hbuf_clone(&v->rndr_blockcode.text,
			&n->rndr_blockcode.text) &&
		     hbuf_clone(&v->rndr_blockcode.lang,
			&n->rndr_blockcode.lang);
		break;
	case LOWDOWN_CODESPAN:
		rc = hbuf_clone(&v->rndr_codespan.text,
			&n->rndr_codespan.text);
		break;
	case LOWDOWN_TABLE_BLOCK:
		n->rndr_table.columns = v->rndr_table.columns;
		break;
	case LOWDOWN_TABLE_HEADER:
		n->rndr_table_header.columns = 
			v->rndr_table_header.columns;
		n->rndr_table_header.flags = calloc
			(n->rndr_table_header.columns, 
			 sizeof(enum htbl_flags));
		if (n->rndr_table_header.flags == NULL)
			return NULL;
		for (i = 0; i < n->rndr_table_header.columns; i++)
			n->rndr_table_header.flags[i] =
				v->rndr_table_header.flags[i];
		break;
	case LOWDOWN_TABLE_CELL:
		n->rndr_table_cell.flags = 
			v->rndr_table_cell.flags;
		n->rndr_table_cell.col = 
			v->rndr_table_cell.col;
		n->rndr_table_cell.columns = 
			v->rndr_table_cell.columns;
		break;
	case LOWDOWN_IMAGE:
		rc = hbuf_clone(&v->rndr_image.link,
			&n->rndr_image.link) &&
		     hbuf_clone(&v->rndr_image.title,
			&n->rndr_image.title) &&
		     hbuf_clone(&v->rndr_image.dims,
			&n->rndr_image.dims) &&
		     hbuf_clone(&v->rndr_image.alt,
			&n->rndr_image.alt);
		break;
	case LOWDOWN_MATH_BLOCK:
		n->rndr_math.blockmode = 
			v->rndr_math.blockmode;
		break;
	case LOWDOWN_BLOCKHTML:
		rc = hbuf_clone(&v->rndr_blockhtml.text,
			&n->rndr_blockhtml.text);
		break;
	default:
		break;
	}

	if (!rc) {
		lowdown_node_free(n);
		n = NULL;
	}

	return n;
}

/*
 * Take the sub-tree "v" and clone it and all of the nodes beneath it,
 * returning the cloned node.
 * This starts using identifiers at "id".
 */
static struct lowdown_node *
node_clonetree(const struct lowdown_node *v, size_t *id)
{
	struct lowdown_node *n, *nn;
	const struct lowdown_node *vv;

	if ((n = node_clone(v, *id++)) == NULL)
		return NULL;

	TAILQ_FOREACH(vv, &v->children, entries) {
		if ((nn = node_clonetree(vv, id)) == NULL)
			goto out;
		TAILQ_INSERT_TAIL(&n->children, nn, entries);
		nn->parent = n;
	}

	return n;
out:
	lowdown_node_free(n);
	return NULL;
}

/*
 * Count the number of words in a normal-text node.
 */
static size_t
node_countwords(const struct lowdown_node *n)
{
	const char	*cp;
	size_t		 i = 0, sz, words = 0;

	cp = n->rndr_normal_text.text.data;
	sz = n->rndr_normal_text.text.size;

	/* Skip leading space. */

	while (i < sz &&
	       isspace((unsigned char)cp[i]))
		i++;

	/* First go through word, then trailing space. */

	while (i < sz) {
		assert(!isspace((unsigned char)cp[i]));
		words++;
		while (i < sz &&
		       !isspace((unsigned char)cp[i]))
			i++;
		while (i < sz && 
		       isspace((unsigned char)cp[i]))
			i++;
	}

	return words;
}

/*
 * Like node_countwords(), except dupping individual words into a
 * structure.
 * Return zero on failure (memory), non-zero on success.
 */
static int
node_tokenise(const struct lowdown_node *n, 
	struct sesnode *toks, size_t toksz, char **savep)
{
	char	*cp;
	size_t	 i = 0, sz, words = 0;

	*savep = NULL;

	if (toksz == 0)
		return 1;

	sz = n->rndr_normal_text.text.size;
	*savep = cp = malloc(sz + 1);
	if (cp == NULL)
		return 0;
	memcpy(cp, n->rndr_normal_text.text.data, sz);
	cp[sz] = '\0';

	*savep = cp;

	/* Skip leading space. */

	if (i < sz)
		toks[0].headsp = isspace((unsigned char)cp[0]);

	while (i < sz &&
	       isspace((unsigned char)cp[i]))
		i++;

	while (i < sz) {
		assert(words < toksz);
		assert(!isspace((unsigned char)cp[i]));
		toks[words].buf = &cp[i];
		toks[words].bufsz = 0;
		while (i < sz &&
		       !isspace((unsigned char)cp[i])) {
			toks[words].bufsz++;
			i++;
		}
		words++;
		if (i == sz)
			break;
		toks[words - 1].tailsp = 1;
		assert(isspace((unsigned char)cp[i]));
		cp[i++] = '\0';
		while (i < sz && 
		       isspace((unsigned char)cp[i]))
			i++;
	}
	return 1;
}

static int
node_word_cmp(const void *p1, const void *p2)
{
	const struct sesnode *l1 = p1, *l2 = p2;

	if (l1->bufsz != l2->bufsz)
		return 0;
	return 0 == strncmp(l1->buf, l2->buf, l1->bufsz);
}

/*
 * Return zero on failure (memory), non-zero on success.
 */
static int
node_lcs(const struct lowdown_node *nold,
	const struct lowdown_node *nnew,
	struct lowdown_node *n, size_t *id)
{
	const struct sesnode	*tmp;
	struct lowdown_node	*nn;
	struct sesnode		*newtok = NULL, *oldtok = NULL;
	char			*newtokbuf = NULL, *oldtokbuf = NULL;
	size_t			 i, newtoksz, oldtoksz;
	struct diff		 d;
	int			 rc = 0;

	memset(&d, 0, sizeof(struct diff));

	newtoksz = node_countwords(nnew);
	oldtoksz = node_countwords(nold);

	newtok = calloc(newtoksz, sizeof(struct sesnode));
	if (newtok == NULL)
		goto out;
	oldtok = calloc(oldtoksz, sizeof(struct sesnode));
	if (oldtok == NULL)
		goto out;

	if (!node_tokenise(nnew, newtok, newtoksz, &newtokbuf))
		goto out;
	if (!node_tokenise(nold, oldtok, oldtoksz, &oldtokbuf))
		goto out;

	if (!diff(&d, node_word_cmp, sizeof(struct sesnode), 
	    oldtok, oldtoksz, newtok, newtoksz))
		goto out;

	for (i = 0; i < d.sessz; i++) {
		tmp = d.ses[i].e;

		if (tmp->headsp) {
			nn = calloc(1, sizeof(struct lowdown_node));
			if (nn == NULL)
				goto out;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			TAILQ_INIT(&nn->children);

			nn->type = LOWDOWN_NORMAL_TEXT;
			nn->id = (*id)++;
			nn->parent = n;
			nn->rndr_normal_text.text.size = 1;
			nn->rndr_normal_text.text.data = strdup(" ");
			if (nn->rndr_normal_text.text.data == NULL)
				goto out;
		}

		nn = calloc(1, sizeof(struct lowdown_node));
		if (nn == NULL)
			goto out;
		TAILQ_INSERT_TAIL(&n->children, nn, entries);
		TAILQ_INIT(&nn->children);

		nn->type = LOWDOWN_NORMAL_TEXT;
		nn->id = (*id)++;
		nn->parent = n;
		nn->rndr_normal_text.text.size = tmp->bufsz;
		nn->rndr_normal_text.text.data = 
			calloc(1, tmp->bufsz + 1);
		if (nn->rndr_normal_text.text.data == NULL)
			goto out;

		memcpy(nn->rndr_normal_text.text.data,
			tmp->buf, tmp->bufsz);
		nn->chng = DIFF_DELETE == d.ses[i].type ?
			LOWDOWN_CHNG_DELETE :
			DIFF_ADD == d.ses[i].type ?
			LOWDOWN_CHNG_INSERT :
			LOWDOWN_CHNG_NONE;

		if (tmp->tailsp) {
			nn = calloc(1, sizeof(struct lowdown_node));
			if (nn == NULL)
				goto out;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			TAILQ_INIT(&nn->children);
			nn->type = LOWDOWN_NORMAL_TEXT;
			nn->id = (*id)++;
			nn->parent = n;
			nn->rndr_normal_text.text.size = 1;
			nn->rndr_normal_text.text.data = strdup(" ");
			if (nn->rndr_normal_text.text.data == NULL)
				goto out;
		}
	}

	rc = 1;
out:
	free(d.ses);
	free(d.lcs);
	free(newtok);
	free(oldtok);
	free(newtokbuf);
	free(oldtokbuf);
	return rc;
}

/*
 * Merge the new tree "nnew" with the old "nold" using a depth-first
 * algorithm.
 * The produced tree will show the new tree with deleted nodes from the
 * old and inserted ones.
 * It will also show moved nodes by delete/add pairs.
 * This uses "Phase 5" semantics, but implements the merge algorithm
 * without notes from the paper.
 */
static struct lowdown_node *
node_merge(const struct lowdown_node *nold,
	const struct lowdown_node *nnew, struct merger *parms)
{
	const struct xnode		*xnew, *xold;
	struct lowdown_node		*n, *nn;
	const struct lowdown_node	*nnold;
	const struct xmap 		*xoldmap = parms->xoldmap,
	      				*xnewmap = parms->xnewmap;

	/* 
	 * Invariant: the current nodes are matched.
	 * Start by putting that node into the current output.
	 */

	assert(nnew != NULL && nold != NULL );
	xnew = &xnewmap->nodes[nnew->id];
	xold = &xoldmap->nodes[nold->id];
	assert(xnew->match != NULL);
	assert(xold->match != NULL);
	assert(xnew->match == xold->node);

	if ((n = node_clone(nnew, parms->id++)) == NULL)
		goto err;

	/* Now walk through the children on both sides. */

	nold = TAILQ_FIRST(&nold->children);
	nnew = TAILQ_FIRST(&nnew->children);

	while (nnew != NULL) {
		/* 
		 * Begin by flushing out all of the nodes that have been
		 * deleted from the old tree at this level.
		 * According to the paper, deleted nodes have no match.
		 * These will leave us with old nodes that are in the
		 * new tree (not necessarily at this level, though).
		 */

		while (nold != NULL) {
			xold = &xoldmap->nodes[nold->id];
			if (xold->match != NULL ||
			    LOWDOWN_NORMAL_TEXT == nold->type)
				break;
			if ((nn = node_clonetree
			    (nold, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_DELETE;
			nold = TAILQ_NEXT(nold, entries);
		}

		/* 
		 * Now flush inserted nodes.
		 * According to the paper, these have no match.
		 * This leaves us with nodes that are matched somewhere
		 * (not necessarily at this level) with the old.
		 */

		while (nnew != NULL) {
			xnew = &xnewmap->nodes[nnew->id];
			if (xnew->match != NULL ||
			    LOWDOWN_NORMAL_TEXT == nnew->type)
				break;
			if ((nn = node_clonetree
			    (nnew, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_INSERT;
			nnew = TAILQ_NEXT(nnew, entries);
		}

		/*
		 * If both nodes are text nodes, then we want to run the
		 * LCS algorithm on them.
		 * This is an extension of the BULD algorithm.
		 */

		if (nold != NULL && nnew != NULL &&
		    nold->type == LOWDOWN_NORMAL_TEXT &&
		    xold->match == NULL &&
		    nnew->type == LOWDOWN_NORMAL_TEXT &&
		    xnew->match == NULL) {
			if (!node_lcs(nold, nnew, n, &parms->id))
				goto err;
			nold = TAILQ_NEXT(nold, entries);
			nnew = TAILQ_NEXT(nnew, entries);
		}

		while (nold != NULL) {
			xold = &xoldmap->nodes[nold->id];
			if (xold->match != NULL)
				break;
			if ((nn = node_clonetree
			    (nold, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_DELETE;
			nold = TAILQ_NEXT(nold, entries);
		}

		while (nnew != NULL) {
			xnew = &xnewmap->nodes[nnew->id];
			if (xnew->match != NULL)
				break;
			if ((nn = node_clonetree
			    (nnew, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_INSERT;
			nnew = TAILQ_NEXT(nnew, entries);
		}

		/* Nothing more to do at this level? */

		if (nnew == NULL)
			break;

		/*
		 * Now we take the current new node and see if it's a
		 * match with a node in the current level.
		 * If it is, then we can flush out old nodes (moved,
		 * which we call deleted and re-inserted) until we get
		 * to the matching one.
		 * Then we'll be in lock-step with the old tree.
		 */

		xnew = &xnewmap->nodes[nnew->id];
		assert(xnew->match != NULL);

		/* Scan ahead to find a matching old. */
		
		for (nnold = nold; nnold != NULL ; ) {
			xold = &xoldmap->nodes[nnold->id];
			if (xnew->node == xold->match) 
				break;
			nnold = TAILQ_NEXT(nnold, entries);
		}

		/* 
		 * We did not find a match.
		 * This means that the new node has been moved from
		 * somewhere else in the tree.
		 */

		if (nnold == NULL) {
			if ((nn = node_clonetree
			    (nnew, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_INSERT;
			nnew = TAILQ_NEXT(nnew, entries);
			continue;
		}

		/* Match found: flush old nodes til the match. */

		while (nold != NULL) {
			xold = &xoldmap->nodes[nold->id];
			if (xnew->node == xold->match) 
				break;
			if ((nn = node_clonetree
			    (nold, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
			nn->chng = LOWDOWN_CHNG_DELETE;
			nold = TAILQ_NEXT(nold, entries);
		}

		assert(nold != NULL);

		/*
		 * Now we're in lock-step.
		 * Do the recursive step between the matched pair.
		 * Then continue on to the next nodes.
		 */

		if (is_opaque(nnew)) {
			assert(is_opaque(nold));
			if ((nn = node_clonetree
			    (nnew, &parms->id)) == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
		} else {
			assert(!is_opaque(nold));
			nn = node_merge(nold, nnew, parms);
			if (nn == NULL)
				goto err;
			TAILQ_INSERT_TAIL(&n->children, nn, entries);
			nn->parent = n;
		}

		nold = TAILQ_NEXT(nold, entries);
		nnew = TAILQ_NEXT(nnew, entries);
	}

	/* Flush remaining old nodes. */

	while (nold != NULL) {
		if ((nn = node_clonetree (nold, &parms->id)) == NULL)
			goto err;
		TAILQ_INSERT_TAIL(&n->children, nn, entries);
		nn->parent = n;
		nn->chng = LOWDOWN_CHNG_DELETE;
		nold = TAILQ_NEXT(nold, entries);
	}

	return n;
err:
	lowdown_node_free(n);
	return NULL;
}

/*
 * Optimise from top down.
 * This works by selecting matching non-terminal nodes, both adjacent
 * (i.e., children of the same adjacent nodes), and seeing if their
 * immediate siblings may be matched by label.
 * This works well when looking at pure-paragraph changes.
 */
static void
node_optimise_topdown(const struct lowdown_node *n, 
	struct xmap *newmap, struct xmap *oldmap)
{
	struct xnode			*xn, *xmatch, *xnchild, 
					*xmchild, *xnnext, *xmnext;
	const struct lowdown_node	*match, *nchild, *mchild, 
	      				*nnext, *mnext;

	if (is_opaque(n) || TAILQ_EMPTY(&n->children))
		return;

	xn = &newmap->nodes[n->id];
	assert(xn != NULL);

	if ((match = xn->match) == NULL)
		return;

	xmatch = &oldmap->nodes[match->id];
	assert(xmatch != NULL);

	TAILQ_FOREACH(nchild, &n->children, entries) {
		if (is_opaque(nchild) || TAILQ_EMPTY(&nchild->children))
			continue;
		xnchild = &newmap->nodes[nchild->id];
		assert(xnchild != NULL);
		if ((mchild = xnchild->match) == NULL)
			continue;
		if (mchild->parent->id != match->id)
			continue;
		xmchild = &oldmap->nodes[mchild->id];
		assert(xmchild != NULL);

		/* 
		 * Do we have a non-terminal sibling after us without a
		 * match? 
		 */

		if ((nnext = TAILQ_NEXT(nchild, entries)) == NULL)
			continue;
		if (is_opaque(nnext) || TAILQ_EMPTY(&nnext->children))
			continue;
		xnnext = &newmap->nodes[nnext->id];
		assert(xnnext != NULL);
		if (xnnext->match != NULL)
			continue;

		if ((mnext = TAILQ_NEXT(mchild, entries)) == NULL)
			continue;
		if (is_opaque(mnext) || TAILQ_EMPTY(&mnext->children))
			continue;
		xmnext = &oldmap->nodes[mnext->id];
		assert(xmnext != NULL);
		if (xmnext->match != NULL)
			continue;

		if (!match_eq(nnext, mnext))
			continue;

		xnnext->match = mnext;
		xmnext->match = nnext;
	}

	TAILQ_FOREACH(nchild, &n->children, entries)
		node_optimise_topdown(nchild, newmap, oldmap);
}

/*
 * Optimise bottom-up over all un-matched nodes: examine all the
 * children of the un-matched nodes and see which of their matches, if
 * found, are under a root that's the same node as we are.
 * This lets us compute the largest fraction of un-matched nodes'
 * children that are in the same tree.
 * If that fraction is >50%, then we consider that the subtrees are
 * matched.
 */
static void
node_optimise_bottomup(const struct lowdown_node *n, 
	struct xmap *newmap, struct xmap *oldmap)
{
	const struct lowdown_node	*nn, *on, *nnn, *maxn = NULL;
	double				 w, maxw = 0.0, tw = 0.0;

	/* Ignore opaque nodes. */

	if (is_opaque(n) || TAILQ_EMPTY(&n->children))
		return;

	/* Do a depth-first pre-order search. */

	TAILQ_FOREACH(nn, &n->children, entries) {
		tw += newmap->nodes[nn->id].weight;
		node_optimise_bottomup(nn, newmap, oldmap);
	}

	/*
	 * We're now at a non-leaf node.
	 * If we're already matched, then move on.
	 */

	if (newmap->nodes[n->id].match != NULL)
		return;

	TAILQ_FOREACH(nn, &n->children, entries) {
		if (newmap->nodes[nn->id].match == NULL)
			continue;
		if ((on = newmap->nodes[nn->id].match->parent) == NULL)
			continue;
		if (on == maxn)
			continue;
		if (!match_eq(n, on))
			continue;
		
		/*
		 * We've now established "on" as the parent of the
		 * matched node, and that "on" is equivalent.
		 * See what fraction of on's children are matched to our
		 * children.
		 * FIXME: this will harmlessly (except in time) look at
		 * the same parent multiple times.
		 */

		w = 0.0;
		TAILQ_FOREACH(nnn, &n->children, entries) {
			if (newmap->nodes[nnn->id].match == NULL)
				continue;
			if (on != newmap->nodes[nnn->id].match->parent)
				continue;
			w += newmap->nodes[nnn->id].weight;
		}

		/* Is this the highest fraction? */

		if (w > maxw) {
			maxw = w;
			maxn = on;
		}
	}

	/* See if we found any similar sub-trees. */

	if (maxn == NULL)
		return;

	/*
	 * Our magic breakpoint is 50%.
	 * If the matched sub-tree has a greater than 50% match by
	 * weight, then set us as a match!
	 */

	if (maxw / tw >= 0.5) {
		newmap->nodes[n->id].match = maxn;
		oldmap->nodes[maxn->id].match = n;
	}
}

struct lowdown_node *
lowdown_diff(const struct lowdown_node *nold,
	const struct lowdown_node *nnew, size_t *maxn)
{
	struct xmap			 xoldmap, xnewmap;
	struct xnode			*xnew, *xold;
	struct pnodeq			 pq;
	struct pnode			*p;
	const struct lowdown_node	*n, *nn;
	struct lowdown_node		*comp = NULL;
	size_t				 i;
	struct merger			 parms;

	memset(&xoldmap, 0, sizeof(struct xmap));
	memset(&xnewmap, 0, sizeof(struct xmap));

	TAILQ_INIT(&pq);

	/* 
	 * First, assign signatures and weights.
	 * See "Phase 2", sec 5.2.
	 */

	if (assign_sigs(NULL, &xoldmap, nold, 0) < 0.0)
		goto out;
	if (assign_sigs(NULL, &xnewmap, nnew, 0) < 0.0)
		goto out;

	/* Prime the priority queue with the root. */

	if (!pqueue(nnew, &xnewmap, &pq))
		goto out;

	/* 
	 * Match-make while we have nodes in the priority queue.
	 * This is guaranteed to be finite.
	 * See "Phase 3", sec 5.2.
	 */

	while ((p = TAILQ_FIRST(&pq)) != NULL) {
		TAILQ_REMOVE(&pq, p, entries);
		n = p->node;
		free(p);

		xnew = &xnewmap.nodes[n->id];
		assert(xnew->match == NULL);
		assert(xnew->optmatch == NULL);
		assert(xnew->opt == 0);

		/*
		 * Look for candidates: if we have a matching signature,
		 * test for optimality.
		 * Highest optimality gets to be matched.
		 * See "Phase 3", sec. 5.2.
		 */

		for (i = 0; i < xoldmap.maxid + 1; i++) {
			xold = &xoldmap.nodes[i];
			if (xold->node == NULL)
				continue;
			if (xold->match != NULL)
				continue;
			if (strcmp(xnew->sig, xold->sig))
				continue;

			assert(xold->match == NULL);
			candidate(xnew, &xnewmap, xold, &xoldmap);
		}

		/* 
		 * No match: enqueue children ("Phase 3" cont.).
		 * Ignore opaque nodes.
		 */

		if (xnew->optmatch == NULL) {
			if (is_opaque(n))
				continue;
			TAILQ_FOREACH(nn, &n->children, entries)
				if (!pqueue(nn, &xnewmap, &pq))
					goto out;
			continue;
		}

		/*
		 * Match found and is optimal.
		 * Now use the bottom-up and top-down (doesn't matter
		 * which order) algorithms.
		 * See "Phase 3", sec. 5.2.
		 */

		assert(xnew->match == NULL);
		assert(xoldmap.nodes[xnew->optmatch->id].match == NULL);

		match_down(xnew, &xnewmap, 
			&xoldmap.nodes[xnew->optmatch->id], &xoldmap);
		match_up(xnew, &xnewmap, 
			&xoldmap.nodes[xnew->optmatch->id], &xoldmap);
	}

	/*
	 * If our trees are *totally* different, we may end up in the
	 * situation where our root nodes are never matched.  This will
	 * violate an invariant in node_merge() where the entry nodes
	 * are assumed to be matched.
	 */

	if (xnewmap.nodes[nnew->id].match == NULL) {
		assert(nnew->type == LOWDOWN_ROOT);
		assert(nold->type == LOWDOWN_ROOT);
		xnew = &xnewmap.nodes[nnew->id];
		xold = &xoldmap.nodes[nold->id];
		assert(xold->match == NULL);
		xnew->match = xold->node;
		xold->match = xnew->node;
	}

	/*
	 * Following the above, make sure that our LOWDOWN_DOC_HEADER
	 * nodes are also matched, because they are fixed in the tree.
	 */

	n = TAILQ_FIRST(&nnew->children);
	nn = TAILQ_FIRST(&nold->children);
	if (n != NULL && nn != NULL &&
	    n->type == LOWDOWN_DOC_HEADER &&
	    nn->type == LOWDOWN_DOC_HEADER) {
		xnew = &xnewmap.nodes[n->id];
		xold = &xoldmap.nodes[nn->id];
		if (xnew->match == NULL) {
			xnew->match = xold->node;
			xold->match = xnew->node;
		}
	}

	/*
	 * All nodes have been processed.
	 * Now we need to optimise, so run a "Phase 4", sec. 5.2.
	 * Our optimisation is nothing like the paper's.
	 */

	node_optimise_topdown(nnew, &xnewmap, &xoldmap);
	node_optimise_bottomup(nnew, &xnewmap, &xoldmap);

	/*
	 * The tree is optimal.
	 * Now we need to compute the delta and merge the trees.
	 * See "Phase 5", sec. 5.2.
	 */

	memset(&parms, 0, sizeof(struct merger));
	parms.xoldmap = &xoldmap;
	parms.xnewmap = &xnewmap;
	comp = node_merge(nold, nnew, &parms);

	*maxn = xnewmap.maxid > xoldmap.maxid ?
		xnewmap.maxid + 1 :
		xoldmap.maxid + 1;

out:
	assert(comp != NULL);
	while ((p = TAILQ_FIRST(&pq)) != NULL) {
		TAILQ_REMOVE(&pq, p, entries);
		free(p);
	}
	free(xoldmap.nodes);
	free(xnewmap.nodes);
	return comp;
}

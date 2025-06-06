#ifndef LIGHTNING_PLUGINS_ASKRENE_QUEUE_H
#define LIGHTNING_PLUGINS_ASKRENE_QUEUE_H

#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/lqueue/lqueue.h>
#include <ccan/tal/tal.h>

/* Generic and efficient queue based on ccan/lqueue for primitive data.
 * The size of the cache of 64 is the smallest power of two for which I obtain a
 * significant time improvement over directly using lqueue, ie. one lqueue
 * element for each item in the queue. For a small problem sizes (~10) the
 * speed-up is 3x, for large problem sizes
 * (>1000) the speed-up is 7x.
 * ~0.5 operations/nsec */

#define QUEUE_CACHE_SIZE 64

#define QUEUE_DEFINE_TYPE(type, name)                                          \
	struct name##_qcache_ {                                                \
		struct lqueue_link qlink;                                      \
		int begin, end;                                                \
		type data[QUEUE_CACHE_SIZE];                                   \
	};                                                                     \
	static inline UNNEEDED bool name##_qcache_empty_(                      \
	    const struct name##_qcache_ *qc)                                   \
	{                                                                      \
		return qc->begin == qc->end;                                   \
	}                                                                      \
	/* UB if _qcache is empty */                                           \
	static inline UNNEEDED type name##_qcache_front_(                      \
	    const struct name##_qcache_ *qc)                                   \
	{                                                                      \
		return qc->data[qc->begin];                                    \
	}                                                                      \
	static inline UNNEEDED type name##_qcache_pop_(                        \
	    struct name##_qcache_ *qc)                                         \
	{                                                                      \
		type r = name##_qcache_front_(qc);                             \
		qc->begin++;                                                   \
		if (qc->begin >= qc->end) {                                    \
			qc->begin = qc->end = 0;                               \
		}                                                              \
		return r;                                                      \
	}                                                                      \
	static inline UNNEEDED bool name##_qcache_insert_(                     \
	    struct name##_qcache_ *qc, type element)                           \
	{                                                                      \
		if (qc->end == QUEUE_CACHE_SIZE) {                             \
			return false;                                          \
		}                                                              \
		qc->data[qc->end++] = element;                                 \
		return true;                                                   \
	}                                                                      \
	static inline UNNEEDED void name##_qcache_init_(                       \
	    struct name##_qcache_ *qc)                                         \
	{                                                                      \
		qc->begin = qc->end = 0;                                       \
	}                                                                      \
	struct name {                                                          \
		const tal_t *ctx;                                              \
		struct lqueue_ lq;                                             \
	};                                                                     \
	static inline UNNEEDED bool name##_empty(const struct name *q)         \
	{                                                                      \
		return lqueue_empty_(&q->lq);                                  \
	}                                                                      \
	static inline UNNEEDED type name##_front(const struct name *q)         \
	{                                                                      \
		type r;                                                        \
		const struct name##_qcache_ *qc =                              \
		    (const struct name##_qcache_ *)lqueue_front_(&q->lq);      \
		r = name##_qcache_front_(qc);                                  \
		return r;                                                      \
	}                                                                      \
	static inline UNNEEDED type name##_pop(struct name *q)                 \
	{                                                                      \
		type r;                                                        \
		struct name##_qcache_ *qc =                                    \
		    (struct name##_qcache_ *)lqueue_front_(&q->lq);            \
		r = name##_qcache_pop_(qc);                                    \
		if (qc && name##_qcache_empty_(qc)) {                          \
			lqueue_dequeue_(&q->lq);                               \
			tal_free(qc);                                          \
		}                                                              \
		return r;                                                      \
	}                                                                      \
	static inline UNNEEDED void name##_init(struct name *q,                \
						const tal_t *ctx)              \
	{                                                                      \
		q->ctx = ctx;                                                  \
		lqueue_init_(&q->lq, NULL);                                    \
	}                                                                      \
	static inline UNNEEDED void name##_insert(struct name *q,              \
						  type element)                \
	{                                                                      \
		struct name##_qcache_ *qc =                                    \
		    (struct name##_qcache_ *)lqueue_back_(&q->lq);             \
		if (qc && name##_qcache_insert_(qc, element))                  \
			return;                                                \
		qc = tal(q->ctx, struct name##_qcache_);                       \
		name##_qcache_init_(qc);                                       \
		name##_qcache_insert_(qc, element);                            \
		lqueue_enqueue_(&q->lq, (struct lqueue_link *)qc);             \
	}                                                                      \
	/* QUEUE_DEFINE_TYPE */

#endif /* LIGHTNING_PLUGINS_ASKRENE_QUEUE_H */

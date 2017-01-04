// Licensed under BSD-MIT: See LICENSE.
#ifndef CCAN_PTR_VALID_H
#define CCAN_PTR_VALID_H
#include "config.h"
#include <stdbool.h>
#include <stdlib.h>

/**
 * ptr_valid_read - can I safely read from a pointer?
 * @p: the proposed pointer.
 *
 * This function verifies that the pointer @p is safe to dereference for
 * reading.  It is very slow, particularly if the answer is "no".
 *
 * Sets errno to EFAULT on failure.
 *
 * See Also:
 *	ptr_valid_batch_read()
 */
#define ptr_valid_read(p)						\
	ptr_valid_r((p), PTR_VALID_ALIGNOF(*(p)), sizeof(*(p)))

/**
 * ptr_valid_write - can I safely write to a pointer?
 * @p: the proposed pointer.
 *
 * This function verifies that the pointer @p is safe to dereference
 * for writing (and reading).  It is very slow, particularly if the
 * answer is "no".
 *
 * Sets errno to EFAULT on failure.
 *
 * See Also:
 *	ptr_valid_batch_write()
 */
#define ptr_valid_write(p)						\
	ptr_valid_w((p), PTR_VALID_ALIGNOF(*(p)), sizeof(*(p)))

/**
 * ptr_valid_string - can I safely read a string?
 * @p: the proposed string.
 *
 * This function verifies that the pointer @p is safe to dereference
 * up to a nul character.  It is very slow, particularly if the answer
 * is "no".
 *
 * Sets errno to EFAULT on failure.
 *
 * See Also:
 *	ptr_valid_batch_string()
 */
bool ptr_valid_string(const char *p);

/**
 * ptr_valid - generic pointer check function
 * @p: the proposed pointer.
 * @align: the alignment requirements of the pointer.
 * @size: the size of the region @p should point to
 * @write: true if @p should be writable as well as readable.
 *
 * This function verifies that the pointer @p is safe to dereference.
 * It is very slow, particularly if the answer is "no".
 *
 * Sets errno to EFAULT on failure.
 *
 * See Also:
 *	ptr_valid_batch()
 */
bool ptr_valid(const void *p, size_t align, size_t size, bool write);

/**
 * struct ptr_valid_batch - pointer to store state for batch ptr ops
 *
 * Treat as private.
 */
struct ptr_valid_batch {
	unsigned int num_maps;
	struct ptr_valid_map *maps;
	int child_pid;
	int to_child, from_child;
	void *last;
	bool last_ok;
};

/**
 * ptr_valid_batch_start - prepare for a batch of ptr_valid checks.
 * @batch: an uninitialized ptr_valid_batch structure.
 *
 * This initializes @batch; this same @batch pointer can be reused
 * until the memory map changes (eg. via mmap(), munmap() or even
 * malloc() and free()).
 *
 * This is useful to check many pointers, because otherwise it can be
 * extremely slow.
 *
 * Example:
 * struct linked {
 *	struct linked *next;
 *	const char *str;
 * };
 *
 * static bool check_linked_carefully(struct linked *head)
 * {
 *	struct ptr_valid_batch batch;
 *	struct linked *old = head;
 *	bool half = true;
 *
 *	// If this fails, we can't check.  Assume OK.
 *	if (!ptr_valid_batch_start(&batch))
 *		return true;
 *
 *	while (head) {
 *		if (!ptr_valid_batch_read(&batch, head))
 *			goto fail;
 *		if (!ptr_valid_batch_string(&batch, head->str))
 *			goto fail;
 *		// Loop detection; move old at half speed of head.
 *		if (half)
 *			old = old->next;
 *		half = !half;
 *		if (head == old) {
 *			errno = ELOOP;
 *			goto fail;
 *		}
 *	}
 *	ptr_valid_batch_end(&batch);
 *	return true;
 *
 * fail:
 *	ptr_valid_batch_end(&batch);
 *	return false;
 * }
 *
 * See Also:
 *	ptr_valid_batch_stop()
 */
bool ptr_valid_batch_start(struct ptr_valid_batch *batch);

/**
 * ptr_valid_batch_read - can I safely read from a pointer?
 * @batch: the batch initialized by ptr_valid_batch_start().
 * @p: the proposed pointer.
 *
 * Batched version of ptr_valid_read().
 */
#define ptr_valid_batch_read(batch, p)					\
	ptr_valid_batch_r((batch),					\
			  (p), PTR_VALID_ALIGNOF(*(p)), sizeof(*(p)))

/**
 * ptr_valid_batch_write - can I safely write to a pointer?
 * @batch: the batch initialized by ptr_valid_batch_start().
 * @p: the proposed pointer.
 *
 * Batched version of ptr_valid_write().
 */
#define ptr_valid_batch_write(batch, p)					\
	ptr_valid_batch_w((batch),					\
			  (p), PTR_VALID_ALIGNOF(*(p)), sizeof(*(p)))

/**
 * ptr_valid_batch_string - can I safely read a string?
 * @batch: the batch initialized by ptr_valid_batch_start().
 * @p: the proposed string.
 *
 * Batched version of ptr_valid_string().
 */
bool ptr_valid_batch_string(struct ptr_valid_batch *batch, const char *p);

/**
 * ptr_valid_batch - generic batched pointer check function
 * @batch: the batch initialized by ptr_valid_batch_start().
 * @p: the proposed pointer.
 * @align: the alignment requirements of the pointer.
 * @size: the size of the region @p should point to
 * @write: true if @p should be writable as well as readable.
 *
 * Batched version of ptr_valid().
 */
bool ptr_valid_batch(struct ptr_valid_batch *batch,
		     const void *p, size_t alignment, size_t size, bool write);

/**
 * ptr_valid_batch_end - end a batch of ptr_valid checks.
 * @batch: a ptr_valid_batch structure.
 *
 * This is used after all checks are complete.
 *
 * See Also:
 *	ptr_valid_batch_start()
 */
void ptr_valid_batch_end(struct ptr_valid_batch *batch);


/* These wrappers get constness correct. */
static inline bool ptr_valid_r(const void *p, size_t align, size_t size)
{
	return ptr_valid(p, align, size, false);
}

static inline bool ptr_valid_w(void *p, size_t align, size_t size)
{
	return ptr_valid(p, align, size, true);
}

static inline bool ptr_valid_batch_r(struct ptr_valid_batch *batch,
				     const void *p, size_t align, size_t size)
{
	return ptr_valid_batch(batch, p, align, size, false);
}

static inline bool ptr_valid_batch_w(struct ptr_valid_batch *batch,
				     void *p, size_t align, size_t size)
{
	return ptr_valid_batch(batch, p, align, size, true);
}

struct ptr_valid_map {
	const char *start, *end;
	bool is_write;
};

#if HAVE_ALIGNOF
#define PTR_VALID_ALIGNOF(var) __alignof__(var)
#else
/* Can't check this... */
#define PTR_VALID_ALIGNOF(var) 1
#endif
#endif /* CCAN_PTR_VALID_H */

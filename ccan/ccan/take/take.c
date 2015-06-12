/* CC0 (Public domain) - see LICENSE file for details */
#include <ccan/take/take.h>
#include <ccan/likely/likely.h>
#include <stdlib.h>
#include <string.h>

static const void **takenarr;
static size_t max_taken, num_taken;
static size_t allocfail;
static void (*allocfailfn)(const void *p);

void *take_(const void *p)
{
	if (unlikely(num_taken == max_taken)) {
		const void **new;

		new = realloc(takenarr, sizeof(*takenarr) * (max_taken+1));
		if (unlikely(!new)) {
			if (allocfailfn) {
				allocfail++;
				allocfailfn(p);
				return NULL;
			}
			/* Otherwise we leak p. */
			return (void *)p;
		}
		takenarr = new;
		max_taken++;
	}
	takenarr[num_taken++] = p;
	return (void *)p;
}

static size_t find_taken(const void *p)
{
	size_t i;

	for (i = 0; i < num_taken; i++) {
		if (takenarr[i] == p)
			return i+1;
	}
	return 0;
}

bool taken(const void *p)
{
	size_t i;

	if (!p && unlikely(allocfail)) {
		allocfail--;
		return true;
	}

	i = find_taken(p);
	if (!i)
		return false;

	memmove(&takenarr[i-1], &takenarr[i],
		(--num_taken - (i - 1))*sizeof(takenarr[0]));
	return true;
}

bool is_taken(const void *p)
{
	if (!p && unlikely(allocfail))
		return true;

	return find_taken(p) > 0;
}

bool taken_any(void)
{
	return num_taken != 0;
}

void take_cleanup(void)
{
	max_taken = num_taken = 0;
	free(takenarr);
	takenarr = NULL;
}

void take_allocfail(void (*fn)(const void *p))
{
	allocfailfn = fn;
}

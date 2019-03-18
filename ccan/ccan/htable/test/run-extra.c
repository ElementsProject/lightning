#include "../htable.c"

static size_t hash(const void *ptr, void *priv UNNEEDED)
{
	/* We're hashing pointers; no need to get too fancy. */
	return ((size_t)ptr / sizeof(ptr)) ^ ((size_t)ptr % sizeof(ptr));
}

/* 24042: Waiting on 0x5570a500c3f8 (11742786623615)
24042: Waiting on 0x5570a500c430 (11742786623622)
24042: Searching for 0x5570a500c3f8 (11742786623615) in 2 elems
24042: Searching for 0x5570a500c3f8 (11742786623615) in 2 elems
*/
static struct htable waittable = HTABLE_INITIALIZER(waittable, hash, NULL);

int main(void)
{
	const void *p1 = (void *)0x5570a500c3f8ULL;
	const void *p2 = (void *)0x5570a500c430ULL;
	size_t h;
	struct htable_iter i;
	void *p;
	bool found;

	printf("hash %p == %zu\n", p1, hash(p1, NULL));
	printf("hash %p == %zu\n", p2, hash(p2, NULL));
	htable_add(&waittable, hash(p1, NULL), p1);
	htable_add(&waittable, hash(p2, NULL), p2);

	found = false;
	h = hash(p1, NULL);
	for (p = htable_firstval(&waittable, &i, h);
	     p;
	     p = htable_nextval(&waittable, &i, h)) {
		if (p == p1)
			found = true;
	}
	assert(found);

	found = false;
	h = hash(p2, NULL);
	for (p = htable_firstval(&waittable, &i, h);
	     p;
	     p = htable_nextval(&waittable, &i, h)) {
		if (p == p2)
			found = true;
	}
	assert(found);
	
	return found ? 0 : 1;
}

/* Grab dump of Samba4 talloc tree to do benchmarks on it. */
#include <ccan/talloc/talloc.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

struct node {
	void *n;
	struct node *parent;
	char *name;
	bool destructor;
	size_t len;
	unsigned int num_children;
	struct node *children[0];
};

static int node_count;

static struct node *new_node(void)
{
	node_count++;
	return calloc(sizeof(struct node), 1);
}

/* struct db_context              contains    282 bytes in   5 blocks (ref 0) d=(nil) 0x1f64e70 */
static struct node *parse(const char *line)
{
	struct node *n = new_node();
	const char *p;

	p = strstr(line, " contains ");
	p += strlen(" contains ");
	p += strspn(line, " ");
	n->len = strtol(p, NULL, 0);
	p = strstr(p, "d=");
	if (p[2] != '(')
		n->destructor = true;
	return n;
}

static void add_child(struct node *parent, struct node *child)
{
	unsigned int i;
	struct node *oldp = parent;

	parent = realloc(parent, sizeof(*parent)
			 + sizeof(parent->children[0]) * (parent->num_children+1));
	parent->children[parent->num_children++] = child;
	child->parent = parent;

	if (parent == oldp)
		return;

	/* Fix up children's parent pointers. */
	for (i = 0; i < parent->num_children-1; i++) {
		assert(parent->children[i]->parent == oldp);
		parent->children[i]->parent = parent;
	}

	/* Fix up parent's child pointer. */
	if (parent->parent) {
		assert(parent->parent->children[parent->parent->num_children-1]
		       == oldp);
		parent->parent->children[parent->parent->num_children-1]
			= parent;
	}
}

/* Random string of required length */
static char *namelen(int len)
{
	char *p = malloc(len);
	memset(p, 'x', len-1);
	p[len-1] = '\0';
	return p;
}

static struct node *read_nodes(FILE *f)
{
	char line[4096];
	unsigned int curr_indent = 0, indent;
	struct node *n, *curr = new_node();

	/* Ignore first line */
	fgets(line, 4096, f);

	while (fgets(line, 4096, f)) {
		bool is_name;

		indent = strspn(line, " ");

		/* Ignore references for now. */
		if (strstarts(line + indent, "reference to: "))
			continue;

		/* Blank name?  Use offset of 'contains' to guess indent! */
		if (strstarts(line + indent, "contains "))
			indent -= 31;

		is_name = strstarts(line + indent, ".name ");

		n = parse(line + indent);
		if (is_name) {
			curr->name = namelen(n->len);
			free(n);
		} else {
			if (indent > curr_indent) {
				assert(indent == curr_indent + 4);
				curr_indent += 4;
			} else {
				/* Go back up to parent. */
				for (curr_indent += 4;
				     curr_indent != indent;
				     curr_indent -= 4)
					curr = curr->parent;
			}
			add_child(curr, n);
			curr = n;
		}
	}
	while (curr->parent) {
		curr = curr->parent;
		curr_indent -= 4;
	}
	assert(curr_indent == 0);
	return curr;
}

static int unused_talloc_destructor(void *p)
{
	return 0;
}

static void do_tallocs(struct node *node)
{
	unsigned int i;
	static int count;

	if (count++ % 16 == 0)
		node->n = talloc_array(node->parent ? node->parent->n : NULL,
				       char, node->len);
	else
		node->n = talloc_size(node->parent ? node->parent->n : NULL,
				      node->len);
	if (node->destructor)
		talloc_set_destructor(node->n, unused_talloc_destructor);
	if (node->name)
		talloc_set_name(node->n, "%s", node->name);

	for (i = 0; i < node->num_children; i++)
		do_tallocs(node->children[i]);
}

static void free_tallocs(struct node *node)
{
	unsigned int i;

	for (i = 0; i < node->num_children; i++)
		free_tallocs(node->children[i]);

	talloc_free(node->n);
}

static void unused_tal_destructor(void *p)
{
}

static void do_tals(struct node *node)
{
	unsigned int i;
	static int count;

	/* Tal pays a penalty for arrays, but we can't tell which is an array
	 * and which isn't.  Grepping samba source gives 1221 talloc_array of
	 * 33137 talloc occurrences, so conservatively assume 1 in 16 */
	if (count++ % 16 == 0)
		node->n = tal_arr(node->parent ? node->parent->n : NULL,
				  char, node->len);
	else
		node->n = tal_alloc_(node->parent ? node->parent->n : NULL,
				     node->len, false, false, TAL_LABEL(type, ""));

	if (node->destructor)
		tal_add_destructor(node->n, unused_tal_destructor);
	if (node->name)
		tal_set_name(node->n, node->name);

	for (i = 0; i < node->num_children; i++)
		do_tals(node->children[i]);
}

static void free_tals(struct node *node)
{
	unsigned int i;

	for (i = 0; i < node->num_children; i++)
		free_tals(node->children[i]);

	tal_free(node->n);
}

static void do_mallocs(struct node *node)
{
	unsigned int i;

	node->n = malloc(node->len + (node->name ? strlen(node->name) + 1 : 1));

	for (i = 0; i < node->num_children; i++)
		do_mallocs(node->children[i]);
}

static void free_mallocs(struct node *node)
{
	unsigned int i;

	for (i = 0; i < node->num_children; i++)
		free_mallocs(node->children[i]);

	free(node->n);
}

/* See proc(5): field 23 is vsize, 24 is rss (in pages) */
static void dump_vsize(void)
{
	int fd, i;
	char buf[1000], *p = buf;

	sprintf(buf, "/proc/%u/stat", getpid());
	fd = open(buf, O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);

	for (i = 0; i < 22; i++) {
		p += strcspn(p, " ");
		p += strspn(p, " ");
	}
	i = atoi(p);
	printf("Virtual size = %i, ", i);
	p += strcspn(p, " ");
	p += strspn(p, " ");
	i = atoi(p);
	printf("RSS = %i\n", i * getpagesize());
}

#define LOOPS 1000

int main(int argc, char *argv[])
{
	struct timeabs start;
	struct timerel alloc_time, free_time;
	struct node *root;
	unsigned int i;
	FILE *f;
	bool run_talloc = true, run_tal = true, run_malloc = true;

	f = argv[1] ? fopen(argv[1], "r") : stdin;
	root = read_nodes(f);
	fclose(f);
	printf("Read %u nodes\n", node_count);

	if (argc > 2) {
		if (streq(argv[2], "--talloc-size")) {
			do_tallocs(root);
			dump_vsize();
			exit(0);
		}
		if (streq(argv[2], "--tal-size")) {
			do_tals(root);
			dump_vsize();
			exit(0);
		}
		if (strcmp(argv[2], "--talloc") == 0)
			run_tal = run_malloc = false;
		else if (strcmp(argv[2], "--tal") == 0)
			run_talloc = run_malloc = false;
		else if (strcmp(argv[2], "--malloc") == 0)
			run_talloc = run_tal = false;
		else
			errx(1, "Bad flag %s", argv[2]);
	}

	if (!run_malloc)
		goto after_malloc;

	alloc_time.ts.tv_sec = alloc_time.ts.tv_nsec = 0;
	free_time.ts.tv_sec = free_time.ts.tv_nsec = 0;
	for (i = 0; i < LOOPS; i++) {
		start = time_now();
		do_mallocs(root);
		alloc_time = timerel_add(alloc_time,
					 time_between(time_now(), start));

		start = time_now();
		free_mallocs(root);
		free_time = timerel_add(free_time,
					time_between(time_now(), start));
	}
	alloc_time = time_divide(alloc_time, i);
	free_time = time_divide(free_time, i);
	printf("Malloc time:             %"PRIu64"ns\n", time_to_nsec(alloc_time));
	printf("Free time:               %"PRIu64"ns\n", time_to_nsec(free_time));

after_malloc:
	if (!run_talloc)
		goto after_talloc;

	alloc_time.ts.tv_sec = alloc_time.ts.tv_nsec = 0;
	free_time.ts.tv_sec = free_time.ts.tv_nsec = 0;
	for (i = 0; i < LOOPS; i++) {
		start = time_now();
		do_tallocs(root);
		alloc_time = timerel_add(alloc_time,
					 time_between(time_now(), start));

		start = time_now();
		free_tallocs(root);
		free_time = timerel_add(free_time,
					time_between(time_now(), start));
	}
	alloc_time = time_divide(alloc_time, i);
	free_time = time_divide(free_time, i);
	printf("Talloc time:             %"PRIu64"ns\n", time_to_nsec(alloc_time));
	printf("talloc_free time:        %"PRIu64"ns\n", time_to_nsec(free_time));

	free_time.ts.tv_sec = free_time.ts.tv_nsec = 0;
	for (i = 0; i < LOOPS; i++) {
		do_tallocs(root);

		start = time_now();
		talloc_free(root->n);
		free_time = timerel_add(free_time,
					time_between(time_now(), start));
	}
	free_time = time_divide(free_time, i);
	printf("Single talloc_free time: %"PRIu64"\n", time_to_nsec(free_time));

after_talloc:
	if (!run_tal)
		goto after_tal;

	alloc_time.ts.tv_sec = alloc_time.ts.tv_nsec = 0;
	free_time.ts.tv_sec = free_time.ts.tv_nsec = 0;
	for (i = 0; i < LOOPS; i++) {
		start = time_now();
		do_tals(root);
		alloc_time = timerel_add(alloc_time,
					 time_between(time_now(), start));

		start = time_now();
		free_tals(root);
		free_time = timerel_add(free_time,
					time_between(time_now(), start));
	}
	alloc_time = time_divide(alloc_time, i);
	free_time = time_divide(free_time, i);
	printf("Tal time:                %"PRIu64"ns\n", time_to_nsec(alloc_time));
	printf("Tal_free time:           %"PRIu64"ns\n", time_to_nsec(free_time));

	free_time.ts.tv_sec = free_time.ts.tv_nsec = 0;
	for (i = 0; i < LOOPS; i++) {
		do_tals(root);

		start = time_now();
		tal_free(root->n);
		free_time = timerel_add(free_time,
					time_between(time_now(), start));
	}
	free_time = time_divide(free_time, i);
	printf("Single tal_free time:    %"PRIu64"ns\n", time_to_nsec(free_time));
after_tal:

	return 0;
}

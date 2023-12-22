#include "config.h"
#include <common/setup.h>
#include <common/trace.h>

/* This is mostly a benchmark to see how much overhead the tracing
 * introduces. */

int main(int argx, char *argv[])
{
	/* Just some context objects to hang spans off of. */
	int a, b, c, d;

	common_setup(argv[0]);

	/* Create a bunch of nested spans to emit. */
	for(int i=0; i<25000; i++) {
		trace_span_start("a", &a);
		trace_span_start("b", &b);

		trace_span_start("c", &c);
		trace_span_end(&c);

		trace_span_end(&b);

		trace_span_start("d", &d);
		trace_span_end(&d);

		trace_span_end(&a);
	}
	trace_cleanup();
	common_shutdown();
}

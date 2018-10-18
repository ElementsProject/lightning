#include <ccan/structeq/structeq.h>

struct mydata {
	int start, end;
	int pad;
};
#ifdef FAIL
#define PADDING -1
#else
#define PADDING -(int)sizeof(int)
#endif

STRUCTEQ_DEF(mydata, PADDING, start, end);

int main(void)
{
	struct mydata a = { 0, 100 };

	return mydata_eq(&a, &a);
}

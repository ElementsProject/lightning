#include <ccan/structeq/structeq.h>

struct mydata {
	int start, end;
	int pad;
};
#ifdef FAIL
#define PADDING -1 /* We have more than 1 byte padding */
#else
#define PADDING sizeof(int)
#endif

STRUCTEQ_DEF(mydata, PADDING, start, end);

int main(void)
{
	struct mydata a = { 0, 100 };

	return mydata_eq(&a, &a);
}

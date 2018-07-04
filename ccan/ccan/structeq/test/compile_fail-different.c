#include <ccan/structeq/structeq.h>

struct mydata1 {
	int start, end;
};

struct mydata2 {
	int start, end;
};

STRUCTEQ_DEF(mydata1, 0, start, end);

int main(void)
{
	struct mydata1 a = { 0, 100 };
#ifdef FAIL
	struct mydata2
#else
	struct mydata1
#endif
		b = { 0, 100 };

	return mydata1_eq(&a, &b);
}

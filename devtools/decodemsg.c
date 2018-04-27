#include <common/utils.h>
#include <devtools/gen_print_wire.h>

int main(int argc UNUSED, char *argv[])
{
	setup_locale();

	u8 *m = tal_hexdata(NULL, argv[1], strlen(argv[1]));
	print_message(m);
	return 0;
}

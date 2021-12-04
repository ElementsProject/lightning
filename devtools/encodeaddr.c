#include "config.h"
#include <assert.h>
#include <common/bech32.h>
#include <common/utils.h>
#include <stdio.h>

static void test_enc(const char *hrp, const char *hex)
{
	u8 *val;
	bool ok;
	u8 ver;
	char *out;

	val = tal_hexdata(NULL, hex, strlen(hex));
	assert(val);
	out = tal_arr(NULL, char, 73 + strlen(hrp));
	/* First byte is version */
	ver = (val[0] == 0 ? 0 : val[0] - 0x50);
	/* Second byte is OP_PUSH */
	assert(val[1] == tal_bytelen(val) - 2);
	ok = segwit_addr_encode(out, hrp, ver, val+2, tal_bytelen(val)-2);
	assert(ok);
	printf("%s\n", out);
}

int main(int argc, char *argv[])
{
	const char *hrp = argv[1];

	setup_locale();
	test_enc(hrp ?: "bc", "0014751e76e8199196d454941c45d1b3a323f1433bd6");
	test_enc(hrp ?: "tb", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
	test_enc(hrp ?: "bc", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6");
	test_enc(hrp ?: "bc", "6002751e");
	test_enc(hrp ?: "bc", "5210751e76e8199196d454941c45d1b3a323");
	test_enc(hrp ?: "tb", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433");
	test_enc(hrp ?: "tb", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433");
	test_enc(hrp ?: "bc", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
}

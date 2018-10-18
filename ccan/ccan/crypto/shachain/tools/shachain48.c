#include <ccan/crypto/shachain/shachain.h>
#include <ccan/str/hex/hex.h>
#include <ccan/str/str.h>
#include <ccan/err/err.h>
#include <ccan/rbuf/rbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	if (argc == 2 && streq(argv[1], "--store")) {
		struct shachain s;
		struct rbuf rbuf;
		size_t size = rbuf_good_size(STDIN_FILENO);
		char *p;

		shachain_init(&s);
		rbuf_init(&rbuf, STDIN_FILENO, malloc(size), size, membuf_realloc);

		while ((p = rbuf_read_str(&rbuf, '\n')) != NULL) {
			struct sha256 hash;
			unsigned long long idx;

			if (strstarts(p, "0x"))
				p += 2;
			if (!hex_decode(p, 64, &hash, sizeof(hash)))
				errx(2, "%.*s is not 64 chars of hex", 64, p);
			p += 64;
			p += strspn(p, " \t");
			idx = strtoull(p, NULL, 0);
			if (shachain_add_hash(&s, idx, &hash))
				printf("OK\n");
			else
				printf("ERROR\n");
		}
	} else if (argc == 3) {
		struct sha256 seed, hash;
		const char *p;
		unsigned long long idx;
		char hex[65];

		if (strstarts(argv[1], "0x"))
			p = argv[1] + 2;
		else
			p = argv[1];
		idx = strtoull(argv[2], NULL, 0);

		if (!hex_decode(p, 64, &seed, sizeof(seed)))
			errx(2, "%s is not 64 chars of hex", p);

		shachain_from_seed(&seed, idx, &hash);
		hex_encode(&hash, sizeof(hash), hex, sizeof(hex));
		printf("0x%s\n", hex);
	} else
		errx(1, "Usage: shachain --store OR shachain <seed> <index>");
	return 0;
}

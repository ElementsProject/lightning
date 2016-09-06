/* Bitcoin does a lot of SHA of SHA.  Benchmark that. */
#include <ccan/crypto/sha256/sha256.c>
#include <ccan/time/time.h>
#include <stdio.h>

void sha256_avx(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_rorx(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_rorx_x8ms(void *input_data, uint32_t digest[8], uint64_t num_blks);
void sha256_sse4(void *input_data, uint32_t digest[8], uint64_t num_blks);

int main(int argc, char *argv[])
{
	struct timeabs start;
	struct timerel diff;
	size_t i, n;
	union {
		struct sha256 h;
		uint32_t u32[16];
		uint8_t u8[64];
	} block;

	n = atoi(argv[1] ? argv[1] : "1000000");
	memset(&block, 0, sizeof(block));
	sha256(&block.h, &n, sizeof(n));

	start = time_now();
	for (i = 0; i < n; i++) {
		sha256(&block.h, &block.h, sizeof(block.h));
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Normal gave %02x%02x%02x%02x%02x%02x... in %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	/* Now, don't re-initalize every time; use Transform */
	memset(&block, 0, sizeof(block));
	sha256(&block.h, &n, sizeof(n));
	block.u8[sizeof(block.h)] = 0x80;
	/* Size is 256 bits */
	block.u8[sizeof(block)-2] = 1;

	start = time_now();
	for (i = 0; i < n; i++) {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t j;
		Transform(ctx.s, block.u32);
		for (j = 0; j < sizeof(ctx.s) / sizeof(ctx.s[0]); j++)
			block.h.u.u32[j] = cpu_to_be32(ctx.s[j]);
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Transform gave %02x%02x%02x%02x%02x%02x... in %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	/* Now, assembler variants */
	sha256(&block.h, &n, sizeof(n));

	start = time_now();
	for (i = 0; i < n; i++) {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t j;
		sha256_rorx(block.u32, ctx.s, 1);
		for (j = 0; j < sizeof(ctx.s) / sizeof(ctx.s[0]); j++)
			block.h.u.u32[j] = cpu_to_be32(ctx.s[j]);
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Asm rorx for %02x%02x%02x%02x%02x%02x... is %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	sha256(&block.h, &n, sizeof(n));

	start = time_now();
	for (i = 0; i < n; i++) {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t j;
		sha256_sse4(block.u32, ctx.s, 1);
		for (j = 0; j < sizeof(ctx.s) / sizeof(ctx.s[0]); j++)
			block.h.u.u32[j] = cpu_to_be32(ctx.s[j]);
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Asm SSE4 for %02x%02x%02x%02x%02x%02x... is %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	sha256(&block.h, &n, sizeof(n));
	start = time_now();
	for (i = 0; i < n; i++) {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t j;
		sha256_rorx_x8ms(block.u32, ctx.s, 1);
		for (j = 0; j < sizeof(ctx.s) / sizeof(ctx.s[0]); j++)
			block.h.u.u32[j] = cpu_to_be32(ctx.s[j]);
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Asm RORx-x8ms for %02x%02x%02x%02x%02x%02x... is %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	sha256(&block.h, &n, sizeof(n));
	start = time_now();
	for (i = 0; i < n; i++) {
		struct sha256_ctx ctx = SHA256_INIT;
		size_t j;
		sha256_avx(block.u32, ctx.s, 1);
		for (j = 0; j < sizeof(ctx.s) / sizeof(ctx.s[0]); j++)
			block.h.u.u32[j] = cpu_to_be32(ctx.s[j]);
	}
	diff = time_divide(time_between(time_now(), start), n);
	printf("Asm AVX for %02x%02x%02x%02x%02x%02x... is %llu nsec\n",
	       block.h.u.u8[0], block.h.u.u8[1], block.h.u.u8[2],
	       block.h.u.u8[3], block.h.u.u8[4], block.h.u.u8[5],
	       (unsigned long long)time_to_nsec(diff));

	return 0;
}
	

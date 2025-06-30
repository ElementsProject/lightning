#include "config.h"
#include <assert.h>
#include <ccan/ccan/array_size/array_size.h>
#include <common/setup.h>
#include <common/utils.h>
#include <common/codex32.h>
#include <tests/fuzz/libfuzz.h>

/* Default mutator defined by libFuzzer */
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
				unsigned int seed);
size_t LLVMFuzzerCustomCrossOver(const u8 *in1, size_t in1_size, const u8 *in2,
				size_t in2_size, u8 *out, size_t max_out_size,
				unsigned seed);

/* Initial valid Codex32 strings for seeding */
static const char *valid_vectors[] = {
	"ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
	"MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
	"ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
	"ms10leetsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nlnve25gvezzyqqtum9pgv99ycma",
	"MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXV"
	"CEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"
};

/* Generate valid initial input */
static size_t initial_input(uint8_t *fuzz_data, size_t max_size)
{
	size_t idx = rand() % ARRAY_SIZE(valid_vectors);
	const char *vec = valid_vectors[idx];
	size_t len = strlen(vec);

	if (len > max_size)
		len = max_size;

	memcpy(fuzz_data, vec, len);
	return len;
}

void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
}

/* Custom mutator preserving Codex32 structure */
size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size,
				size_t max_size, unsigned int seed)
{
	srand(seed);
	char *str = to_string(tmpctx, fuzz_data, size);
	char *fail;
	struct codex32 *parts = codex32_decode(tmpctx, NULL, str, &fail);

	/* If invalid, return valid vector */
	if (!parts)
		return initial_input(fuzz_data, max_size);

	/* Mutate a random component */
	switch(rand() % 5) {
		case 0: /* Mutate HRP */
			if (streq(parts->hrp, "ms"))
				parts->hrp = "MS";
			else
				parts->hrp = "ms";
			break;
		case 1: /* Mutate threshold (0-9) */
			parts->threshold = rand() % 10;
			break;
		case 2: /* Mutate ID (4 characters) */
			for (int i = 0; i < 4; i++)
				parts->id[i] = 'A' + (rand() % 26);
			parts->id[4] = '\0';
			break;
		case 3: /* Mutate share index (valid char) */
			parts->share_idx = "abcdefghijklmnopqrstuvwxyzABCDEF"[rand() % 32];
			break;
		case 4: /* Mutate payload */
			if (tal_bytelen(parts->payload) > 0) {
			size_t mutate_len = 1 + rand() % tal_bytelen(parts->payload);
			LLVMFuzzerMutate((u8 *) parts->payload, mutate_len,
					tal_bytelen(parts->payload));
			}
			break;
	}

	/* Re-encode mutated parts */
	char *reencoded;
	const char *err = codex32_secret_encode(tmpctx, parts->hrp, parts->id, parts->threshold,
				parts->payload, tal_bytelen(parts->payload), &reencoded);

	if (err)
		return initial_input(fuzz_data, max_size);

	size_t len = strlen(reencoded);
	if (len > max_size)
		return initial_input(fuzz_data, max_size);

	memcpy(fuzz_data, reencoded, len);
	return len;
}

/* Custom crossover for Codex32 strings */
size_t LLVMFuzzerCustomCrossOver(const u8 *in1, size_t in1_size,  const u8 *in2, size_t in2_size,
				u8 *out, size_t max_out_size, unsigned seed)
{
	srand(seed);
	char *str1 = to_string(tmpctx, in1, in1_size);
	char *str2 = to_string(tmpctx, in2, in2_size);
	char *fail;

	/* Decode both inputs */
	struct codex32 *p1 = codex32_decode(tmpctx, NULL, str1, &fail);
	struct codex32 *p2 = codex32_decode(tmpctx, NULL, str2, &fail);

	/* If either invalid, use initial input */
	if (!p1 || !p2)
		return initial_input(out, max_out_size);

	/* Choose component to crossover */
	struct codex32 *child = p1;
	switch(rand() % 5) {
		case 0:
			child->hrp = p2->hrp;
			break;
		case 1:
			child->threshold = p2->threshold;
			break;
		case 2:
			memcpy(child->id, p2->id, 5);
			break;
		case 3:
			child->share_idx = p2->share_idx;
			break;
		case 4: /* Payload crossover */
			child->payload = tal_arr(child, u8, tal_bytelen(p2->payload));
			memcpy((u8 *) child->payload, p2->payload, tal_bytelen(p2->payload));
			break;
	}

	/* Re-encode child */
	char *reencoded;
	const char *err = codex32_secret_encode(tmpctx, child->hrp, child->id, child->threshold,
				child->payload, tal_bytelen(child->payload), &reencoded);

	if (err)
		return initial_input(out, max_out_size);

	size_t len = strlen(reencoded);
	if (len > max_out_size)
		return initial_input(out, max_out_size);

	memcpy(out, reencoded, len);
	clean_tmpctx();
	return len;
}

void run(const uint8_t *data, size_t size)
{
	struct codex32 *c32;
	char *str, *fail, *bip93;

	str = to_string(tmpctx, data, size);

	c32 = codex32_decode(tmpctx, NULL, str, &fail);
	if (c32) {
		const char *ret = codex32_secret_encode(tmpctx, c32->hrp, c32->id, c32->threshold,
				c32->payload, tal_bytelen(c32->payload), &bip93);
		assert(!ret && bip93);
	} else
		assert(fail);

	clean_tmpctx();
}

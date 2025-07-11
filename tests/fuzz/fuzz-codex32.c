#include "config.h"
#include <assert.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/ccan/tal/str/str.h>
#include <common/setup.h>
#include <common/bech32.h>
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

/* Duplicate codex32 structure */
static struct codex32 *codex32_dup(const tal_t *ctx, const struct codex32 *src)
{
	struct codex32 *dup = tal(ctx, struct codex32);
	dup->hrp = tal_strdup(dup, src->hrp);
	dup->threshold = src->threshold;
	memcpy(dup->id, src->id, sizeof(dup->id));
	dup->share_idx = src->share_idx;
	dup->payload = tal_dup_arr(dup, u8, src->payload,
				   tal_bytelen(src->payload), 0);
	dup->type = src->type;
	return dup;
}

static bool codex32_fields_valid_for_encoding(const struct codex32 *parts)
{
	/* Check threshold */
	if (parts->threshold > 9 || parts->threshold == 1)
		return false;

	/* Check id: must be 4 characters, each in bech32 charset and ASCII */
	if (strlen(parts->id) != 4)
		return false;

	for (int i = 0; i < 4; i++) {
		unsigned char c = parts->id[i];
		if (c == 0 || c >= 128)
			return false;
		if (bech32_charset_rev[c] == -1)
			return false;
	}

	/* Check HRP: must be 2 characters, no embedded zeros, and ASCII */
	if (strlen(parts->hrp) != 2)
		return false;

	if (parts->hrp[0] == 0)
		return false;

	for (size_t i = 0; i < strlen(parts->hrp); i++) {
		unsigned char c = parts->hrp[i];
		if (c == 0 || c >= 128)
			return false;
	}

	/* Check share index */
	unsigned char si = parts->share_idx;
	if (si == 0 || si >= 128)
		return false;
	if (bech32_charset_rev[si] == -1)
		return false;

	return true;
}

void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
}

/* Custom mutator with structure-aware and byte-level mutations */
size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size,
				size_t max_size, unsigned int seed)
{
	srand(seed);
	char *str = to_string(tmpctx, fuzz_data, size);
	char *fail;
	struct codex32 *parts = codex32_decode(tmpctx, NULL, str, &fail);

	/* If valid, try structure-aware mutation */
	if (parts) {
		/* Mutate a random component */
		switch(rand() % 4) {
		case 0: /* Mutate HRP arbitrarily */
			{
				size_t hrp_len = strlen(parts->hrp);
				size_t max_hrp_len = 10; /* Reasonable max */
				char *new_hrp = tal_arr(parts, char, max_hrp_len + 1);
				size_t new_hrp_len = LLVMFuzzerMutate((u8 *)new_hrp,
								hrp_len, max_hrp_len);
				new_hrp[new_hrp_len] = '\0';
				parts->hrp = new_hrp;
			}
			break;

		case 1: /* Mutate threshold to any value */
			parts->threshold = rand();
			break;

		case 2: /* Mutate ID arbitrarily */
			{
				size_t id_len = sizeof(parts->id) - 1;
				LLVMFuzzerMutate((u8 *)parts->id, id_len, id_len);
				parts->id[id_len] = '\0';
			}
			break;

		case 3: /* Mutate payload */
			{
				size_t old_size = tal_bytelen(parts->payload);
				tal_resize(&parts->payload, max_size);
				size_t new_size = LLVMFuzzerMutate((u8 *)parts->payload, old_size, max_size);
				tal_resize(&parts->payload, new_size);
			}
			break;
		}

		/* Only try to re-encode if parts are valid */
		if (codex32_fields_valid_for_encoding(parts)) {
			char *reencoded;
			const char *err = codex32_secret_encode(tmpctx, parts->hrp, parts->id,
								parts->threshold, parts->payload,
								tal_bytelen(parts->payload), &reencoded);
			if (!err) {
				size_t len = tal_bytelen(reencoded);
				if (len <= max_size) {
					memcpy(fuzz_data, reencoded, len);
					return len;
				}
			}
		}
	}

	/* Fallback: byte-level mutation */
	return LLVMFuzzerMutate(fuzz_data, size, max_size);
}

/* Custom crossover with structure-aware recombination */
size_t LLVMFuzzerCustomCrossOver(const u8 *in1, size_t in1_size, const u8 *in2, size_t in2_size,
				u8 *out, size_t max_out_size, unsigned seed)
{
	srand(seed);
	char *str1 = to_string(tmpctx, in1, in1_size);
	char *str2 = to_string(tmpctx, in2, in2_size);
	char *fail;

	/* Decode both inputs */
	struct codex32 *p1 = codex32_decode(tmpctx, NULL, str1, &fail);
	struct codex32 *p2 = codex32_decode(tmpctx, NULL, str2, &fail);

	/* If both valid, try structure-aware crossover */
	if (p1 && p2) {
		/* Create child by combining parts */
		struct codex32 *child = codex32_dup(tmpctx, p1);

		/* Choose crossover method */
		switch(rand() % 5) {
		case 0: /* Crossover HRP */
			{
				size_t hrp1_len = strlen(p1->hrp);
				size_t hrp2_len = strlen(p2->hrp);
				char *new_hrp = tal_arr(child, char, max_out_size);
				size_t new_hrp_len = cross_over((const u8 *)p1->hrp, hrp1_len,
								(const u8 *)p2->hrp, hrp2_len,
								(u8 *)new_hrp, max_out_size, rand());
				new_hrp[new_hrp_len] = '\0';
				child->hrp = new_hrp;
			}
			break;

		case 1: /* Crossover threshold */
			child->threshold = p2->threshold;
			break;

		case 2: /* Crossover ID */
			{
				size_t id_len = sizeof(p1->id) - 1;
				cross_over((const u8 *)p1->id, id_len, (const u8 *)p2->id, id_len,
					   (u8 *)child->id, id_len, rand());
				child->id[id_len] = '\0';
			}
			break;

		case 3: /* Crossover payload */
			{
				size_t p1_len = tal_bytelen(p1->payload);
				size_t p2_len = tal_bytelen(p2->payload);
				tal_resize(&child->payload, max_out_size);
				size_t new_payload_len = cross_over(p1->payload, p1_len,
								p2->payload, p2_len,
								(u8 *)child->payload, max_out_size, rand());
				tal_resize(&child->payload, new_payload_len);
			}
			break;

		case 4: /* Random combination */
			if (rand() % 2)
				child->hrp = tal_strdup(child, p2->hrp);
			if (rand() % 2)
				child->threshold = p2->threshold;
			if (rand() % 2)
				memcpy(child->id, p2->id, sizeof(child->id));
			if (rand() % 2) {
				tal_free(child->payload);
				child->payload = tal_dup_arr(child, u8, p2->payload,
							    tal_bytelen(p2->payload), 0);
			}
			break;
		}

		/* Only try to re-encode if child valid */
		if (codex32_fields_valid_for_encoding(child)) {
			char *reencoded;
			const char *err = codex32_secret_encode(tmpctx, child->hrp, child->id,
								child->threshold, child->payload,
								tal_bytelen(child->payload), &reencoded);
			if (!err) {
				size_t len = strlen(reencoded);
				if (len <= max_out_size) {
					memcpy(out, reencoded, len);
					return len;
				}
			}
		}
	}

	/* Fallback: byte-level crossover */
	return cross_over(in1, in1_size, in2, in2_size, out, max_out_size, seed);
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

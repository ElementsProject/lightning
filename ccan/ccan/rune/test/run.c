#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>

static const char *check(const tal_t *ctx,
			 const struct rune *rune,
			 const struct rune_altern *alt,
			 char **parts)
{
	const char *val = NULL;

	for (size_t i = 1; parts[i]; i++) {
		if (strstarts(parts[i], alt->fieldname)
		    && parts[i][strlen(alt->fieldname)] == '=')
			val = parts[i] + strlen(alt->fieldname) + 1;
	}

	/* If it's an integer, hand it like that */
	if (val) {
		char *endp;
		s64 v = strtol(val, &endp, 10);
		if (*endp == '\0' && endp != val)
			return rune_alt_single_int(ctx, alt, v);
		return rune_alt_single_str(ctx, alt, val, strlen(val));
	}
	return rune_alt_single_missing(ctx, alt);
}

int main(void)
{
	char *vecs;
	char **lines;
	static const u8 secret_zero[16];
	struct rune *mr;

	/* Test vector rune uses all-zero secret */
	mr = rune_new(NULL, secret_zero, sizeof(secret_zero), NULL); 

	/* Python runes library generates test vectors */
	vecs = grab_file(mr, "test/test_vectors.csv");
	assert(vecs);
	lines = tal_strsplit(mr, take(vecs), "\n", STR_NO_EMPTY);

	plan_tests(343);

	for (size_t i = 0; lines[i]; i++) {
		struct rune *rune1, *rune2;
		char **parts;

		parts = tal_strsplit(lines, lines[i], ",", STR_EMPTY_OK);
		if (streq(parts[0], "VALID")) {
			diag("test %s %s", parts[0], parts[1]);
			rune1 = rune_from_string(parts, parts[2]);
			ok1(rune1);
			rune2 = rune_from_base64(parts, parts[3]);
			ok1(rune2);
			ok1(rune_eq(rune1, rune2));
			ok1(streq(rune_to_string(parts, rune2), parts[2]));
			ok1(streq(rune_to_base64(parts, rune1), parts[3]));
			ok1(rune_is_derived_anyversion(mr, rune1) == NULL);
			ok1(rune_is_derived_anyversion(mr, rune2) == NULL);

			if (parts[4]) {
				if (parts[5])
					ok1(streq(rune1->version, parts[5]));
				ok1(streq(rune1->unique_id, parts[4]));
			} else {
				ok1(!rune1->version);
				ok1(!rune1->unique_id);
			}
			mr->version = NULL;
		} else if (streq(parts[0], "DERIVE")) {
			struct rune_restr *restr;
			diag("test %s %s", parts[0], parts[1]);
			rune1 = rune_from_base64(parts, parts[2]);
			ok1(rune1);
			rune2 = rune_from_base64(parts, parts[3]);
			ok1(rune2);
			ok1(rune_is_derived_anyversion(mr, rune1) == NULL);
			ok1(rune_is_derived_anyversion(mr, rune2) == NULL);
			ok1(rune_is_derived_anyversion(rune1, rune2) == NULL);

			restr = rune_restr_new(NULL);
			for (size_t i = 4; parts[i]; i+=3) {
				struct rune_altern *alt;
				alt = rune_altern_new(NULL,
						      parts[i],
						      parts[i+1][0],
						      parts[i+2]);
				rune_restr_add_altern(restr, take(alt));
			}
			rune_add_restr(rune1, take(restr));
			ok1(rune_eq(rune1, rune2));
		} else if (streq(parts[0], "MALFORMED")) {
			diag("test %s %s", parts[0], parts[1]);
			rune1 = rune_from_string(parts, parts[2]);
			ok1(!rune1);
			rune2 = rune_from_base64(parts, parts[3]);
			ok1(!rune2);
		} else if (streq(parts[0], "BAD DERIVATION")) {
			diag("test %s %s", parts[0], parts[1]);
			rune1 = rune_from_string(parts, parts[2]);
			ok1(rune1);
			rune2 = rune_from_base64(parts, parts[3]);
			ok1(rune2);
			ok1(rune_eq(rune1, rune2));
			ok1(rune_is_derived(mr, rune1) != NULL);
			ok1(rune_is_derived(mr, rune2) != NULL);
		} else {
			const char *err;
			diag("test %s", parts[0]);
			err = rune_test(parts, mr, rune1, check, parts);
			if (streq(parts[0], "PASS")) {
				ok1(!err);
			} else {
				assert(streq(parts[0], "FAIL"));
				ok1(err);
			}
		}
	}

	tal_free(mr);
	/* This exits depending on whether all tests passed */
	return exit_status();
}

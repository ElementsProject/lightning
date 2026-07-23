/* libbolt12 test suite.
 *
 * Uses the same test vectors as ocean-offer-cli/src/verify.rs.
 * SPDX-License-Identifier: BSD-MIT
 */
#include "config.h"
#include "contrib/libbolt12/bolt12.h"
#include <common/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
	tests_run++; \
	if ((a) == (b)) { tests_passed++; } \
	else { \
		fprintf(stderr, "FAIL [%s:%d]: %s (expected %d, got %d)\n", \
			__FILE__, __LINE__, msg, (int)(b), (int)(a)); \
	} \
} while(0)

#define ASSERT_NEQ(a, b, msg) do { \
	tests_run++; \
	if ((a) != (b)) { tests_passed++; } \
	else { \
		fprintf(stderr, "FAIL [%s:%d]: %s (should not be %d)\n", \
			__FILE__, __LINE__, msg, (int)(a)); \
	} \
} while(0)

/* Test vectors from ocean-offer-cli/src/verify.rs */

/* A valid offer/invoice/preimage tuple (CLN-generated). */
static const char *VALID_OFFER =
	"lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq";

static const char *VALID_INVOICE =
	"lni1qqg9sr0tna8ljw0tp9zk9uehh7s8vz3ufap52s2wypgxz7t0w468xgrxdaezqcnrx9chswp5ds6rwen2x4nhyees8qmnyuphvearscfhxdkhwar3x33hxe3kx3ehgmt9zcss8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9w2gpsz28qtqssxstnfpsaqtgdhchfv70shwvganrwuk28gwz9f6v5nlt37s0xh7hp5zvq8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9wq27sqsf52x7pdt5432aztt8ee3s5l20g3u0whwudkk5asanadjzz5qgzhgehdw5jyjf6m83awzntjkxykywzxycduph6gp5crv29qjf9gsasqv394jhcqgta9q4cr975hw4vl5nzekvuzujxv0u7rngsse707e0pq4duexv3930unvay593kd38t6z8em29zrsqqqqqqqqqqqqqqzgqqqqqqqqqqqqqayjedltzjqqqqqq9yq359nfhm4qst3qczk7fkkjhhqs6syjuygh3q87t8jsmtg04xvzu6vsys3fggzt92qvqj3c9wqvpqqq9syyp7ysy2f8c86t6qswj8x3qn3mufuashucu3jgpvj24g6jd4wjjkpthsgqtas84k74uvj2uvxh32exre34mu4vsc5cnmqpftru4cw0s6wujsk8ggn30v3jll8rn98r3xmlymy850udw2smfmse0amens93mk6fzt";

static const char *VALID_PREIMAGE =
	"a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc";

/* A Phoenix wallet offer (different issuer). */
static const char *PHOENIX_OFFER =
	"lno1pgd57cm9v9hzqnmxvejhygzrd35jqanpd35kgct5d9hkugqsacpcvnhsyh77376c0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrczf6ycmt3ftr363p6f3fm08epd84y0lkz4t5zphpuygjqnwxzklltqyqnv4q7rx9lc4k8zjcyy7jdxaupjyuhfu7j7jkrdszh9xah04npkysqrxka4j4yxve6j8czdzcr56f5m5hku3uy0zlqn3genn8pszptkms5u6vv6u7qjej4sg4r00r8lpkeuk9allsgz2gqhm8qmj9cuwcfttex5366yvcma274gtaysskp5nmxrl9h3gsdsqv38tquert0z9py4uadrnuceanv26ytqw2pwys6909szlpw562u5lw8gv0ne7jnz52w9903vfv28pdpswrq";

static const char *PHOENIX_INVOICE =
	"lni1qqgpllwtmnmv6xspe70m78ptxrr5vzsmfa3k2ctwyp8kven9wgsyxmrfypmxzmrfv3shg6t0dcsppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878syn5f3khzjk8r4zr5nznk70jz602gllv92hgyrwrcg3ypxuv9dl7kqgpxe2puxvtl3tvw99sgfay6dmcryfewnea9a9vxmq9w2dmwltxrvfqqxddmt92gven4y0sy69s8f5nfhf0dercg797p8z3n8xwrqyzhdhpfe5ce4eup9n9tq32x77x07rdnevtmllqsy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qmqqezwkpejxk7y2zfte6688e3nmxc45gkqu5zufp527tq97zaf54ef7uwscl8na9x9g5u22lzcjc5wz6rqux9yqc0gfq9gqzcyypaauxsjgg80qzvfrysks88du2s78vme6neec3jt5axdcrj4yj8a99ql5qm2quxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upfh49ulj5edehzplt3t9fyw9m2j63x9nmey3r8204yfqpj0y5zzlqzqv5wvsgcqc463wtwd2npxp2t953yqp5vj7j829em3apsnt56chhx2qz9rl9mszedhld2xpuzgthfx007d585x4nfxtdefz74f355mua8wwnnr0weqkgeyj8fa72saljsa0kjzhys9w3dt60k9jxqjddkttw5x50l99smn9grg39v0up6s83lvf5x3nxs3knpvm7qpz8vtl7gj78q9jv7yt8cw0nqpecrvfcy4a0tq2z7560lys4tzp3j2586awqv2pgm66plh4a0q73jw3fq3yzl0tje4u5emck0p3x5p5w9gr74xshtkplmk9p68qwa6uz4m3ez4gv35ldgnl3zytpnm6fszejm4rk4f8g6vrknh7cuas5qq6tgt3f0grshlxxzkcyyzm6jp60p9mym870h2nuk9cl2cz3urvd0qksyegf6lq6gquzy0xumkwge00066l8yyss5wh44hz7vr5nssx0ywst5ju5escm85qwyv4jjs8qdlg2llun2zfymp4qqu8u30avlt52879nsfwgvskvvv3hrmggelcjysxnegcgfxexeaz2k6zttq9vdf4pwfy7qfwcnf88j5gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqr6zgqqqq5szxshfdu6nqxq23sz5zqcu908d9dzgtmzva3vh28mpjz4hggyja3r8d48x6cuhxky628xjp4gps7sjq4cpsyqqqkqssy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qm7pqx6pt4td9rrz7ek6gpfzner0dmq9zz92md57cnee4mfv7mktgjj7c3vqn66pdzy80fzgu9sarhtdgd3sy6fl0pzq2dac6m5p87qd393q";

/* --- Test cases --- */

static void test_valid_verification(void)
{
	bolt12_error_t err;
	int rc;

	printf("  test_valid_verification... ");
	rc = bolt12_verify_offer_payment(VALID_OFFER, VALID_INVOICE,
					 VALID_PREIMAGE, &err);
	ASSERT_EQ(rc, 0, "Valid payment should verify");
	if (rc == 0)
		printf("OK\n");
	else
		printf("FAIL: %s\n", err.message);
}

static void test_mismatched_offer_invoice(void)
{
	bolt12_error_t err;
	int rc;

	printf("  test_mismatched_offer_invoice... ");
	/* Phoenix offer + valid CLN invoice -- should fail on signing pubkey
	 * or offer_id mismatch. */
	rc = bolt12_verify_offer_payment(PHOENIX_OFFER, VALID_INVOICE,
					 VALID_PREIMAGE, &err);
	ASSERT_NEQ(rc, 0, "Mismatched offer/invoice should fail");
	if (rc != 0)
		printf("OK (expected error: %s)\n", err.message);
	else
		printf("FAIL: should have errored\n");
}

static void test_bad_preimage(void)
{
	bolt12_error_t err;
	int rc;

	printf("  test_bad_preimage... ");
	/* Valid offer + valid invoice, but wrong preimage. */
	rc = bolt12_verify_offer_payment(VALID_OFFER, VALID_INVOICE,
					 "0000000000000000000000000000000000000000000000000000000000000000",
					 &err);
	ASSERT_NEQ(rc, 0, "Bad preimage should fail");
	if (rc != 0)
		printf("OK (expected error: %s)\n", err.message);
	else
		printf("FAIL: should have errored\n");
}

static void test_decode_offer(void)
{
	bolt12_error_t err;
	bolt12_offer_t *offer;
	bolt12_sha256_t id;
	bolt12_pubkey_t pk;

	printf("  test_decode_offer... ");
	offer = bolt12_offer_decode(VALID_OFFER, &err);
	ASSERT_NEQ((intptr_t)offer, 0, "Should decode valid offer");
	if (!offer) {
		printf("FAIL: %s\n", err.message);
		return;
	}

	ASSERT_EQ(bolt12_offer_id(offer, &id), 0, "Should compute offer_id");
	ASSERT_EQ(bolt12_offer_effective_signing_pubkey(offer, &pk), 0,
		  "Should have signing pubkey");

	/* Test property accessors */
	char desc[256];
	int desc_len = bolt12_offer_description(offer, desc, sizeof(desc));
	ASSERT_NEQ(desc_len, -1, "Should have description");
	if (desc_len >= 0)
		printf("\n    description: \"%s\" (%d bytes)\n", desc, desc_len);

	size_t npaths = bolt12_offer_num_paths(offer);
	printf("    paths: %zu\n", npaths);

	/* Currency should not be present (msat denomination) */
	char currency[8];
	int curr_len = bolt12_offer_currency(offer, currency, sizeof(currency));
	ASSERT_EQ(curr_len, -1, "Should not have currency (msat)");

	bolt12_offer_free(offer);
	printf("  ... OK\n");
}

static void test_decode_invoice(void)
{
	bolt12_error_t err;
	bolt12_invoice_t *invoice;
	bolt12_sha256_t hash;
	bolt12_pubkey_t pk;

	printf("  test_decode_invoice... ");
	invoice = bolt12_invoice_decode(VALID_INVOICE, &err);
	ASSERT_NEQ((intptr_t)invoice, 0, "Should decode valid invoice");
	if (!invoice) {
		printf("FAIL: %s\n", err.message);
		return;
	}

	ASSERT_EQ(bolt12_invoice_payment_hash(invoice, &hash), 0,
		  "Should have payment_hash");
	ASSERT_EQ(bolt12_invoice_signing_pubkey(invoice, &pk), 0,
		  "Should have signing_pubkey");

	/* Test property accessors */
	uint64_t amount = 0;
	ASSERT_EQ(bolt12_invoice_amount(invoice, &amount), 0,
		  "Should have amount");
	printf("\n    amount_msat: %llu\n", (unsigned long long)amount);

	uint64_t created_at = 0;
	ASSERT_EQ(bolt12_invoice_created_at(invoice, &created_at), 0,
		  "Should have created_at");
	printf("    created_at: %llu\n", (unsigned long long)created_at);

	uint64_t expiry = 0;
	ASSERT_EQ(bolt12_invoice_expiry(invoice, &expiry), 0,
		  "Should have expiry");
	printf("    expiry: %llu\n", (unsigned long long)expiry);

	bolt12_signature_t sig;
	ASSERT_EQ(bolt12_invoice_signature(invoice, &sig), 0,
		  "Should have signature");

	size_t inv_paths = bolt12_invoice_num_paths(invoice);
	printf("    paths: %zu\n", inv_paths);

	char inv_desc[256];
	int inv_desc_len = bolt12_invoice_description(invoice, inv_desc, sizeof(inv_desc));
	if (inv_desc_len >= 0)
		printf("    description: \"%s\"\n", inv_desc);

	bolt12_invoice_free(invoice);
	printf("  ... OK\n");
}

static void test_invalid_preimage_format(void)
{
	bolt12_error_t err;
	bolt12_invoice_t *invoice;
	int rc;

	printf("  test_invalid_preimage_format... ");
	invoice = bolt12_invoice_decode(VALID_INVOICE, &err);
	if (!invoice) {
		printf("SKIP (can't decode invoice: %s)\n", err.message);
		return;
	}

	/* Too short */
	rc = bolt12_verify_proof_of_payment(invoice, "deadbeef", &err);
	ASSERT_NEQ(rc, 0, "Short preimage should fail");

	/* Not hex */
	rc = bolt12_verify_proof_of_payment(invoice,
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		&err);
	ASSERT_NEQ(rc, 0, "Non-hex preimage should fail");

	bolt12_invoice_free(invoice);
	printf("OK\n");
}

static void test_invalid_offer_string(void)
{
	bolt12_error_t err;
	bolt12_offer_t *offer;

	printf("  test_invalid_offer_string... ");
	offer = bolt12_offer_decode("not_a_valid_offer", &err);
	ASSERT_EQ((intptr_t)offer, 0, "Invalid offer should return NULL");
	ASSERT_EQ(err.code, BOLT12_ERR_DECODE,
		  "Error code should be BOLT12_ERR_DECODE");
	printf("OK\n");
}

int main(void)
{
	int rc;

	setup_locale();
	printf("libbolt12 test suite\n");
	printf("====================\n\n");

	rc = bolt12_init();
	if (rc != 0) {
		fprintf(stderr, "FATAL: bolt12_init() failed\n");
		return 1;
	}

	printf("Decode tests:\n");
	test_decode_offer();
	test_decode_invoice();
	test_invalid_offer_string();

	printf("\nVerification tests:\n");
	test_valid_verification();
	test_mismatched_offer_invoice();
	test_bad_preimage();
	test_invalid_preimage_format();

	bolt12_cleanup();

	printf("\n====================\n");
	printf("Results: %d/%d passed\n", tests_passed, tests_run);

	return tests_passed == tests_run ? 0 : 1;
}

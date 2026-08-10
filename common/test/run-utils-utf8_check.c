#include "config.h"
#include <assert.h>
#include <common/amount.h>
#include <common/pseudorand.h>
#include <common/setup.h>
#include <common/utils.h>
#include <stdio.h>
#include <string.h>
#include <wire/wire.h>


bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }

struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }

 bool amount_feerate(u32 *feerate UNNEEDED, struct amount_sat fee UNNEEDED, size_t weight UNNEEDED)
{ fprintf(stderr, "amount_feerate called!\n"); abort(); }

struct amount_sat amount_sat(u64 satoshis UNNEEDED)
{ fprintf(stderr, "amount_sat called!\n"); abort(); }

 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }

bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }

bool amount_sat_greater_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_greater_eq called!\n"); abort(); }

 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }

struct amount_asset amount_sat_to_asset(struct amount_sat *sat UNNEEDED, const u8 *asset UNNEEDED)
{ fprintf(stderr, "amount_sat_to_asset called!\n"); abort(); }

struct amount_sat amount_tx_fee(u32 fee_per_kw UNNEEDED, size_t weight UNNEEDED)
{ fprintf(stderr, "amount_tx_fee called!\n"); abort(); }

const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }

bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }

void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }

void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }

void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }

u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }

u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }

u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }

u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }

void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }

const struct siphash_seed *siphash_seed(void)
{ fprintf(stderr, "siphash_seed called!\n"); abort(); }

void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }

void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }

void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }

void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }

void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }

void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }

void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }

void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }

static void test_valid(void)
{
	assert(utf8_check("hello world", strlen("hello world")));

	{
		static const u8 nansensu[] = {
			0xe3, 0x83, 0x8a, 0xe3, 0x83, 0xb3, 0xe3, 0x82,
			0xbb, 0xe3, 0x83, 0xb3, 0xe3, 0x82, 0xb9
		};
		assert(utf8_check(nansensu, sizeof(nansensu)));
	}

	assert(utf8_check("", 0));
}

static void test_banned(void)
{
	static const u8 embedded_nul[] = { 'a', 0x00, 'b' };
	assert(!utf8_check(embedded_nul, sizeof(embedded_nul)));

	assert(!utf8_check("a\tb", 3));

	static const u8 del[] = { 'a', 0x7f, 'b' };
	assert(!utf8_check(del, sizeof(del)));

	static const u8 c1_control[] = { 'a', 0xc2, 0x85, 'b' };
	assert(!utf8_check(c1_control, sizeof(c1_control)));

	static const u8 rtl_override[] = { 'a', 0xe2, 0x80, 0xae, 'b' };
	assert(!utf8_check(rtl_override, sizeof(rtl_override)));

	static const u8 private_use[] = { 'a', 0xee, 0x80, 0x80, 'b' };
	assert(!utf8_check(private_use, sizeof(private_use)));

	static const u8 unassigned[] = { 'a', 0xcd, 0xb8, 'b' };
	assert(!utf8_check(unassigned, sizeof(unassigned)));
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	test_valid();
	test_banned();

	common_shutdown();
}

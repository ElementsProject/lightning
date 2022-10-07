#include "internal.h"
#include "hmac.h"
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <ccan/compiler/compiler.h>
#include <include/wally_crypto.h>

#ifdef SHA_T
#undef SHA_T
#endif
#define SHA_T sha256
#define SHA_ALIGN_T uint32_t
#define SHA_MEM u32
#define SHA_POST(name) name ## sha256
#define SHA_POST_IMPL(name) name ## sha256_impl
#define PBKDF2_HMAC_SHA_LEN PBKDF2_HMAC_SHA256_LEN
#include "pbkdf2.inl"

#undef SHA_T
#define SHA_T sha512
#undef SHA_ALIGN_T
#define SHA_ALIGN_T uint64_t
#undef SHA_MEM
#define SHA_MEM u64
#undef SHA_POST
#define SHA_POST(name) name ## sha512
#undef SHA_POST_IMPL
#define SHA_POST_IMPL(name) name ## sha512_impl
#undef PBKDF2_HMAC_SHA_LEN
#define PBKDF2_HMAC_SHA_LEN PBKDF2_HMAC_SHA512_LEN
#include "pbkdf2.inl"


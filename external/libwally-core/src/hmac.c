#include "internal.h"
#include "hmac.h"
#include <ccan/ccan/crypto/sha256/sha256.h>
#include <ccan/ccan/crypto/sha512/sha512.h>
#include <include/wally_crypto.h>
#include <stdbool.h>

#ifdef SHA_T
#undef SHA_T
#endif
#define SHA_T sha256
#define SHA_CTX_MEMBER u32
#define SHA_PRE(name) sha256 ## name
#define HMAC_FUNCTION hmac_sha256_impl
#define WALLY_HMAC_FUNCTION wally_hmac_sha256
#include "hmac.inl"

#undef SHA_T
#define SHA_T sha512
#undef SHA_CTX_MEMBER
#define SHA_CTX_MEMBER u64
#undef SHA_PRE
#define SHA_PRE(name) sha512 ## name
#undef HMAC_FUNCTION
#define HMAC_FUNCTION hmac_sha512_impl
#undef WALLY_HMAC_FUNCTION
#define WALLY_HMAC_FUNCTION wally_hmac_sha512
#include "hmac.inl"

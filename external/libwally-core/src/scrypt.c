#include "internal.h"
#include <include/wally_bip38.h>
#include <include/wally_crypto.h>
#include "hmac.h"
#include "ccan/ccan/endian/endian.h"

/* Use scrypts internal malloc/free */
#undef malloc
#undef free

/* Implement functions required by the scrypt core */
static uint32_t le32dec(const void *p)
{
    leint32_t tmp;
    memcpy(&tmp, p, sizeof(tmp));
    return le32_to_cpu(tmp);
}

static void le32enc(void *p, uint32_t value)
{
    leint32_t tmp = cpu_to_le32(value);
    memcpy(p, &tmp, sizeof(tmp));
}

static void PBKDF2_SHA256(const unsigned char *pass, size_t pass_len,
                          const unsigned char *salt, size_t salt_len,
                          uint64_t cost,
                          unsigned char *bytes_out, size_t len)
{
    const uint32_t flags = 0;
    wally_pbkdf2_hmac_sha256(pass, pass_len, (unsigned char *)salt, salt_len,
                             flags, (uint32_t)cost, bytes_out, len);
}

/* Include a suitable smix function/functions */
#if defined(__ARM_NEON__) || defined(__ARM_NEON)
# include <arm_neon.h>
# include "scrypt/crypto_scrypt_smix_neon.c"
# if !defined(__ANDROID__)
/* No way to check for support, assume Neon present */
#  define crypto_scrypt_smix_fn crypto_scrypt_smix_neon
# else
/* On Android, detect Neon support at runtime */
#  include "cpufeatures/cpu-features.h"
#  include "scrypt/crypto_scrypt_smix.c"
static void
crypto_scrypt_smix_fn(uint8_t *B, size_t r, uint64_t N, void *_V, void *XY)
{
    if (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON)
        crypto_scrypt_smix_neon(B, r, N, _V, XY);
    else
        crypto_scrypt_smix_c(B, r, N, _V, XY);
}
# endif
#elif defined(__SSE2__)
/* Use the SSE2 version */
# include "scrypt/crypto_scrypt_smix_sse2.c"
# define crypto_scrypt_smix_fn crypto_scrypt_smix_sse2
#else
/* Use the C version */
# include "scrypt/crypto_scrypt_smix.c"
# define crypto_scrypt_smix_fn crypto_scrypt_smix_c
#endif

#include "scrypt/crypto_scrypt.c"

/* Our scrypt wrapper. */
int wally_scrypt(const unsigned char *pass, size_t pass_len,
                 const unsigned char *salt, size_t salt_len,
                 uint32_t cost, uint32_t block_size, uint32_t parallelism,
                 unsigned char *bytes_out, size_t len)
{
    return _crypto_scrypt(pass, pass_len, salt, salt_len,
                          cost, block_size, parallelism,
                          bytes_out, len, crypto_scrypt_smix_fn);
}

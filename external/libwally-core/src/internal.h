#ifndef LIBWALLY_INTERNAL_H
#define LIBWALLY_INTERNAL_H

#include <include/wally_core.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"
#ifndef BUILD_STANDARD_SECP
#include "secp256k1/include/secp256k1_ecdsa_s2c.h"
#endif
#include <config.h>
#if defined(HAVE_MEMSET_S)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

/* Fetch an internal secp context */
const secp256k1_context *secp_ctx(void);
#define secp256k1_context_destroy(c) _do_not_destroy_shared_ctx_pointers(c)

/* secp pub/priv key functions */
#define pubkey_create     secp256k1_ec_pubkey_create
#define pubkey_tweak_add  secp256k1_ec_pubkey_tweak_add

int privkey_tweak_add(unsigned char *seckey, const unsigned char *tweak);
int pubkey_combine(secp256k1_pubkey *pubnonce, const secp256k1_pubkey *const *pubnonces, size_t n);
int pubkey_negate(secp256k1_pubkey *pubkey);
int pubkey_parse(secp256k1_pubkey *pubkey, const unsigned char *input, size_t inputlen);
int pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags);
int seckey_verify(const unsigned char *seckey);

#define PUBKEY_COMPRESSED   SECP256K1_EC_COMPRESSED
#define PUBKEY_UNCOMPRESSED SECP256K1_EC_UNCOMPRESSED


void wally_clear(void *p, size_t len);
void wally_clear_2(void *p, size_t len, void *p2, size_t len2);
void wally_clear_3(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3);
void wally_clear_4(void *p, size_t len, void *p2, size_t len2,
                   void *p3, size_t len3, void *p4, size_t len4);

void clear_and_free(void *p, size_t len);

/* Fetch our internal operations function pointers */
const struct wally_operations *wally_ops(void);

void *wally_malloc(size_t size);
void *wally_calloc(size_t size);
void wally_free(void *ptr);
char *wally_strdup(const char *str);

#define malloc(size) __use_wally_malloc_internally__
#define calloc(size) __use_wally_calloc_internally__
#define free(ptr) __use_wally_free_internally__
#ifdef strdup
#undef strdup
#endif
#define strdup(ptr) __use_wally_strdup_internally__

/* Validity checking for input parameters */
#define BYTES_VALID(p, len) ((p != NULL) == (len != 0))
#define BYTES_INVALID(p, len) (!BYTES_VALID(p, len))
#define BYTES_INVALID_N(p, len, siz) ((p != NULL) != (len == siz))

#endif /* LIBWALLY_INTERNAL_H */

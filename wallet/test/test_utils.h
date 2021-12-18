#ifndef LIGHTNING_WALLET_TEST_TEST_UTILS_H
#define LIGHTNING_WALLET_TEST_TEST_UTILS_H

#include "config.h"
#include "lightningd/lightningd.h"

/* Definitions "inspired" by libsecp256k1 */
#define TEST_FAILURE(msg) do { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
    return false; \
} while(0)

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#define CHECK_MSG(cond,msg) do {      \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE(msg); \
    } \
} while(0)

#define CHECK(cond) CHECK_MSG(cond,"test condition failed");

const struct config test_config;

#endif /* LIGHTNING_WALLET_TEST_TEST_UTILS_H */

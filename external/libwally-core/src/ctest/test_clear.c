#include "config.h"

#ifdef HAVE_ASM_PAGE_H
#   include <asm/page.h>
#endif
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


/* From ASAN wiki, modified to not break gcc */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__)
extern void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    __asan_poison_memory_region((addr), (size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    __asan_unpoison_memory_region((addr), (size))
#else
#define ASAN_POISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#endif

/* Many compilers these days will elide calls to memset when they
 * determine that the memory is not read afterwards. There are reports
 * that tricks designed to work around this including making data volatile,
 * calling through function pointers, dummy asm contraints etc are
 * not always effective as optimisation continues to improve.
 *
 * Here we try to ensure that the wally_clear/wally_clear_n() functions work as advertised
 * by:
 * - Setting a custom thread stack, then
 * - Calling a function that processes sensitive data, then
 * - Searching the stack for any sensitive data when the function returns
 *
 * This test does not address data leaked through registers, ancillary heap
 * allocations, side channels, or being swapped to disk.
 */
#ifndef PTHREAD_STACK_MIN
/* OSX Needs a minimum of 512K of stack per thread */
#define PTHREAD_STACK_MIN 512u * 1024u
#endif

/* Global alternate stack pointer */
static unsigned char *gstack;
/* Global scratch buffer */
static unsigned char *gbytes;

static const char *BIP39_MNEMONIC = "legal winner thank year wave sausage worth "
                                    "useful legal winner thank yellow";
static const unsigned char BIP39_SECRET[16] = {
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
};

/* Useful for developing these tests */
static void dump_mem(volatile const void *mem, size_t len)
{
    static size_t i;
    for (i = 0; i < len; ++i) {
        if (!((const unsigned char *)mem)[i])
            printf(".");
        else
            printf("%02x, ", ((const unsigned char *)mem)[i]);
    }
    printf("\n");
}

static unsigned char *checked_malloc(size_t len)
{
    void *ret = malloc(len);
    if (!ret)
        abort();
    wally_bzero(ret, len);
    return ret;
}

static bool in_stack(const char *caller, volatile const void *search, size_t len)
{
    static size_t i;

    for (i = 0; i < PTHREAD_STACK_MIN - len - 1; ++i)
        if (!memcmp(gstack + i, (const void *)search, len)) {
            if (caller) {
                printf("Found %s secret at stack position %ld and base %p\n", caller, (long)i, (void *)gstack);
                dump_mem(search, len);
            }
            return true; /* Found */
        }

    return false; /* Not found */
}

/* Test that searching for data on the stack actually works */
static bool test_search(void)
{
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    /* Don't let the optimiser elide buf off the stack */
    buf[7] ^= (((size_t)gstack) & 0xff);

    return in_stack(NULL, buf, sizeof(buf));
}

static bool test_bip39(void)
{
    static size_t len;
    /* Converting uses a temporary buffer on the stack */
    if (bip39_mnemonic_to_bytes(NULL, BIP39_MNEMONIC, gbytes,
                                BIP39_ENTROPY_LEN_128, &len))
        return false;

    if (in_stack("bip39_mnemonic_to_bytes", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    /* Internally converts to bytes */
    if (bip39_mnemonic_validate(NULL, BIP39_MNEMONIC))
        return false;

    if (in_stack("bip39_mnemonic_validate", BIP39_SECRET, sizeof(BIP39_SECRET)))
        return false;

    return true;
}

static void *run_tests(void *passed_stack)
{
    if (passed_stack != gstack) {
        printf("stack mismatch!\n");
        return passed_stack;
    }

#define RUN(t) if (!t()) { printf(#t " wally_clear() test failed!\n"); return gstack; }

    /* Due to the nature of the test reading poisoned bytes off the custom stack will trigger ASAN */
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_search);

    /* Due to the nature of the test reading poisoned bytes off the custom stack will trigger ASAN */
    ASAN_UNPOISON_MEMORY_REGION(passed_stack, PTHREAD_STACK_MIN);
    RUN(test_bip39);

    return NULL;
}

static int error(const char *fn, int ret)
{
    printf("error: %s failed, returned %d\n", fn, ret);
    return ret;
}

int main(void)
{
    pthread_t id;
    pthread_attr_t attr;
    void *tests_ok = &gstack; /* Anything non-null */
    int ret;

    gstack = checked_malloc(PTHREAD_STACK_MIN);
    gbytes = checked_malloc(64u * 1024u);

    ret = pthread_attr_init(&attr);
    if (ret)
        return error("pthread_attr_init", ret);

    ret = pthread_attr_setstack(&attr, gstack, PTHREAD_STACK_MIN);
    if (ret)
        return error("pthread_attr_setstack", ret);

    ret = pthread_create(&id, &attr, run_tests, gstack);
    if (ret)
        return error("pthread_create", ret);

    ret = pthread_join(id, &tests_ok);
    if (ret)
        return error("pthread_join", ret);

    free(gbytes);
    free(gstack);

    return tests_ok == NULL ? 0 : 1;
}

#include "internal.h"
#include "mnemonic.h"
#include "wordlist.h"
#include "hmac.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/sha512/sha512.h"
#include <include/wally_bip39.h>
#include <include/wally_crypto.h>

#include "data/wordlists/english.c"

#ifndef BUILD_MINIMAL
#include "data/wordlists/chinese_simplified.c"
#include "data/wordlists/chinese_traditional.c"
#include "data/wordlists/french.c"
#include "data/wordlists/italian.c"
#include "data/wordlists/spanish.c"
#include "data/wordlists/japanese.c"
#endif

/* Maximum length including up to 2 bytes for checksum */
#define BIP39_ENTROPY_LEN_MAX (BIP39_ENTROPY_LEN_320 + sizeof(unsigned char) * 2)

static const struct {
    const char name[4];
    const struct words *words;
} lookup[] = {
    { "en", &en_words},
#ifndef BUILD_MINIMAL
    { "es", &es_words}, { "fr", &fr_words},
    { "it", &it_words}, { "jp", &jp_words}, { "zhs", &zhs_words},
    { "zht", &zht_words},
    /* FIXME: Should 'zh' map to traditional or simplified? */
#endif
};

int bip39_get_languages(char **output)
{
    if (!output)
        return WALLY_EINVAL;
#ifndef BUILD_MINIMAL
    *output = wally_strdup("en es fr it jp zhs zht");
#else
    *output = wally_strdup("en");
#endif
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

int bip39_get_wordlist(const char *lang, struct words **output)
{
    size_t i;

    if (!output)
        return WALLY_EINVAL;

    *output = (struct words *)&en_words; /* Fallback to English if not found */

    if (lang)
        for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); ++i)
            if (!strcmp(lang, lookup[i].name)) {
                *output = (struct words *)lookup[i].words;
                break;
            }
    return WALLY_OK;
}

int bip39_get_word(const struct words *w, size_t idx,
                   char **output)
{
    const char *word;

    if (output)
        *output = NULL;

    w = w ? w : &en_words;

    if (!output || !(word = wordlist_lookup_index(w, idx)))
        return WALLY_EINVAL;

    *output = wally_strdup(word);
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

/* Convert an input entropy length to a mask for checksum bits. As it
 * returns 0 for bad lengths, it serves as a validation function too.
 */
static size_t len_to_mask(size_t len)
{
    switch (len) {
    case BIP39_ENTROPY_LEN_128: return 0xf0;
    case BIP39_ENTROPY_LEN_160: return 0xf8;
    case BIP39_ENTROPY_LEN_192: return 0xfc;
    case BIP39_ENTROPY_LEN_224: return 0xfe;
    case BIP39_ENTROPY_LEN_256: return 0xff;
    case BIP39_ENTROPY_LEN_288: return 0x80ff;
    case BIP39_ENTROPY_LEN_320: return 0xC0ff;
    }
    return 0;
}

static size_t bip39_checksum(const unsigned char *bytes, size_t bytes_len, size_t mask)
{
    struct sha256 sha;
    size_t ret;
    sha256(&sha, bytes, bytes_len);
    ret = sha.u.u8[0] | (sha.u.u8[1] << 8);
    wally_clear(&sha, sizeof(sha));
    return ret & mask;
}

int bip39_mnemonic_from_bytes(const struct words *w,
                              const unsigned char *bytes, size_t bytes_len,
                              char **output)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_MAX];
    size_t checksum, mask;

    if (output)
        *output = NULL;

    if (!bytes || !bytes_len || !output)
        return WALLY_EINVAL;

    w = w ? w : &en_words;

    if (w->bits != 11u || !(mask = len_to_mask(bytes_len)))
        return WALLY_EINVAL;

    memcpy(tmp_bytes, bytes, bytes_len);
    checksum = bip39_checksum(bytes, bytes_len, mask);
    tmp_bytes[bytes_len] = checksum & 0xff;
    if (mask > 0xff)
        tmp_bytes[++bytes_len] = (checksum >> 8) & 0xff;
    *output = mnemonic_from_bytes(w, tmp_bytes, bytes_len + 1);
    wally_clear(tmp_bytes, sizeof(tmp_bytes));
    return *output ? WALLY_OK : WALLY_ENOMEM;
}

static bool checksum_ok(const unsigned char *bytes, size_t idx, size_t mask)
{
    /* The checksum is stored after the data to sum */
    size_t calculated = bip39_checksum(bytes, idx, mask);
    size_t stored = bytes[idx];
    if (mask > 0xff)
        stored |= (bytes[idx + 1] << 8);
    return (stored & mask) == calculated;
}

int bip39_mnemonic_to_bytes(const struct words *w, const char *mnemonic,
                            unsigned char *bytes_out, size_t len,
                            size_t *written)
{
    unsigned char tmp_bytes[BIP39_ENTROPY_LEN_MAX];
    size_t mask, tmp_len;
    int ret;

    /* Ideally we would infer the wordlist here. Unfortunately this cannot
     * work reliably because the default word lists overlap. In combination
     * with being sorted lexographically, this means the default lists
     * were poorly chosen. But we are stuck with them now.
     *
     * If the caller doesn't know which word list to use, they should iterate
     * over the available ones and try any resulting list that the mnemonic
     * validates against.
     */
    w = w ? w : &en_words;

    if (written)
        *written = 0;

    if (w->bits != 11u || !mnemonic || !bytes_out)
        return WALLY_EINVAL;

    ret = mnemonic_to_bytes(w, mnemonic, tmp_bytes, sizeof(tmp_bytes), &tmp_len);

    if (!ret) {
        /* Remove checksum bytes from the output length */
        --tmp_len;
        if (tmp_len > BIP39_ENTROPY_LEN_256)
            --tmp_len; /* Second byte required */

        if (tmp_len > sizeof(tmp_bytes))
            ret = WALLY_EINVAL; /* Too big for biggest supported entropy */
        else {
            if (tmp_len <= len) {
                if (!(mask = len_to_mask(tmp_len)) ||
                    !checksum_ok(tmp_bytes, tmp_len, mask)) {
                    tmp_len = 0;
                    ret = WALLY_EINVAL; /* Bad checksum */
                }
                else
                    memcpy(bytes_out, tmp_bytes, tmp_len);
            }
        }
    }

    wally_clear(tmp_bytes, sizeof(tmp_bytes));
    if (!ret && written)
        *written = tmp_len;
    return ret;
}

int bip39_mnemonic_validate(const struct words *w, const char *mnemonic)
{
    unsigned char buf[BIP39_ENTROPY_LEN_MAX];
    size_t len;
    int ret = bip39_mnemonic_to_bytes(w, mnemonic, buf, sizeof(buf), &len);
    wally_clear(buf, sizeof(buf));
    return ret;
}

int  bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                            unsigned char *bytes_out, size_t len,
                            size_t *written)
{
    const uint32_t bip9_cost = 2048u;
    const char *prefix = "mnemonic";
    const size_t prefix_len = strlen(prefix);
    const size_t passphrase_len = passphrase ? strlen(passphrase) : 0;
    const size_t salt_len = prefix_len + passphrase_len;
    unsigned char *salt;
    int ret;

    if (written)
        *written = 0;

    if (!mnemonic || !bytes_out || len != BIP39_SEED_LEN_512)
        return WALLY_EINVAL;

    salt = wally_malloc(salt_len);
    if (!salt)
        return WALLY_ENOMEM;

    memcpy(salt, prefix, prefix_len);
    if (passphrase_len)
        memcpy(salt + prefix_len, passphrase, passphrase_len);

    ret = wally_pbkdf2_hmac_sha512((unsigned char *)mnemonic, strlen(mnemonic),
                                   salt, salt_len, 0,
                                   bip9_cost, bytes_out, len);

    if (!ret && written)
        *written = BIP39_SEED_LEN_512; /* Succeeded */

    clear_and_free(salt, salt_len);

    return ret;
}

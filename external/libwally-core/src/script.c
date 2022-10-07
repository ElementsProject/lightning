#include "internal.h"

#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include <include/wally_crypto.h>
#include <include/wally_script.h>
#include <include/wally_transaction.h>

#include <limits.h>
#include <stdbool.h>
#include "script_int.h"

/* varint tags and limits */
#define VI_TAG_16 253
#define VI_TAG_32 254
#define VI_TAG_64 255

#define VI_MAX_8 252
#define VI_MAX_16 USHRT_MAX
#define VI_MAX_32 UINT_MAX

#define ALL_SCRIPT_HASH_FLAGS (WALLY_SCRIPT_HASH160 | WALLY_SCRIPT_SHA256)

static bool script_flags_ok(uint32_t flags, uint32_t extra_flags)
{
    if ((flags & ~(ALL_SCRIPT_HASH_FLAGS | extra_flags)) ||
        ((flags & ALL_SCRIPT_HASH_FLAGS) == ALL_SCRIPT_HASH_FLAGS))
        return false;
    return true;
}

bool script_is_op_n(unsigned char op, bool allow_zero, size_t *n) {
    if (allow_zero && op == OP_0) {
        if (n)
            *n = 0;
        return true;
    }
    if (op >= OP_1 && op <= OP_16) {
        if (n)
            *n = op - OP_1 + 1;
        return true;
    }
    return false;
}

/* Note: does no parameter checking, v must be between 0 and 16 */
size_t value_to_op_n(uint64_t v)
{
    if (!v)
        return OP_0;
    return OP_1 + v - 1;
}

static bool is_pk_len(size_t bytes_len) {
    return bytes_len == EC_PUBLIC_KEY_LEN ||
           bytes_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
}

/* Calculate the opcode size of a push of 'n' bytes */
static size_t calc_push_opcode_size(size_t n)
{
    if (n < 76)
        return 1;
    else if (n < 256)
        return 2;
    else if (n < 65536)
        return 3;
    return 5;
}

size_t script_get_push_size(size_t n)
{
    return calc_push_opcode_size(n) + n;
}

static int get_push_size(const unsigned char *bytes, size_t bytes_len,
                         bool get_opcode_size, size_t *size_out)
{
    size_t opcode_len;

    if (!bytes || !bytes_len || !size_out)
        return WALLY_EINVAL;

    if (bytes[0] < 76) {
        opcode_len = 1;
        *size_out = bytes[0];
    } else if (bytes[0] == OP_PUSHDATA1) {
        opcode_len = 2;
        if (bytes_len < opcode_len)
            return WALLY_EINVAL;
        *size_out = bytes[1];
    } else if (bytes[0] == OP_PUSHDATA2) {
        leint16_t data_len;
        opcode_len = 3;
        if (bytes_len < opcode_len)
            return WALLY_EINVAL;
        memcpy(&data_len, &bytes[1], sizeof(data_len));
        *size_out = le16_to_cpu(data_len);
    } else if (bytes[0] == OP_PUSHDATA4) {
        leint32_t data_len;
        opcode_len = 5;
        if (bytes_len < opcode_len)
            return WALLY_EINVAL;
        memcpy(&data_len, &bytes[1], sizeof(data_len));
        *size_out = le32_to_cpu(data_len);
    } else
        return WALLY_EINVAL; /* Not a push */
    if (bytes_len < opcode_len + *size_out)
        return WALLY_EINVAL; /* Push is longer than current script bytes */
    if (get_opcode_size)
        *size_out = opcode_len;
    return WALLY_OK;
}

size_t varint_get_length(uint64_t v)
{
    if (v <= VI_MAX_8)
        return sizeof(uint8_t);
    if (v <= VI_MAX_16)
        return sizeof(uint8_t) + sizeof(uint16_t);
    if (v <= VI_MAX_32)
        return sizeof(uint8_t) + sizeof(uint32_t);
    return sizeof(uint8_t) + sizeof(uint64_t);
}

size_t varint_to_bytes(uint64_t v, unsigned char *bytes_out)
{
    if (v <= VI_MAX_8)
        return uint8_to_le_bytes(v, bytes_out);
    else if (v <= VI_MAX_16) {
        *bytes_out++ = VI_TAG_16;
        return sizeof(uint8_t) + uint16_to_le_bytes(v, bytes_out);
    } else if (v <= VI_MAX_32) {
        *bytes_out++ = VI_TAG_32;
        return sizeof(uint8_t) + uint32_to_le_bytes(v, bytes_out);
    }
    *bytes_out++ = VI_TAG_64;
    return sizeof(uint8_t) + uint64_to_le_bytes(v, bytes_out);
}

size_t varint_length_from_bytes(const unsigned char *bytes)
{
    switch (*bytes) {
    case VI_TAG_16:
        return sizeof(uint8_t) + sizeof(uint16_t);
    case VI_TAG_32:
        return sizeof(uint8_t) + sizeof(uint32_t);
    case VI_TAG_64:
        return sizeof(uint8_t) + sizeof(uint64_t);
    }
    return sizeof(uint8_t);
}

/* Get the length of a script integer in bytes. signed_v should not be
 * larger than int32_t (i.e. +/- 31 bits)
 */
static size_t scriptint_get_length(int64_t signed_v)
{
    uint64_t v = signed_v < 0 ? -signed_v : signed_v;
    size_t len = 0;
    unsigned char last = 0;

    while (v) {
        last = v & 0xff;
        len += 1;
        v >>= 8;
    }
    return len + (last & 0x80 ? 1 : 0);
}

static size_t scriptint_to_bytes(int64_t signed_v, unsigned char *bytes_out)
{
    uint64_t v = signed_v < 0 ? -signed_v : signed_v;
    size_t len = 0;
    unsigned char last = 0;

    while (v) {
        last = v & 0xff;
        *bytes_out++ = last;
        len += 1;
        v >>= 8;
    }
    if (last & 0x80) {
        *bytes_out = signed_v < 0 ? 0x80 : 0;
        ++len;
    } else if (signed_v < 0)
        bytes_out[-1] |= 0x80;
    return len;
}

static size_t confidential_commitment_length_from_bytes(const unsigned char *bytes,
                                                        bool ct_value)
{
    if (bytes) {
        switch (*bytes) {
        case 1:
            return ct_value ? WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN : WALLY_TX_ASSET_CT_LEN;
        case WALLY_TX_ASSET_CT_VALUE_PREFIX_A:
        case WALLY_TX_ASSET_CT_VALUE_PREFIX_B:
        case WALLY_TX_ASSET_CT_ASSET_PREFIX_A:
        case WALLY_TX_ASSET_CT_ASSET_PREFIX_B:
        case WALLY_TX_ASSET_CT_NONCE_PREFIX_A:
        case WALLY_TX_ASSET_CT_NONCE_PREFIX_B:
            return WALLY_TX_ASSET_CT_LEN;
        }
    }
    return sizeof(uint8_t);
}

static size_t confidential_commitment_varint_from_bytes(const unsigned char *bytes,
                                                        uint64_t *v,
                                                        bool ct_value)
{
    switch (*bytes) {
    case 1:
        *v = ct_value ? WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN : WALLY_TX_ASSET_CT_LEN;
        return *v;
    case WALLY_TX_ASSET_CT_VALUE_PREFIX_A:
    case WALLY_TX_ASSET_CT_VALUE_PREFIX_B:
    case WALLY_TX_ASSET_CT_ASSET_PREFIX_A:
    case WALLY_TX_ASSET_CT_ASSET_PREFIX_B:
    case WALLY_TX_ASSET_CT_NONCE_PREFIX_A:
    case WALLY_TX_ASSET_CT_NONCE_PREFIX_B:
        *v = WALLY_TX_ASSET_CT_LEN;
        return *v;
    }
    *v = 0;
    return sizeof(uint8_t);
}

size_t confidential_asset_length_from_bytes(const unsigned char *bytes)
{
    return confidential_commitment_length_from_bytes(bytes, false);
}

size_t confidential_value_length_from_bytes(const unsigned char *bytes)
{
    return confidential_commitment_length_from_bytes(bytes, true);
}

size_t confidential_nonce_length_from_bytes(const unsigned char *bytes)
{
    return confidential_commitment_length_from_bytes(bytes, false);
}

size_t confidential_asset_varint_from_bytes(const unsigned char *bytes, uint64_t *v)
{
    return confidential_commitment_varint_from_bytes(bytes, v, false);
}

size_t confidential_value_varint_from_bytes(const unsigned char *bytes, uint64_t *v)
{
    return confidential_commitment_varint_from_bytes(bytes, v, true);
}

size_t confidential_nonce_varint_from_bytes(const unsigned char *bytes, uint64_t *v)
{
    return confidential_commitment_varint_from_bytes(bytes, v, false);
}

size_t varint_from_bytes(const unsigned char *bytes, uint64_t *v)
{
#define b(n) ((uint64_t)bytes[n] << ((n - 1) * 8))
    switch (*bytes) {
    case VI_TAG_16:
        *v = b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint16_t);
    case VI_TAG_32:
        *v = b(4) | b(3) | b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint32_t);
    case VI_TAG_64:
        *v = b(8) | b(7) | b(6) | b(5) | b(4) | b(3) | b(2) | b(1);
        return sizeof(uint8_t) + sizeof(uint64_t);
    }
    *v = *bytes;
    return sizeof(uint8_t);
#undef b
}

size_t varbuff_to_bytes(const unsigned char *bytes, size_t bytes_len,
                        unsigned char *bytes_out)
{
    size_t n = varint_to_bytes(bytes_len, bytes_out);
    bytes_out += n;
    if (bytes_len)
        memcpy(bytes_out, bytes, bytes_len);
    return n + bytes_len;
}

size_t confidential_value_to_bytes(const unsigned char *bytes, size_t bytes_len,
                                   unsigned char *bytes_out)
{
    if (!bytes_len)
        *bytes_out = 0;
    else
        memcpy(bytes_out, bytes, bytes_len);
    return !bytes_len ? 1 : bytes_len;
}

static bool scriptpubkey_is_op_return(const unsigned char *bytes, size_t bytes_len)
{
    size_t n_op, n_push;

    return bytes_len && bytes[0] == OP_RETURN &&
           get_push_size(bytes + 1, bytes_len - 1, true, &n_op) == WALLY_OK &&
           get_push_size(bytes + 1, bytes_len - 1, false, &n_push) == WALLY_OK &&
           bytes_len == 1 + n_op + n_push;
}

static bool scriptpubkey_is_p2pkh(const unsigned char *bytes, size_t bytes_len)
{
    return bytes_len == WALLY_SCRIPTPUBKEY_P2PKH_LEN &&
           bytes[0] == OP_DUP && bytes[1] == OP_HASH160 &&
           bytes[2] == 20 && /* HASH160 */
           bytes[23] == OP_EQUALVERIFY &&
           bytes[24] == OP_CHECKSIG;
}

static bool scriptpubkey_is_p2sh(const unsigned char *bytes, size_t bytes_len)
{
    return bytes_len == WALLY_SCRIPTPUBKEY_P2SH_LEN &&
           bytes[0] == OP_HASH160 &&
           bytes[1] == 20 && /* HASH160 */
           bytes[22] == OP_EQUAL;
}

static bool scriptpubkey_is_p2wpkh(const unsigned char *bytes, size_t bytes_len)
{
    return bytes_len == WALLY_SCRIPTPUBKEY_P2WPKH_LEN &&
           bytes[0] == OP_0 && /* Segwit v0 */
           bytes[1] == 20; /* HASH160 */
}

static bool scriptpubkey_is_p2wsh(const unsigned char *bytes, size_t bytes_len)
{
    return bytes_len == WALLY_SCRIPTPUBKEY_P2WSH_LEN &&
           bytes[0] == OP_0 && /* Segwit v0 */
           bytes[1] == 32; /* SHA256 */
}

static bool scriptpubkey_is_p2tr(const unsigned char *bytes, size_t bytes_len)
{
    return bytes_len == WALLY_SCRIPTPUBKEY_P2TR_LEN &&
           bytes[0] == OP_1 && /* Segwit v1 */
           bytes[1] == 32; /* X-ONLY-PUBKEY */
}

static bool scriptpubkey_is_multisig(const unsigned char *bytes, size_t bytes_len)
{
    const size_t min_1of1_len = 1 + 1 + 33 + 1 + 1; /* OP_1 [pubkey] OP_1 OP_CHECKMULTISIG */
    size_t i, n_pushes;

    if (bytes_len < min_1of1_len || !script_is_op_n(bytes[0], false, NULL) ||
        bytes[bytes_len - 1] != OP_CHECKMULTISIG ||
        !script_is_op_n(bytes[bytes_len - 2], false, &n_pushes))
        return false;

    ++bytes;
    --bytes_len;
    for (i = 0; i < n_pushes; ++i) {
        size_t n_op, n_push;
        if (get_push_size(bytes, bytes_len, true, &n_op) != WALLY_OK ||
            get_push_size(bytes, bytes_len, false, &n_push) != WALLY_OK ||
            !is_pk_len(n_push) || bytes_len < n_op + n_push + 2)
            return false;
        bytes += n_op + n_push;
        bytes_len -= n_op + n_push;
    }
    return bytes_len == 2;
}

int wally_scriptpubkey_get_type(const unsigned char *bytes, size_t bytes_len,
                                size_t *written)
{
    if (written)
        *written = WALLY_SCRIPT_TYPE_UNKNOWN;

    if (!bytes || !bytes_len || !written)
        return WALLY_EINVAL;

    if (scriptpubkey_is_op_return(bytes, bytes_len)) {
        *written = WALLY_SCRIPT_TYPE_OP_RETURN;
        return WALLY_OK;
    }

    if (scriptpubkey_is_multisig(bytes, bytes_len)) {
        *written = WALLY_SCRIPT_TYPE_MULTISIG;
        return WALLY_OK;
    }

    switch (bytes_len) {
    case WALLY_SCRIPTPUBKEY_P2PKH_LEN:
        if (scriptpubkey_is_p2pkh(bytes, bytes_len)) {
            *written = WALLY_SCRIPT_TYPE_P2PKH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2SH_LEN:
        if (scriptpubkey_is_p2sh(bytes, bytes_len)) {
            *written = WALLY_SCRIPT_TYPE_P2SH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2WPKH_LEN:
        if (scriptpubkey_is_p2wpkh(bytes, bytes_len)) {
            *written = WALLY_SCRIPT_TYPE_P2WPKH;
            return WALLY_OK;
        }
        break;
    case WALLY_SCRIPTPUBKEY_P2WSH_LEN: /* Also WALLY_SCRIPTPUBKEY_P2TR_LEN */
        if (scriptpubkey_is_p2wsh(bytes, bytes_len)) {
            *written = WALLY_SCRIPT_TYPE_P2WSH;
            return WALLY_OK;
        } else if (scriptpubkey_is_p2tr(bytes, bytes_len)) {
            *written = WALLY_SCRIPT_TYPE_P2TR;
            return WALLY_OK;
        }
        break;
    }
    return WALLY_OK;
}

int wally_scriptpubkey_p2pkh_from_bytes(
    const unsigned char *bytes, size_t bytes_len,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || !script_flags_ok(flags, 0) ||
        (flags & WALLY_SCRIPT_SHA256) || !bytes_out ||
        len < WALLY_SCRIPTPUBKEY_P2PKH_LEN || !written)
        return WALLY_EINVAL;

    if (flags & WALLY_SCRIPT_HASH160) {
        if (bytes_len != EC_PUBLIC_KEY_LEN && bytes_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
            return WALLY_EINVAL;
    } else if (bytes_len != HASH160_LEN)
        return WALLY_EINVAL;

    bytes_out[0] = OP_DUP;
    bytes_out[1] = OP_HASH160;
    ret = wally_script_push_from_bytes(bytes, bytes_len, flags,
                                       bytes_out + 2, len - 4, written);
    if (ret == WALLY_OK) {
        bytes_out[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 2] = OP_EQUALVERIFY;
        bytes_out[WALLY_SCRIPTPUBKEY_P2PKH_LEN - 1] = OP_CHECKSIG;
        *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
    }
    return ret;
}

int wally_scriptsig_p2pkh_from_sig(const unsigned char *pub_key, size_t pub_key_len,
                                   const unsigned char *sig, size_t sig_len,
                                   uint32_t sighash,
                                   unsigned char *bytes_out, size_t len, size_t *written)
{
    unsigned char buff[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t der_len;
    int ret;

    if (written)
        *written = 0;
    if (sighash & 0xffffff00)
        return WALLY_EINVAL;

    ret = wally_ec_sig_to_der(sig, sig_len, buff, sizeof(buff), &der_len);
    if (ret == WALLY_OK) {
        buff[der_len++] = sighash & 0xff;
        ret = wally_scriptsig_p2pkh_from_der(pub_key, pub_key_len,
                                             buff, der_len,
                                             bytes_out, len, written);
        wally_clear(buff, der_len);
    }
    return ret;
}

int wally_scriptsig_p2pkh_from_der(
    const unsigned char *pub_key, size_t pub_key_len,
    const unsigned char *sig, size_t sig_len,
    unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t n;
    int ret;

    if (written)
        *written = 0;

    if (!pub_key || !is_pk_len(pub_key_len) ||
        !sig || !sig_len || sig_len > EC_SIGNATURE_DER_MAX_LEN + 1 ||
        !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_get_push_size(pub_key_len) + script_get_push_size(sig_len))
        return WALLY_EINVAL;

    ret = wally_script_push_from_bytes(sig, sig_len, 0,
                                       bytes_out, len, written);
    if (ret == WALLY_OK) {
        n = *written;
        ret = wally_script_push_from_bytes(pub_key, pub_key_len, 0,
                                           bytes_out + n, len - n, written);
        if (ret == WALLY_OK) {
            *written += n;
        } else
            wally_clear(bytes_out, n);
    }
    return ret;
}

int wally_scriptpubkey_op_return_from_bytes(
    const unsigned char *bytes, size_t bytes_len,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (bytes_len > WALLY_MAX_OP_RETURN_LEN || flags || !bytes_out || !len)
        return WALLY_EINVAL;

    ret = wally_script_push_from_bytes(bytes, bytes_len, flags,
                                       bytes_out + 1, len - 1, written);
    if (ret == WALLY_OK) {
        bytes_out[0] = OP_RETURN;
        *written += 1;
    }
    return ret;
}

int wally_scriptpubkey_p2sh_from_bytes(
    const unsigned char *bytes, size_t bytes_len,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || !script_flags_ok(flags, 0) ||
        (flags & WALLY_SCRIPT_SHA256) || !bytes_out ||
        len < WALLY_SCRIPTPUBKEY_P2SH_LEN || !written)
        return WALLY_EINVAL;

    bytes_out[0] = OP_HASH160;
    ret = wally_script_push_from_bytes(bytes, bytes_len, flags,
                                       bytes_out + 1, len - 2, written);
    if (ret == WALLY_OK) {
        bytes_out[WALLY_SCRIPTPUBKEY_P2SH_LEN - 1] = OP_EQUAL;
        *written = WALLY_SCRIPTPUBKEY_P2SH_LEN;
    }
    return ret;
}

static int pubkey_compare(const void *a, const void *b)
{
    return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

int wally_scriptpubkey_multisig_from_bytes(
    const unsigned char *bytes, size_t bytes_len, uint32_t threshold,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t n_pubkeys = bytes_len / EC_PUBLIC_KEY_LEN;
    size_t script_len = 3 + (n_pubkeys * (EC_PUBLIC_KEY_LEN + 1));
    size_t i;
    unsigned char pubkey_bytes[15 * EC_PUBLIC_KEY_LEN];

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || bytes_len % EC_PUBLIC_KEY_LEN ||
        n_pubkeys < 1 || n_pubkeys > 15 || threshold < 1 || threshold > 15 ||
        threshold > n_pubkeys || (flags & ~WALLY_SCRIPT_MULTISIG_SORTED) ||
        !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_len) {
        *written = script_len;
        return WALLY_OK;
    }

    memcpy(pubkey_bytes, bytes, bytes_len);
    if (flags & WALLY_SCRIPT_MULTISIG_SORTED) {
        qsort(pubkey_bytes, n_pubkeys, EC_PUBLIC_KEY_LEN, pubkey_compare);
    }

    *bytes_out++ = value_to_op_n(threshold);
    for (i = 0; i < n_pubkeys; ++i) {
        *bytes_out++ = EC_PUBLIC_KEY_LEN;
        memcpy(bytes_out, pubkey_bytes + i * EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
        bytes_out += EC_PUBLIC_KEY_LEN;
    }
    wally_clear(pubkey_bytes, sizeof(pubkey_bytes));
    *bytes_out++ = value_to_op_n(n_pubkeys);
    *bytes_out = OP_CHECKMULTISIG;
    *written = script_len;
    return WALLY_OK;
}

int wally_scriptsig_multisig_from_bytes(
    const unsigned char *script, size_t script_len,
    const unsigned char *bytes, size_t bytes_len,
    const uint32_t *sighash, size_t sighash_len, uint32_t flags,
    unsigned char *bytes_out, size_t len, size_t *written)
{
#define MAX_DER (EC_SIGNATURE_DER_MAX_LEN + 1)
    unsigned char der_buff[15 * MAX_DER], *p = bytes_out;
    size_t der_len[15];
    size_t i, required = 0, n_sigs = bytes_len / EC_SIGNATURE_LEN;
    int ret = WALLY_OK;

    if (written)
        *written = 0;

    if (!script || !script_len || !bytes || !bytes_len || bytes_len % EC_SIGNATURE_LEN ||
        n_sigs < 1 || n_sigs > 15 || !sighash || sighash_len != n_sigs ||
        flags || !bytes_out || !written)
        return WALLY_EINVAL;

    /* Create and store the DER encoded signatures with lengths */
    for (i = 0; i < n_sigs; ++i) {
        if (sighash[i] & ~0xff) {
            ret = WALLY_EINVAL;
            goto cleanup;
        }
        ret = wally_ec_sig_to_der(bytes + i * EC_SIGNATURE_LEN, EC_SIGNATURE_LEN,
                                  &der_buff[i * MAX_DER], MAX_DER, &der_len[i]);
        if (ret != WALLY_OK)
            goto cleanup;
        der_buff[i * MAX_DER + der_len[i]] = sighash[i] & 0xff;
        ++der_len[i];
        required += script_get_push_size(der_len[i]);
    }

    /* Account for the initial OP_0 and final script push */
    required += 1 + script_get_push_size(script_len);

    if (len < required) {
        *written = required;
        goto cleanup;
    }

    *p++ = OP_0;
    len--;
    for (i = 0; i < n_sigs; ++i) {
        ret = wally_script_push_from_bytes(&der_buff[i * MAX_DER], der_len[i],
                                           0, p, len, &der_len[i]);
        if (ret != WALLY_OK)
            goto cleanup;
        p += der_len[i];
        len -= der_len[i];
    }
    ret = wally_script_push_from_bytes(script, script_len,
                                       0, p, len, &der_len[0]);
    if (ret != WALLY_OK)
        goto cleanup;
    if (len < der_len[0])
        return WALLY_ERROR; /* Required length mismatch, should not happen! */
    *written = required;

cleanup:
    wally_clear(der_buff, sizeof(der_buff));
    return ret;
}

int wally_scriptpubkey_csv_2of2_then_1_from_bytes(
    const unsigned char *bytes, size_t bytes_len, uint32_t csv_blocks,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t csv_len = scriptint_get_length(csv_blocks);
    size_t script_len = 2 * (EC_PUBLIC_KEY_LEN + 1) + 9 + 1 + csv_len; /* 1 for push */

    if (written)
        *written = 0;

    if (!bytes || bytes_len != 2 * EC_PUBLIC_KEY_LEN ||
        csv_blocks < 17 || csv_blocks > 0xffff || flags || !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_len) {
        *written = script_len;
        return WALLY_OK;
    }

    /* The script we create is:
     *     OP_DEPTH OP_1SUB
     *     OP_IF
     *       # The stack contains the main and and recovery signatures.
     *       # Check the main signature then fall through to check the recovery.
     *       <main_pubkey> OP_CHECKSIGVERIFY
     *     OP_ELSE
     *       # The stack contains only the recovery signature.
     *       # Check the CSV time has expired then fall though as above.
     *       <csv_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
     *     OP_ENDIF
     *     # Check the recovery signature
     *     <recovery_pubkey> OP_CHECKSIG
     */
    *bytes_out++ = OP_DEPTH;
    *bytes_out++ = OP_1SUB;
    *bytes_out++ = OP_IF;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_CHECKSIGVERIFY;
    *bytes_out++ = OP_ELSE;
    *bytes_out++ = csv_len & 0xff;
    bytes_out += scriptint_to_bytes(csv_blocks, bytes_out);
    *bytes_out++ = OP_CHECKSEQUENCEVERIFY;
    *bytes_out++ = OP_DROP;
    *bytes_out++ = OP_ENDIF;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_CHECKSIG;

    *written = script_len;
    return WALLY_OK;
}

int wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt(
    const unsigned char *bytes, size_t bytes_len, uint32_t csv_blocks,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t csv_len = scriptint_get_length(csv_blocks);
    size_t script_len = 2 * (EC_PUBLIC_KEY_LEN + 1) + 6 + 1 + csv_len; /* 1 for push */

    if (written)
        *written = 0;

    if (!bytes || bytes_len != 2 * EC_PUBLIC_KEY_LEN ||
        csv_blocks < 17 || csv_blocks > 0xffff || flags || !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_len) {
        *written = script_len;
        return WALLY_OK;
    }

    /* The script we create is:
     *     <recovery_pubkey> OP_CHECKSIGVERIFY
     *     <main_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF
     *         <CSV_BLOCK> OP_CHECKSEQUENCEVERIFY
     * OP_ENDIF
     * Solved by:
     * 1) The stack containing the main and and recovery signatures.
     * 2) The stack containing an empty signature and the recovery signature.
     */
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_CHECKSIGVERIFY;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_CHECKSIG;
    *bytes_out++ = OP_IFDUP;
    *bytes_out++ = OP_NOTIF;
    *bytes_out++ = csv_len & 0xff;
    bytes_out += scriptint_to_bytes(csv_blocks, bytes_out);
    *bytes_out++ = OP_CHECKSEQUENCEVERIFY;
    *bytes_out++ = OP_ENDIF;

    *written = script_len;
    return WALLY_OK;
}

int wally_scriptpubkey_csv_2of3_then_2_from_bytes(
    const unsigned char *bytes, size_t bytes_len, uint32_t csv_blocks,
    uint32_t flags, unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t csv_len = scriptint_get_length(csv_blocks);
    size_t script_len = 3 * (EC_PUBLIC_KEY_LEN + 1) + 13 + 1 + csv_len; /* 1 for push */

    if (written)
        *written = 0;

    if (!bytes || bytes_len != 3 * EC_PUBLIC_KEY_LEN ||
        csv_blocks < 17 || csv_blocks > 0xffff || flags || !bytes_out || !written)
        return WALLY_EINVAL;

    if (len < script_len) {
        *written = script_len;
        return WALLY_OK;
    }

    /* The script we create is:
     *     OP_DEPTH OP_1SUB OP_1SUB
     *     OP_IF
     *       # The stack contains 3 items, a dummy push for the off-by-one bug
     *       # in OP_CHECKMULTISIG, and any 2 of the 3 signatures.
     *       OP_2 <main_pubkey>
     *     OP_ELSE
     *       # The stack contains a dummy push as above, and either of the
     *       # recovery signatures.
     *       <csv_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
     *       # Note OP_0 is a dummy pubkey that can't match any signature. This
     *       # allows us to share the final OP_3 OP_CHECKMULTISIGVERIFY case
     *       # thus reducing the size of the script.
     *       OP_1 OP_0
     *     OP_ENDIF
     *     # Shared code to check the signatures provided
     *     <recovery_pubkey> <recovery_pubkey_2> OP_3 OP_CHECKMULTISIG
     */
    *bytes_out++ = OP_DEPTH;
    *bytes_out++ = OP_1SUB;
    *bytes_out++ = OP_1SUB;
    *bytes_out++ = OP_IF;
    *bytes_out++ = OP_2;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_ELSE;
    *bytes_out++ = csv_len & 0xff;
    bytes_out += scriptint_to_bytes(csv_blocks, bytes_out);
    *bytes_out++ = OP_CHECKSEQUENCEVERIFY;
    *bytes_out++ = OP_DROP;
    *bytes_out++ = OP_1;
    *bytes_out++ = OP_0;
    *bytes_out++ = OP_ENDIF;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = EC_PUBLIC_KEY_LEN;
    memcpy(bytes_out, bytes + EC_PUBLIC_KEY_LEN * 2, EC_PUBLIC_KEY_LEN);
    bytes_out += EC_PUBLIC_KEY_LEN;
    *bytes_out++ = OP_3;
    *bytes_out++ = OP_CHECKMULTISIG;

    *written = script_len;
    return WALLY_OK;
}

int script_get_push_size_from_bytes(
    const unsigned char *bytes, size_t bytes_len, size_t *size_out)
{
    return get_push_size(bytes, bytes_len, false, size_out);
}

int script_get_push_opcode_size_from_bytes(
    const unsigned char *bytes, size_t bytes_len, size_t *size_out)
{
    return get_push_size(bytes, bytes_len, true, size_out);
}

int wally_script_push_from_bytes(const unsigned char *bytes, size_t bytes_len,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buff[SHA256_LEN];
    size_t opcode_len;
    int ret = WALLY_OK;

    if (written)
        *written = 0;

    if ((bytes_len && !bytes) || !script_flags_ok(flags, 0) ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (flags & WALLY_SCRIPT_HASH160) {
        ret = wally_hash160(bytes, bytes_len, buff, HASH160_LEN);
        bytes = buff;
        bytes_len = HASH160_LEN;
    } else if (flags & WALLY_SCRIPT_SHA256) {
        ret = wally_sha256(bytes, bytes_len, buff, SHA256_LEN);
        bytes = buff;
        bytes_len = SHA256_LEN;
    }
    if (ret != WALLY_OK)
        goto cleanup;

    opcode_len = calc_push_opcode_size(bytes_len);

    *written = bytes_len + opcode_len;
    if (len < *written)
        return WALLY_OK; /* Caller needs to pass a bigger buffer */

    if (bytes_len < 76)
        bytes_out[0] = bytes_len;
    else if (bytes_len < 256) {
        bytes_out[0] = OP_PUSHDATA1;
        bytes_out[1] = bytes_len;
    } else if (bytes_len < 65536) {
        leint16_t data_len = cpu_to_le16(bytes_len);
        bytes_out[0] = OP_PUSHDATA2;
        memcpy(bytes_out + 1, &data_len, sizeof(data_len));
    } else {
        leint32_t data_len = cpu_to_le32(bytes_len);
        bytes_out[0] = OP_PUSHDATA4;
        memcpy(bytes_out + 1, &data_len, sizeof(data_len));
    }
    if (bytes_len)
        memcpy(bytes_out + opcode_len, bytes, bytes_len);

cleanup:
    wally_clear(buff, sizeof(buff));
    return ret;
}

int wally_varint_get_length(uint64_t value, size_t *written)
{
    if (!written)
        return WALLY_EINVAL;
    *written = varint_get_length(value);
    return WALLY_OK;
}

int wally_varint_to_bytes(uint64_t value, unsigned char *bytes_out, size_t len, size_t *written)
{
    if (written)
        *written = 0;
    if (!bytes_out || len < varint_get_length(value) || !written)
        return WALLY_EINVAL;
    *written = varint_to_bytes(value, bytes_out);
    return WALLY_OK;
}

int wally_varbuff_get_length(const unsigned char *bytes, size_t bytes_len, size_t *written)
{
    if (written)
        *written = 0;
    if (BYTES_INVALID(bytes, bytes_len) || !written)
        return WALLY_EINVAL;
    *written = varint_get_length(bytes_len) + bytes_len;
    return WALLY_OK;
}

int wally_varbuff_to_bytes(const unsigned char *bytes, size_t bytes_len,
                           unsigned char *bytes_out, size_t len, size_t *written)
{
    if (written)
        *written = 0;
    if (BYTES_INVALID(bytes, bytes_len) || !bytes_out ||
        len < varint_get_length(bytes_len) + bytes_len || !written)
        return WALLY_EINVAL;
    *written = varbuff_to_bytes(bytes, bytes_len, bytes_out);
    return WALLY_OK;
}

int wally_witness_program_from_bytes_and_version(const unsigned char *bytes, size_t bytes_len,
                                                 uint32_t version, uint32_t flags,
                                                 unsigned char *bytes_out, size_t len,
                                                 size_t *written)
{
    /* v1+ max size: 40 data bytes, 1 byte version plus 1 byte push opcode */
    const size_t v1plus_max_size = WALLY_WITNESSSCRIPT_MAX_LEN - 2;
    int ret;
    unsigned char *p = bytes_out;

    if (written)
        *written = 0;

    if ((bytes_len && !bytes) || version > 16u ||
        !script_flags_ok(flags, WALLY_SCRIPT_AS_PUSH) ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (flags & ALL_SCRIPT_HASH_FLAGS) {
        if (!bytes_len)
            return WALLY_EINVAL;
    } else if (version == 0 && bytes_len != HASH160_LEN && bytes_len != SHA256_LEN) {
        return WALLY_EINVAL; /* Invalid length for v0 witness script */
    } else if (bytes_len < 2 || bytes_len > v1plus_max_size) {
        return WALLY_EINVAL; /* Invalid length for v1+ witness scripts */
    }
    if (flags & WALLY_SCRIPT_AS_PUSH) {
        if (len < 2)
            return WALLY_EINVAL;
        ++bytes_out;
        --len;
    }

    /* Witness version, OP_0 or OP_1 - OP_16 */
    bytes_out[0] = value_to_op_n(version);
    ret = wally_script_push_from_bytes(bytes, bytes_len,
                                       flags & ~WALLY_SCRIPT_AS_PUSH,
                                       bytes_out + 1, len - 1, written);
    if (ret == WALLY_OK) {
        *written += 1; /* For Witness version byte */
        if (flags & WALLY_SCRIPT_AS_PUSH) {
            *p = *written & 0xff;
            *written += 1; /* For Witness version byte */
        }
    }
    return ret;
}

int wally_witness_program_from_bytes(const unsigned char *bytes, size_t bytes_len,
                                     uint32_t flags,
                                     unsigned char *bytes_out, size_t len, size_t *written)
{
    return wally_witness_program_from_bytes_and_version(bytes, bytes_len, 0, flags, bytes_out, len, written);
}

int wally_elements_pegout_script_size(size_t genesis_blockhash_len,
                                      size_t mainchain_script_len,
                                      size_t sub_pubkey_len,
                                      size_t whitelistproof_len,
                                      size_t *written)
{
    *written = 1
               + script_get_push_size(genesis_blockhash_len)
               + script_get_push_size(mainchain_script_len)
               + script_get_push_size(sub_pubkey_len)
               + script_get_push_size(whitelistproof_len);
    return WALLY_OK;
}

int wally_elements_pegout_script_from_bytes(const unsigned char *genesis_blockhash,
                                            size_t genesis_blockhash_len,
                                            const unsigned char *mainchain_script,
                                            size_t mainchain_script_len,
                                            const unsigned char *sub_pubkey,
                                            size_t sub_pubkey_len,
                                            const unsigned char *whitelistproof,
                                            size_t whitelistproof_len,
                                            uint32_t flags,
                                            unsigned char *bytes_out,
                                            size_t len,
                                            size_t *written)
{
#define pegout_script_push(bytes, bytes_len) \
    if (len < bytes_written) \
        return WALLY_OK; \
    bytes_out += bytes_written; \
    len -= bytes_written; \
    if ((ret = wally_script_push_from_bytes(bytes, bytes_len, 0, bytes_out, len, &bytes_written)) != WALLY_OK) \
        return ret; \
    if (written) \
        *written += bytes_written;

    size_t bytes_written = 1; /* OP_RETURN */
    int ret;

    if (written)
        *written = 0;

    if (!genesis_blockhash || genesis_blockhash_len != SHA256_LEN ||
        !mainchain_script || !mainchain_script_len || !sub_pubkey || sub_pubkey_len != EC_PUBLIC_KEY_LEN ||
        !whitelistproof || !whitelistproof_len || flags || !bytes_out || !len)
        return WALLY_EINVAL;

    *bytes_out = OP_RETURN;
    if (written)
        *written += bytes_written;

    pegout_script_push(genesis_blockhash, genesis_blockhash_len);
    pegout_script_push(mainchain_script, mainchain_script_len);
    pegout_script_push(sub_pubkey, sub_pubkey_len);
    pegout_script_push(whitelistproof, whitelistproof_len);

    return WALLY_OK;

#undef pegout_script_push
}

int wally_elements_pegin_contract_script_from_bytes(const unsigned char *redeem_script,
                                                    size_t redeem_script_len,
                                                    const unsigned char *script,
                                                    size_t script_len,
                                                    uint32_t flags,
                                                    unsigned char *bytes_out,
                                                    size_t len,
                                                    size_t *written)
{
    unsigned char ser_pub_key[EC_PUBLIC_KEY_LEN];
    const secp256k1_context *ctx = secp_ctx();
    const unsigned char *p = redeem_script;
    unsigned char *q = bytes_out;
    size_t bytes_len = redeem_script_len;
    size_t ser_len = EC_PUBLIC_KEY_LEN;
    /* For liquidv1 initial watchman template, don't tweak emergency keys. in the future, use flags to change watchmen template */
    bool op_else_found = false;

    int ret;

    if (written)
        *written = 0;

    if (!redeem_script || !redeem_script_len || !script ||
        !script_len || flags || !bytes_out || len != redeem_script_len)
        return WALLY_EINVAL;

    for (;;) {
        size_t size_out;
        ret = script_get_push_size_from_bytes(p, bytes_len, &size_out);
        if (ret == WALLY_OK) {
            size_t offset_siz;
            size_t opcode_size;

            if ((ret = script_get_push_opcode_size_from_bytes(p, bytes_len, &opcode_size)) != WALLY_OK)
                return ret;

            offset_siz = size_out + opcode_size;
            if (bytes_len < offset_siz)
                return WALLY_EINVAL;

            if (opcode_size == 1 && size_out == EC_PUBLIC_KEY_LEN && !op_else_found) {
                unsigned char tweak[HMAC_SHA256_LEN];
                secp256k1_pubkey pub_key;
                secp256k1_pubkey pub_key_from_tweak;
                secp256k1_pubkey pub_key_tweaked;
                const secp256k1_pubkey *pub_key_combination[2];
                secp256k1_pubkey pub_key_combined;
                size_t push_size;

                if (!pubkey_parse(&pub_key, p + 1, EC_PUBLIC_KEY_LEN))
                    return WALLY_ERROR;
                memcpy(&pub_key_tweaked, &pub_key, sizeof(pub_key));
                if ((ret = wally_hmac_sha256(p + 1, EC_PUBLIC_KEY_LEN, script, script_len, tweak, HMAC_SHA256_LEN)) != WALLY_OK)
                    return ret;
                if (!pubkey_tweak_add(ctx, &pub_key_tweaked, tweak))
                    return WALLY_ERROR;
                if (!pubkey_serialize(ser_pub_key, &ser_len, &pub_key_tweaked, PUBKEY_COMPRESSED))
                    return WALLY_ERROR;
                if ((ret = wally_script_push_from_bytes(ser_pub_key, ser_len, 0, q, bytes_len, &push_size)) != WALLY_OK)
                    return ret;
                /* sanity checks as per elementsd */
                if (!pubkey_create(ctx, &pub_key_from_tweak, tweak))
                    return WALLY_ERROR;
                if (!pubkey_negate(&pub_key))
                    return WALLY_ERROR;

                pub_key_combination[0] = &pub_key;
                pub_key_combination[1] = &pub_key_tweaked;
                if (!pubkey_combine(&pub_key_combined, pub_key_combination, 2))
                    return WALLY_ERROR;
                if (memcmp(&pub_key_combined, &pub_key_from_tweak, sizeof(secp256k1_pubkey)) != 0)
                    return WALLY_ERROR;
            }
            else
                memcpy(q, p, offset_siz);
            p += offset_siz;
            q += offset_siz;
            bytes_len -= offset_siz;
        } else {
            if (*p == OP_ELSE && flags == 0) {
                op_else_found = true;
            }

            *q++ = *p++;
            --bytes_len;
        }
        if (bytes_len == 0)
            break;
    }

    if (written)
        *written = redeem_script_len;

    return WALLY_OK;
}

/* Converts a push only scriptsig to a newly allocated witness stack */
static int scriptsig_to_witness(unsigned char *bytes, size_t bytes_len, struct wally_tx_witness_stack **output)
{
    unsigned char *p = bytes, *end = p + bytes_len;
    struct wally_tx_witness_stack *result = NULL;
    int ret = WALLY_OK;

    if (!bytes || !output || !bytes_len) {
        return WALLY_EINVAL;
    }

    if ((ret = wally_tx_witness_stack_init_alloc(2, &result)) != WALLY_OK) {
        return ret;
    }

    while (p < end) {
        size_t push_size, push_opcode_size;

        if ((ret = script_get_push_size_from_bytes(p, end - p, &push_size)) != WALLY_OK) {
            goto fail;
        }
        if ((ret = script_get_push_opcode_size_from_bytes(p, end - p, &push_opcode_size)) != WALLY_OK) {
            goto fail;
        }
        p += push_opcode_size;

        if ((ret = wally_tx_witness_stack_add(result, p, push_size)) != WALLY_OK) {
            goto fail;
        }
        p += push_size;
    }

    *output = result;
    return WALLY_OK;

fail:
    wally_tx_witness_stack_free(result);
    return ret;
}

int wally_witness_p2wpkh_from_der(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *sig,
    size_t sig_len,
    struct wally_tx_witness_stack **witness)
{
    unsigned char scriptsig[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
    size_t written;
    int ret;

    ret = wally_scriptsig_p2pkh_from_der(pub_key, pub_key_len, sig, sig_len, scriptsig, sizeof(scriptsig), &written);

    if (ret == WALLY_OK)
        ret = scriptsig_to_witness(scriptsig, written, witness);

    return ret;
}

int wally_witness_p2wpkh_from_sig(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *sig,
    size_t sig_len,
    uint32_t sighash,
    struct wally_tx_witness_stack **witness)
{
    unsigned char scriptsig[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
    size_t written;
    int ret;

    ret = wally_scriptsig_p2pkh_from_sig(pub_key, pub_key_len, sig, sig_len, sighash, scriptsig, sizeof(scriptsig), &written);

    if (ret == WALLY_OK)
        ret = scriptsig_to_witness(scriptsig, written, witness);

    return ret;
}

int wally_witness_multisig_from_bytes(
    const unsigned char *script,
    size_t script_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const uint32_t *sighash,
    size_t sighash_len,
    uint32_t flags,
    struct wally_tx_witness_stack **witness)
{
    unsigned char *scriptsig = NULL;
    int ret = WALLY_OK;
    size_t scriptsig_len, n_sigs, buf_len;

    if (!script || !script_len || !bytes || !bytes_len || !sighash || !sighash_len ||
        !witness || !script_is_op_n(script[0], false, &n_sigs))
        return WALLY_EINVAL;

    buf_len = n_sigs * (EC_SIGNATURE_DER_MAX_LEN + 2) + script_len;
    if (!(scriptsig = wally_malloc(buf_len)))
        return WALLY_ENOMEM;

    ret = wally_scriptsig_multisig_from_bytes(script, script_len,
                                              bytes, bytes_len,
                                              sighash, sighash_len, flags,
                                              scriptsig, buf_len, &scriptsig_len);
    if (ret == WALLY_OK)
        ret = scriptsig_to_witness(scriptsig, scriptsig_len, witness);

    clear_and_free(scriptsig, scriptsig_len);
    return ret;
}

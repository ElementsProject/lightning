%module wallycore
%{
#include "../include/wally_core.h"
#include "../include/wally_address.h"
#include "../include/wally_anti_exfil.h"
#include "../include/wally_bip32.h"
#include "bip32_int.h"
#include "../include/wally_bip38.h"
#include "../include/wally_bip39.h"
#include "../include/wally_crypto.h"
#include "../include/wally_psbt.h"
#include "psbt_int.h"
#include "../include/wally_script.h"
#include "../include/wally_symmetric.h"
#include "../include/wally_transaction.h"
#include "transaction_int.h"
#include "../include/wally_elements.h"
#include "../internal.h"
#include <limits.h>


static int check_result(JNIEnv *jenv, int result)
{
    switch (result) {
    case WALLY_OK:
        break;
    case WALLY_EINVAL:
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, "Invalid argument");
        break;
    case WALLY_ENOMEM:
        SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "Out of memory");
        break;
    default: /* WALLY_ERROR */
        SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, "Failed");
        break;
    }
    return result;
}

static int int_cast(JNIEnv *jenv, size_t value) {
    if (value > UINT_MAX)
        SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Invalid length");
    return (int)value;
}

static uint32_t uint32_cast(JNIEnv *jenv, jlong value) {
    if (value < 0 || value > UINT_MAX)
        SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Invalid uint32_t");
    return (uint32_t)value;
}

/* Use a static class to hold our opaque pointers */
#define OBJ_CLASS "com/blockstream/libwally/Wally$Obj"

/* Create and return a java object to hold an opaque pointer */
static jobject create_obj(JNIEnv *jenv, void *p, int id) {
    jclass clazz;
    jmethodID ctor;

    if (!(clazz = (*jenv)->FindClass(jenv, OBJ_CLASS)))
        return NULL;
    if (!(ctor = (*jenv)->GetMethodID(jenv, clazz, "<init>", "(JI)V")))
        return NULL;
    return (*jenv)->NewObject(jenv, clazz, ctor, (jlong)(uintptr_t)p, id);
}

/* Fetch an opaque pointer from a java object */
static void *get_obj(JNIEnv *jenv, jobject obj, int id) {
    jclass clazz;
    jmethodID getter;
    void *ret;

    if (!obj || !(clazz = (*jenv)->GetObjectClass(jenv, obj)))
        return NULL;
    getter = (*jenv)->GetMethodID(jenv, clazz, "get_id", "()I");
    if (!getter || (*jenv)->CallIntMethod(jenv, obj, getter) != id ||
        (*jenv)->ExceptionOccurred(jenv))
        return NULL;
    getter = (*jenv)->GetMethodID(jenv, clazz, "get", "()J");
    if (!getter)
        return NULL;
    ret = (void *)(uintptr_t)((*jenv)->CallLongMethod(jenv, obj, getter));
    return (*jenv)->ExceptionOccurred(jenv) ? NULL : ret;
}

static void* get_obj_or_throw(JNIEnv *jenv, jobject obj, int id, const char *name) {
    void *ret = get_obj(jenv, obj, id);
    if (!ret)
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, name);
    return ret;
}

static unsigned char* malloc_or_throw(JNIEnv *jenv, size_t len) {
    unsigned char *p = (unsigned char *)wally_malloc(len);
    if (!p)
        SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "Out of memory");
    return p;
}

static jbyteArray create_array(JNIEnv *jenv, const unsigned char* p, size_t len) {
    jbyteArray ret = (*jenv)->NewByteArray(jenv, len);
    if (ret)
        (*jenv)->SetByteArrayRegion(jenv, ret, 0, len, (const jbyte*)p);
    return ret;
}

#define member_size(struct_, member) sizeof(((struct struct_ *)0)->member)
%}

%javaconst(1);
%ignore wally_free_string;
%ignore wally_bzero;

%pragma(java) jniclasscode=%{
    private static boolean loadLibrary() {
        try {
            System.loadLibrary("wallycore");
            return true;
        } catch (final UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            return false;
        }
    }

    private static final boolean enabled = loadLibrary();
    public static boolean isEnabled() {
        return enabled;
    }

    static final class Obj {
        private final transient long ptr;
        private final int id;
        private Obj(final long ptr, final int id) { this.ptr = ptr; this.id = id; }
        private long get() { return ptr; }
        private int get_id() { return id; }
    }
%}

/* Raise an exception whenever a function fails */
%exception {
    if (!(*jenv)->ExceptionOccurred(jenv)) {
        $action
        check_result(jenv, result);
    }
}

/* Don't use our int return value except for exception checking */
%typemap(out) int %{
%}

/* Output parameters indicating how many bytes were written/sizes are
 * converted into return values. */
%typemap(in,noblock=1,numinputs=0) size_t *written(size_t sz) {
    sz = 0; $1 = ($1_ltype)&sz;
}
%typemap(in,noblock=1,numinputs=0) size_t *output(size_t sz) {
    sz = 0; $1 = ($1_ltype)&sz;
}
%typemap(argout,noblock=1) size_t* {
    $result = int_cast(jenv, *$1);
}

/* Output strings are converted to native Java strings and returned */
%typemap(in,noblock=1,numinputs=0) char **output(char *temp = 0) {
    $1 = &temp;
}
%typemap(argout,noblock=1) (char **output) {
    $result = NULL;
    if ($1 && *$1) {
        if (!(*jenv)->ExceptionOccurred(jenv))
            $result = (*jenv)->NewStringUTF(jenv, *$1);
        wally_free_string(*$1);
    }
}

/* uint32_t input arguments are taken as longs and cast with range checking */
%typemap(in) uint32_t {
    $1 = uint32_cast(jenv, $input);
}

/* uint64_t input arguments are taken as longs and cast unchecked. This means
 * callers need to take care with treating negative values correctly */
%typemap(in) uint64_t {
    $1 = (uint64_t)($input);
}

/* Treat uint32_t/uint64_t arrays like strings of ints */
%define %java_int_array(INTTYPE, JNITYPE, JTYPE, GETFN, RELEASEFN)
%typemap(jni)     (INTTYPE *STRING, size_t LENGTH) "JNITYPE"
%typemap(jtype)   (INTTYPE *STRING, size_t LENGTH) "JTYPE[]"
%typemap(jstype)  (INTTYPE *STRING, size_t LENGTH) "JTYPE[]"
%typemap(javain)  (INTTYPE *STRING, size_t LENGTH) "$javainput"
%typemap(freearg) (INTTYPE *STRING, size_t LENGTH) ""
%typemap(in)      (INTTYPE *STRING, size_t LENGTH) {
    if (!(*jenv)->ExceptionOccurred(jenv)) {
        $1 = $input ? (INTTYPE *) JCALL2(GETFN, jenv, $input, 0) : 0;
        $2 = $input ? (size_t) JCALL1(GetArrayLength, jenv, $input) : 0;
    } else {
        $1 = 0;
        $2 = 0;
    }
}
%typemap(argout)  (INTTYPE *STRING, size_t LENGTH) {
  if ($input) JCALL3(RELEASEFN, jenv, $input, (j##JTYPE *)$1, 0);
}
%enddef

%java_int_array(uint32_t, jintArray, int, GetIntArrayElements, ReleaseIntArrayElements)
%java_int_array(uint64_t, jlongArray, long, GetLongArrayElements, ReleaseLongArrayElements)

/* BEGIN AUTOGENERATED */
%apply(char *STRING, size_t LENGTH) { (const unsigned char* abf, size_t abf_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* asset, size_t asset_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* bytes, size_t bytes_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* chain_code, size_t chain_code_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* commitment, size_t commitment_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* contract_hash, size_t contract_hash_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* entropy, size_t entropy_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* extra, size_t extra_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* final_scriptsig, size_t final_scriptsig_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* fingerprint, size_t fingerprint_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* generator, size_t generator_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* genesis_blockhash, size_t genesis_blockhash_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* hash160, size_t hash160_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* hmac_key, size_t hmac_key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* inflation_keys, size_t inflation_keys_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* issuance_amount, size_t issuance_amount_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* iv, size_t iv_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* key, size_t key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* label, size_t label_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* mainchain_script, size_t mainchain_script_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* nonce, size_t nonce_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* nonce_hash, size_t nonce_hash_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* offline_keys, size_t offline_keys_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* online_keys, size_t online_keys_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* online_priv_key, size_t online_priv_key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* output_abf, size_t output_abf_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* output_asset, size_t output_asset_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* output_generator, size_t output_generator_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* parent160, size_t parent160_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* pass, size_t pass_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* priv_key, size_t priv_key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* proof, size_t proof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* pub_key, size_t pub_key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* rangeproof, size_t rangeproof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* redeem_script, size_t redeem_script_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* s2c_data, size_t s2c_data_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* s2c_opening, size_t s2c_opening_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* salt, size_t salt_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* script, size_t script_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* scriptpubkey, size_t scriptpubkey_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* sig, size_t sig_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* sub_pubkey, size_t sub_pubkey_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* summed_key, size_t summed_key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* surjectionproof, size_t surjectionproof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* txhash, size_t txhash_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* value, size_t value_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* vbf, size_t vbf_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* whitelistproof, size_t whitelistproof_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char* witness, size_t witness_len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char* abf_out, size_t abf_out_len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char* asset_out, size_t asset_out_len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char* bytes_out, size_t len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char* s2c_opening_out, size_t s2c_opening_out_len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char* vbf_out, size_t vbf_out_len) };
/* END AUTOGENERATED */

%apply(uint32_t *STRING, size_t LENGTH) { (const uint32_t *child_path, size_t child_path_len) }
%apply(uint32_t *STRING, size_t LENGTH) { (const uint32_t *sighash, size_t sighash_len) }
%apply(uint64_t *STRING, size_t LENGTH) { (const uint64_t *values, size_t values_len) }

%typemap(in, numinputs=0) uint32_t *value_out (uint32_t val) {
   val = 0; $1 = ($1_ltype)&val;
}
%typemap(argout) uint32_t* value_out{
   $result = (jlong)*$1;
}

%typemap(in, numinputs=0) uint64_t *value_out (uint64_t val) {
   val = 0; $1 = ($1_ltype)&val;
}
%typemap(argout) uint64_t* value_out{
   $result = (jlong)*$1;
}

/* Opaque types are converted to/from an internal object holder class */
%define %java_opaque_struct(NAME, ID)
%typemap(in, numinputs=0) struct NAME **output (struct NAME * w) {
    w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) struct NAME ** {
    if (*$1)
        $result = create_obj(jenv, *$1, ID);
}
%typemap (in) const struct NAME * {
    if (strcmp("NAME", "wally_tx_witness_stack") == 0)
        $1 = (struct NAME *)get_obj(jenv, $input, ID);
    else {
        $1 = (struct NAME *)get_obj_or_throw(jenv, $input, ID, "NAME");
        if (!$1)
          return $null;
    }
}
%typemap(jtype) const struct NAME * "Object"
%typemap(jni) const struct NAME * "jobject"
%typemap (in) struct NAME * {
    $1 = (struct NAME *)get_obj_or_throw(jenv, $input, ID, "NAME");
    if (!$1)
        return $null;
}
%typemap(jtype) struct NAME * "Object"
%typemap(jni) struct NAME * "jobject"

%enddef

/* Change a functions return type to match its output type mapping */
%define %return_decls(FUNC, JTYPE, JNITYPE)
%typemap(jstype) int FUNC "JTYPE"
%typemap(jtype) int FUNC "JTYPE"
%typemap(jni) int FUNC "JNITYPE"
%rename("%(strip:[wally_])s") FUNC;
%enddef

%define %returns_void__(FUNC)
%return_decls(FUNC, void, void)
%enddef
%define %returns_size_t(FUNC)
%return_decls(FUNC, int, jint)
%enddef
%define %returns_uint64(FUNC)
%return_decls(FUNC, long, jlong)
%enddef
%define %returns_string(FUNC)
%return_decls(FUNC, String, jstring)
%enddef
%define %returns_struct(FUNC, STRUCT)
%return_decls(FUNC, Object, jobject)
%enddef
%define %returns_array_(FUNC, ARRAYARG, LENARG, LEN)
%return_decls(FUNC, byte[], jbyteArray)
%exception FUNC {
    int skip = 0;
    jresult = NULL;
    if (!jarg ## ARRAYARG) {
        arg ## LENARG = LEN;
        arg ## ARRAYARG = malloc_or_throw(jenv, LEN);
        if (!arg ## ARRAYARG)
            skip = 1; /* Exception set by malloc_or_throw */
    }
    if (!skip && !(*jenv)->ExceptionOccurred(jenv)) {
        $action
        if (check_result(jenv, result) == WALLY_OK && !jarg ## ARRAYARG)
           jresult = create_array(jenv, arg ## ARRAYARG, LEN);
    }
    if (!jarg ## ARRAYARG)
        clear_and_free(arg ## ARRAYARG, LEN);
}
%enddef
%define %returns_array_check_flag(FUNC, ARRAYARG, LENARG, FLAGSARG, FLAG, LEN_SET, LEN_UNSET)
%returns_array_(FUNC, ARRAYARG, LENARG, (FLAGSARG & FLAG) ? LEN_SET : LEN_UNSET)
%enddef

/* Our wrapped opaque types */
%java_opaque_struct(words, 1)
%java_opaque_struct(ext_key, 2)
%java_opaque_struct(wally_tx_witness_stack, 3);
%java_opaque_struct(wally_tx_input, 4);
%java_opaque_struct(wally_tx_output, 5);
%java_opaque_struct(wally_tx, 6);
%java_opaque_struct(wally_map, 7);
%java_opaque_struct(wally_psbt, 8);

/* Our wrapped functions return types */
%returns_void__(bip32_key_free);
%returns_struct(bip32_key_from_base58_alloc, ext_key);
%rename("bip32_key_from_base58") bip32_key_from_base58_alloc;
%returns_struct(bip32_key_from_base58_n_alloc, ext_key);
%rename("bip32_key_from_base58_n") bip32_key_from_base58_n_alloc;
%returns_struct(bip32_key_from_parent_alloc, ext_key);
%rename("bip32_key_from_parent") bip32_key_from_parent_alloc;
%returns_struct(bip32_key_from_parent_path_alloc, ext_key);
%rename("bip32_key_from_parent_path") bip32_key_from_parent_path_alloc;
%returns_struct(bip32_key_from_parent_path_str_alloc, ext_key);
%rename("bip32_key_from_parent_path_str") bip32_key_from_parent_path_str_alloc;
%returns_struct(bip32_key_from_parent_path_str_n_alloc, ext_key);
%rename("bip32_key_from_parent_path_str_n") bip32_key_from_parent_path_str_n_alloc;
%returns_struct(bip32_key_from_seed_alloc, ext_key);
%rename("bip32_key_from_seed") bip32_key_from_seed_alloc;
%returns_struct(bip32_key_from_seed_custom_alloc, ext_key);
%rename("bip32_key_from_seed_custom") bip32_key_from_seed_custom_alloc;
%returns_array_(bip32_key_get_chain_code, 2, 3, member_size(ext_key, chain_code));
%returns_size_t(bip32_key_get_child_num);
%returns_size_t(bip32_key_get_depth);
%returns_array_(bip32_key_get_fingerprint, 2, 3, BIP32_KEY_FINGERPRINT_LEN);
%returns_array_(bip32_key_get_hash160, 2, 3, member_size(ext_key, hash160));
%returns_array_(bip32_key_get_parent160, 2, 3, member_size(ext_key, parent160));
%returns_array_(bip32_key_get_priv_key, 2, 3, member_size(ext_key, priv_key) - 1);
%returns_array_(bip32_key_get_pub_key, 2, 3, member_size(ext_key, pub_key));
%returns_array_(bip32_key_get_pub_key_tweak_sum, 2, 3, member_size(ext_key, pub_key_tweak_sum));
%returns_size_t(bip32_key_get_version);
%returns_struct(bip32_key_init_alloc, ext_key);
%rename("bip32_key_init") bip32_key_init_alloc;
%returns_array_(bip32_key_serialize, 3, 4, BIP32_SERIALIZED_LEN);
%returns_void__(bip32_key_strip_private_key);
%returns_string(bip32_key_to_base58);
%returns_struct(bip32_key_unserialize_alloc, ext_key);
%rename("bip32_key_unserialize") bip32_key_unserialize_alloc;
%returns_struct(bip32_key_with_tweak_from_parent_path_alloc, ext_key);
%rename("bip32_key_with_tweak_from_parent_path") bip32_key_with_tweak_from_parent_path_alloc;
%returns_array_(bip38_raw_from_private_key, 6, 7, BIP38_SERIALIZED_LEN);
%returns_string(bip38_from_private_key);
%returns_array_(bip38_raw_to_private_key, 6, 7, 32);
%returns_array_(bip38_to_private_key, 5, 6, 32);
%returns_size_t(bip38_raw_get_flags);
%returns_size_t(bip38_get_flags);
%returns_string(bip39_get_languages);
%returns_struct(bip39_get_wordlist, words);
%returns_string(bip39_get_word);
%returns_string(bip39_mnemonic_from_bytes);
%returns_size_t(bip39_mnemonic_to_bytes);
%returns_void__(bip39_mnemonic_validate);
%returns_size_t(bip39_mnemonic_to_seed);
%returns_string(wally_addr_segwit_from_bytes);
%returns_size_t(wally_addr_segwit_get_version);
%returns_size_t(wally_addr_segwit_n_get_version);
%returns_size_t(wally_addr_segwit_n_to_bytes);
%returns_size_t(wally_addr_segwit_to_bytes);
%returns_size_t(wally_address_to_scriptpubkey);
%returns_array_(wally_aes, 6, 7, AES_BLOCK_LEN);
%returns_size_t(wally_aes_cbc);
%returns_array_(wally_asset_final_vbf, 8, 9, ASSET_TAG_LEN);
%returns_array_(wally_asset_generator_from_bytes, 5, 6, ASSET_GENERATOR_LEN);
%returns_size_t(wally_asset_rangeproof_with_nonce);
%returns_size_t(wally_asset_rangeproof);
%returns_size_t(wally_asset_surjectionproof_size);
%returns_size_t(wally_asset_surjectionproof);
%returns_uint64(wally_asset_unblind_with_nonce);
%returns_uint64(wally_asset_unblind);
%returns_array_(wally_asset_blinding_key_from_seed, 3, 4, HMAC_SHA512_LEN);
%returns_array_(wally_asset_blinding_key_to_ec_private_key, 5, 6, EC_PRIVATE_KEY_LEN);
%returns_array_(wally_asset_value_commitment, 6, 7, ASSET_COMMITMENT_LEN);
%returns_string(wally_base58_from_bytes);
%returns_size_t(wally_base58_to_bytes);
%returns_size_t(wally_base58_get_length);
%returns_size_t(wally_base58_n_get_length);
%returns_size_t(wally_base58_n_to_bytes);
%returns_string(wally_base64_from_bytes);
%returns_size_t(wally_base64_to_bytes);
%returns_size_t(wally_base64_get_maximum_length);
%returns_string(wally_bip32_key_to_address);
%returns_string(wally_bip32_key_to_addr_segwit);
%returns_string(wally_confidential_addr_to_addr);
%returns_array_(wally_confidential_addr_to_ec_public_key, 3, 4, EC_PUBLIC_KEY_LEN);
%returns_string(wally_confidential_addr_from_addr);
%returns_string(wally_confidential_addr_to_addr_segwit);
%returns_array_(wally_confidential_addr_segwit_to_ec_public_key, 3, 4, EC_PUBLIC_KEY_LEN);
%returns_string(wally_confidential_addr_from_addr_segwit);
%returns_void__(wally_ec_private_key_verify);
%returns_void__(wally_ec_public_key_verify);
%returns_array_(wally_ec_public_key_decompress, 3, 4, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
%returns_array_(wally_ec_public_key_negate, 3, 4, EC_PUBLIC_KEY_LEN);
%returns_array_(wally_ec_public_key_from_private_key, 3, 4, EC_PUBLIC_KEY_LEN);
%returns_array_check_flag(wally_ec_sig_from_bytes, 6, 7, jarg5, 8, EC_SIGNATURE_RECOVERABLE_LEN, EC_SIGNATURE_LEN);
%returns_array_(wally_ec_sig_normalize, 3, 4, EC_SIGNATURE_LEN);
%returns_array_(wally_ec_sig_from_der, 3, 4, EC_SIGNATURE_LEN);
%returns_size_t(wally_ec_sig_to_der);
%returns_array_(wally_ec_sig_to_public_key, 5, 6, EC_PUBLIC_KEY_LEN);
%returns_void__(wally_ec_sig_verify);
%returns_array_(wally_ecdh, 5, 6, SHA256_LEN);
%returns_size_t(wally_format_bitcoin_message);
%returns_array_(wally_hash160, 3, 4, HASH160_LEN);
%returns_string(wally_hex_from_bytes);
%returns_size_t(wally_hex_n_to_bytes);
%returns_void__(wally_hex_n_verify);
%returns_size_t(wally_hex_to_bytes);
%returns_void__(wally_hex_verify);
%returns_array_(wally_hmac_sha256, 5, 6, HMAC_SHA256_LEN);
%returns_array_(wally_hmac_sha512, 5, 6, HMAC_SHA512_LEN);
%returns_void__(wally_init);
%rename("_is_elements_build") wally_is_elements_build;
%returns_size_t(_is_elements_build);
%returns_void__(wally_map_add);
%returns_void__(wally_map_add_keypath_item);
%returns_size_t(wally_map_find);
%returns_void__(wally_map_free)
%returns_struct(wally_map_init_alloc, wally_map);
%rename("map_init") wally_map_init_alloc;
%returns_void__(wally_map_sort);
%returns_array_(wally_pbkdf2_hmac_sha256, 7, 8, PBKDF2_HMAC_SHA256_LEN);
%returns_array_(wally_pbkdf2_hmac_sha512, 7, 8, PBKDF2_HMAC_SHA512_LEN);
%returns_void__(wally_psbt_add_input_at);
%returns_void__(wally_psbt_add_output_at);
%returns_void__(wally_psbt_clear_input_value);
%returns_struct(wally_psbt_clone_alloc, wally_psbt);
%rename("psbt_clone") wally_psbt_clone_alloc;
%returns_void__(wally_psbt_combine);
%returns_struct(wally_psbt_elements_init_alloc, wally_psbt);
%rename("psbt_elements_init") wally_psbt_elements_init_alloc;
%returns_struct(wally_psbt_extract, wally_tx);
%returns_void__(wally_psbt_finalize);
%returns_size_t(wally_psbt_find_input_keypath);
%returns_size_t(wally_psbt_find_input_signature);
%returns_size_t(wally_psbt_find_input_unknown);
%returns_size_t(wally_psbt_find_output_keypath);
%returns_size_t(wally_psbt_find_output_unknown);
%returns_void__(wally_psbt_free)
%returns_struct(wally_psbt_from_base64, wally_psbt);
%returns_struct(wally_psbt_from_bytes, wally_psbt);
%returns_struct(wally_psbt_get_global_tx_alloc, wally_tx);
%rename("psbt_get_global_tx") wally_psbt_get_global_tx_alloc;
%returns_size_t(wally_psbt_get_input_abf);
%returns_size_t(wally_psbt_get_input_abf_len);
%returns_size_t(wally_psbt_get_input_asset);
%returns_size_t(wally_psbt_get_input_asset_len);
%returns_size_t(wally_psbt_get_input_redeem_script);
%returns_size_t(wally_psbt_get_input_redeem_script_len);
%returns_size_t(wally_psbt_get_input_claim_script);
%returns_size_t(wally_psbt_get_input_claim_script_len);
%returns_size_t(wally_psbt_get_input_final_scriptsig);
%returns_size_t(wally_psbt_get_input_final_scriptsig_len);
%returns_struct(wally_psbt_get_input_final_witness_alloc, wally_tx_witness_stack);
%rename("psbt_get_input_final_witness") wally_psbt_get_input_final_witness_alloc;
%returns_size_t(wally_psbt_get_input_genesis_blockhash);
%returns_size_t(wally_psbt_get_input_genesis_blockhash_len);
%returns_size_t(wally_psbt_get_input_keypaths_size);
%returns_size_t(wally_psbt_get_input_keypath);
%returns_size_t(wally_psbt_get_input_keypath_len);
%returns_struct(wally_psbt_get_input_pegin_tx_alloc, wally_tx);
%returns_size_t(wally_psbt_get_input_signatures_size);
%returns_size_t(wally_psbt_get_input_signature);
%returns_size_t(wally_psbt_get_input_signature_len);
%returns_size_t(wally_psbt_get_input_sighash);
%rename("psbt_get_input_pegin_tx") wally_psbt_get_input_pegin_tx_alloc;
%returns_size_t(wally_psbt_get_input_txoutproof);
%returns_size_t(wally_psbt_get_input_txoutproof_len);
%returns_size_t(wally_psbt_get_input_unknown);
%returns_size_t(wally_psbt_get_input_unknown_len);
%returns_size_t(wally_psbt_get_input_unknowns_size);
%returns_struct(wally_psbt_get_input_utxo_alloc, wally_tx);
%rename("psbt_get_input_utxo") wally_psbt_get_input_utxo_alloc;
%returns_uint64(wally_psbt_get_input_value);
%returns_size_t(wally_psbt_get_input_vbf);
%returns_size_t(wally_psbt_get_input_vbf_len);
%returns_size_t(wally_psbt_get_input_witness_script);
%returns_size_t(wally_psbt_get_input_witness_script_len);
%returns_struct(wally_psbt_get_input_witness_utxo_alloc, wally_tx_output);
%rename("psbt_get_input_witness_utxo") wally_psbt_get_input_witness_utxo_alloc;
%returns_size_t(wally_psbt_get_length);
%returns_size_t(wally_psbt_get_num_inputs);
%returns_size_t(wally_psbt_get_num_outputs);
%returns_size_t(wally_psbt_get_output_abf);
%returns_size_t(wally_psbt_get_output_abf_len);
%returns_size_t(wally_psbt_get_output_asset_commitment);
%returns_size_t(wally_psbt_get_output_asset_commitment_len);
%returns_size_t(wally_psbt_get_output_blinding_pubkey);
%returns_size_t(wally_psbt_get_output_blinding_pubkey_len);
%returns_size_t(wally_psbt_get_output_keypaths_size);
%returns_size_t(wally_psbt_get_output_keypath);
%returns_size_t(wally_psbt_get_output_keypath_len);
%returns_size_t(wally_psbt_get_output_nonce);
%returns_size_t(wally_psbt_get_output_nonce_len);
%returns_size_t(wally_psbt_get_output_rangeproof);
%returns_size_t(wally_psbt_get_output_rangeproof_len);
%returns_size_t(wally_psbt_get_output_redeem_script);
%returns_size_t(wally_psbt_get_output_redeem_script_len);
%returns_size_t(wally_psbt_get_output_surjectionproof);
%returns_size_t(wally_psbt_get_output_surjectionproof_len);
%returns_size_t(wally_psbt_get_output_unknown);
%returns_size_t(wally_psbt_get_output_unknown_len);
%returns_size_t(wally_psbt_get_output_unknowns_size);
%returns_size_t(wally_psbt_get_output_value_commitment);
%returns_size_t(wally_psbt_get_output_value_commitment_len);
%returns_size_t(wally_psbt_get_output_vbf);
%returns_size_t(wally_psbt_get_output_vbf_len);
%returns_size_t(wally_psbt_get_output_witness_script);
%returns_size_t(wally_psbt_get_output_witness_script_len);
%returns_size_t(wally_psbt_get_version);
%returns_size_t(wally_psbt_has_input_value);
%returns_struct(wally_psbt_init_alloc, wally_psbt);
%rename("psbt_init") wally_psbt_init_alloc;
%returns_size_t(wally_psbt_is_elements);
%returns_size_t(wally_psbt_is_finalized);
%returns_void__(wally_psbt_remove_input);
%returns_void__(wally_psbt_remove_output);
%returns_void__(wally_psbt_set_global_tx);
%returns_void__(wally_psbt_set_input_abf);
%returns_void__(wally_psbt_set_input_asset);
%returns_void__(wally_psbt_set_input_claim_script);
%returns_void__(wally_psbt_set_input_final_scriptsig);
%returns_void__(wally_psbt_set_input_final_witness);
%returns_void__(wally_psbt_set_input_genesis_blockhash);
%returns_void__(wally_psbt_set_input_keypaths);
%returns_void__(wally_psbt_set_input_pegin_tx);
%returns_void__(wally_psbt_set_input_redeem_script);
%returns_void__(wally_psbt_set_input_sighash);
%returns_void__(wally_psbt_set_input_signatures);
%returns_void__(wally_psbt_set_input_txoutproof);
%returns_void__(wally_psbt_set_input_unknowns);
%returns_void__(wally_psbt_set_input_utxo);
%returns_void__(wally_psbt_set_input_value);
%returns_void__(wally_psbt_set_input_vbf);
%returns_void__(wally_psbt_set_input_witness_script);
%returns_void__(wally_psbt_set_input_witness_utxo);
%returns_void__(wally_psbt_set_output_abf);
%returns_void__(wally_psbt_set_output_asset_commitment);
%returns_void__(wally_psbt_set_output_blinding_pubkey);
%returns_void__(wally_psbt_set_output_keypaths);
%returns_void__(wally_psbt_set_output_nonce);
%returns_void__(wally_psbt_set_output_rangeproof);
%returns_void__(wally_psbt_set_output_redeem_script);
%returns_void__(wally_psbt_set_output_surjectionproof);
%returns_void__(wally_psbt_set_output_unknowns);
%returns_void__(wally_psbt_set_output_value_commitment);
%returns_void__(wally_psbt_set_output_vbf);
%returns_void__(wally_psbt_set_output_witness_script);
%returns_void__(wally_psbt_sign);
%returns_string(wally_psbt_to_base64);
%returns_size_t(wally_psbt_to_bytes);
%returns_array_(wally_ripemd160, 3, 4, RIPEMD160_LEN);
%returns_size_t(wally_script_push_from_bytes);
%returns_size_t(wally_scriptpubkey_csv_2of2_then_1_from_bytes);
%returns_size_t(wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt);
%returns_size_t(wally_scriptpubkey_csv_2of3_then_2_from_bytes);
%returns_size_t(wally_scriptpubkey_get_type);
%returns_size_t(wally_scriptpubkey_op_return_from_bytes);
%returns_size_t(wally_scriptpubkey_p2pkh_from_bytes);
%returns_size_t(wally_scriptpubkey_p2sh_from_bytes);
%returns_size_t(wally_scriptpubkey_multisig_from_bytes);
%returns_size_t(wally_scriptsig_p2pkh_from_sig);
%returns_size_t(wally_scriptsig_p2pkh_from_der);
%returns_size_t(wally_scriptsig_multisig_from_bytes);
%returns_struct(wally_witness_p2wpkh_from_sig, wally_tx_witness_stack);
%returns_struct(wally_witness_p2wpkh_from_der, wally_tx_witness_stack);
%returns_struct(wally_witness_multisig_from_bytes, wally_tx_witness_stack);
%returns_size_t(wally_elements_pegout_script_size);
%returns_size_t(wally_elements_pegout_script_from_bytes);
%returns_size_t(wally_elements_pegin_contract_script_from_bytes);
%returns_void__(wally_scrypt);
%returns_void__(wally_secp_randomize);
%returns_array_(wally_sha256, 3, 4, SHA256_LEN);
%returns_array_(wally_sha256d, 3, 4, SHA256_LEN);
%returns_array_(wally_sha256_midstate, 3, 4, SHA256_LEN);
%returns_array_(wally_sha512, 3, 4, SHA512_LEN);
%returns_void__(wally_tx_add_elements_raw_input);
%returns_void__(wally_tx_add_elements_raw_input_at);
%returns_void__(wally_tx_add_elements_raw_output);
%returns_void__(wally_tx_add_elements_raw_output_at);
%returns_void__(wally_tx_add_input);
%returns_void__(wally_tx_add_input_at);
%returns_void__(wally_tx_add_raw_input);
%returns_void__(wally_tx_add_raw_input_at);
%returns_void__(wally_tx_add_output);
%returns_void__(wally_tx_add_output_at);
%returns_void__(wally_tx_add_raw_output);
%returns_void__(wally_tx_add_raw_output_at);
%returns_array_(wally_tx_confidential_value_from_satoshi, 2, 3, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
%returns_uint64(wally_tx_confidential_value_to_satoshi);
%returns_struct(wally_tx_elements_input_init_alloc, wally_tx_input);
%rename("tx_elements_input_init") wally_tx_elements_input_init_alloc;
%rename("_tx_elements_input_is_pegin") wally_tx_elements_input_is_pegin;
%returns_size_t(_tx_elements_input_is_pegin);
%returns_void__(wally_tx_elements_input_issuance_set);
%returns_void__(wally_tx_elements_input_issuance_free);
%returns_array_(wally_tx_elements_issuance_calculate_asset, 3, 4, SHA256_LEN);
%returns_array_(wally_tx_elements_issuance_calculate_reissuance_token, 4, 5, SHA256_LEN);
%returns_array_(wally_tx_elements_issuance_generate_entropy, 6, 7, SHA256_LEN);
%returns_struct(wally_tx_elements_output_init_alloc, wally_tx_output);
%rename("tx_elements_output_init") wally_tx_elements_output_init_alloc;
%returns_void__(wally_tx_free);
%returns_struct(wally_tx_from_bytes, wally_tx);
%returns_struct(wally_tx_from_hex, wally_tx);
%returns_array_(wally_tx_get_btc_signature_hash, 8, 9, SHA256_LEN);
%returns_array_(wally_tx_get_elements_signature_hash, 9, 10, SHA256_LEN);
%returns_array_(wally_tx_get_input_blinding_nonce, 3, 4, SHA256_LEN);
%returns_array_(wally_tx_get_input_entropy, 3, 4, SHA256_LEN);
%rename("_tx_get_input_issuance_amount") wally_tx_get_input_issuance_amount;
%returns_size_t(_tx_get_input_issuance_amount);
%returns_size_t(wally_tx_get_input_issuance_amount_len);
%rename("_tx_get_input_issuance_amount_rangeproof") wally_tx_get_input_issuance_amount_rangeproof;
%returns_size_t(_tx_get_input_issuance_amount_rangeproof);
%returns_size_t(wally_tx_get_input_issuance_amount_rangeproof_len);
%returns_size_t(wally_tx_get_input_index);
%rename("_tx_get_input_inflation_keys") wally_tx_get_input_inflation_keys;
%returns_size_t(_tx_get_input_inflation_keys);
%returns_size_t(wally_tx_get_input_inflation_keys_len);
%rename("_tx_get_input_inflation_keys_rangeproof") wally_tx_get_input_inflation_keys_rangeproof;
%returns_size_t(_tx_get_input_inflation_keys_rangeproof);
%returns_size_t(wally_tx_get_input_inflation_keys_rangeproof_len);
%rename("_tx_get_input_script") wally_tx_get_input_script;
%returns_size_t(_tx_get_input_script);
%returns_size_t(wally_tx_get_input_script_len);
%rename("_tx_get_input_sequence") wally_tx_get_input_sequence;
%returns_size_t(_tx_get_input_sequence);
%returns_array_(wally_tx_get_input_txhash, 3, 4, SHA256_LEN);
%rename("_tx_get_input_witness") wally_tx_get_input_witness;
%returns_size_t(_tx_get_input_witness);
%returns_size_t(wally_tx_get_input_witness_len);
%returns_size_t(wally_tx_get_length);
%returns_size_t(wally_tx_get_locktime);
%returns_size_t(wally_tx_get_num_inputs);
%returns_size_t(wally_tx_get_num_outputs);
%returns_array_(wally_tx_get_output_asset, 3, 4, WALLY_TX_ASSET_CT_ASSET_LEN);
%returns_array_(wally_tx_get_output_nonce, 3, 4, WALLY_TX_ASSET_CT_NONCE_LEN);
%rename("_tx_get_output_rangeproof") wally_tx_get_output_rangeproof;
%returns_size_t(_tx_get_output_rangeproof);
%returns_size_t(wally_tx_get_output_rangeproof_len);
%returns_uint64(wally_tx_get_output_satoshi);
%rename("_tx_get_output_script") wally_tx_get_output_script;
%returns_size_t(_tx_get_output_script);
%returns_size_t(wally_tx_get_output_script_len);
%rename("_tx_get_output_surjectionproof") wally_tx_get_output_surjectionproof;
%returns_size_t(_tx_get_output_surjectionproof);
%returns_size_t(wally_tx_get_output_surjectionproof_len);
%rename("_tx_get_output_value") wally_tx_get_output_value;
%returns_size_t(_tx_get_output_value);
%returns_size_t(wally_tx_get_output_value_len);
%returns_array_(wally_tx_get_signature_hash, 12, 13, SHA256_LEN);
%returns_uint64(wally_tx_get_total_output_satoshi);
%returns_array_(wally_tx_get_txid, 2, 3, WALLY_TXHASH_LEN);
%returns_size_t(wally_tx_get_version);
%returns_size_t(wally_tx_get_vsize);
%returns_size_t(wally_tx_get_weight);
%returns_size_t(wally_tx_get_witness_count);
%returns_struct(wally_tx_init_alloc, wally_tx);
%rename("tx_init") wally_tx_init_alloc;
%returns_struct(wally_tx_clone_alloc, wally_tx);
%rename("tx_clone") wally_tx_clone_alloc;
%returns_void__(wally_tx_input_free);
%returns_array_(wally_tx_input_get_blinding_nonce, 2, 3, SHA256_LEN);
%returns_array_(wally_tx_input_get_entropy, 2, 3, SHA256_LEN);
%rename("_tx_input_get_issuance_amount") wally_tx_input_get_issuance_amount;
%returns_size_t(_tx_input_get_issuance_amount);
%returns_size_t(wally_tx_input_get_issuance_amount_len);
%returns_size_t(wally_tx_input_get_index);
%rename("_tx_input_get_inflation_keys") wally_tx_input_get_inflation_keys;
%returns_size_t(_tx_input_get_inflation_keys);
%returns_size_t(wally_tx_input_get_inflation_keys_len);
%rename("_tx_input_get_issuance_amount_rangeproof") wally_tx_input_get_issuance_amount_rangeproof;
%returns_size_t(_tx_input_get_issuance_amount_rangeproof);
%returns_size_t(wally_tx_input_get_issuance_amount_rangeproof_len);
%rename("_tx_input_get_inflation_keys_rangeproof") wally_tx_input_get_inflation_keys_rangeproof;
%returns_size_t(_tx_input_get_inflation_keys_rangeproof);
%returns_size_t(wally_tx_input_get_inflation_keys_rangeproof_len);
%rename("_tx_input_get_script") wally_tx_input_get_script;
%returns_size_t(_tx_input_get_script);
%returns_size_t(wally_tx_input_get_script_len);
%rename("_tx_input_get_sequence") wally_tx_input_get_sequence;
%returns_size_t(_tx_input_get_sequence);
%returns_array_(wally_tx_input_get_txhash, 2, 3, WALLY_TXHASH_LEN);
%rename("_tx_input_get_witness") wally_tx_input_get_witness;
%returns_size_t(_tx_input_get_witness);
%returns_size_t(wally_tx_input_get_witness_len);
%returns_struct(wally_tx_input_init_alloc, wally_tx_input);
%rename("tx_input_init") wally_tx_input_init_alloc;
%returns_void__(wally_tx_input_set_index);
%returns_void__(wally_tx_input_set_sequence);
%returns_void__(wally_tx_input_set_script);
%returns_void__(wally_tx_input_set_txhash);
%returns_void__(wally_tx_input_set_witness);
%returns_void__(wally_tx_input_set_blinding_nonce);
%returns_void__(wally_tx_input_set_entropy);
%returns_void__(wally_tx_input_set_inflation_keys);
%returns_void__(wally_tx_input_set_inflation_keys_rangeproof);
%returns_void__(wally_tx_input_set_issuance_amount);
%returns_void__(wally_tx_input_set_issuance_amount_rangeproof);
%rename("_tx_is_coinbase") wally_tx_is_coinbase;
%returns_size_t(_tx_is_coinbase);
%rename("_tx_is_elements") wally_tx_is_elements;
%returns_size_t(_tx_is_elements);
%returns_void__(wally_tx_elements_output_commitment_set);
%returns_void__(wally_tx_elements_output_commitment_free);
%returns_void__(wally_tx_output_free);
%rename("_tx_output_get_asset") wally_tx_output_get_asset;
%returns_size_t(_tx_output_get_asset);
%returns_size_t(wally_tx_output_get_asset_len);
%rename("_tx_output_get_nonce") wally_tx_output_get_nonce;
%returns_size_t(_tx_output_get_nonce);
%returns_size_t(wally_tx_output_get_nonce_len);
%rename("_tx_output_get_rangeproof") wally_tx_output_get_rangeproof;
%returns_size_t(_tx_output_get_rangeproof);
%returns_size_t(wally_tx_output_get_rangeproof_len);
%returns_uint64(wally_tx_output_get_satoshi);
%rename("_tx_output_get_script") wally_tx_output_get_script;
%returns_size_t(_tx_output_get_script);
%returns_size_t(wally_tx_output_get_script_len);
%rename("_tx_output_get_surjectionproof") wally_tx_output_get_surjectionproof;
%returns_size_t(_tx_output_get_surjectionproof);
%returns_size_t(wally_tx_output_get_surjectionproof_len);
%rename("_tx_output_get_value") wally_tx_output_get_value;
%returns_size_t(_tx_output_get_value);
%returns_size_t(wally_tx_output_get_value_len);
%returns_struct(wally_tx_output_init_alloc, wally_tx_output);
%rename("tx_output_init") wally_tx_output_init_alloc;
%returns_struct(wally_tx_output_clone_alloc, wally_tx_output_clone);
%rename("tx_output_clone") wally_tx_output_clone_alloc;
%returns_void__(wally_tx_output_set_satoshi);
%returns_void__(wally_tx_output_set_script);
%returns_void__(wally_tx_output_set_asset);
%returns_void__(wally_tx_output_set_value);
%returns_void__(wally_tx_output_set_nonce);
%returns_void__(wally_tx_output_set_surjectionproof);
%returns_void__(wally_tx_output_set_rangeproof);
%returns_void__(wally_tx_remove_input);
%returns_void__(wally_tx_remove_output);
%returns_void__(wally_tx_set_input_index);
%returns_void__(wally_tx_set_input_sequence);
%returns_void__(wally_tx_set_input_script);
%returns_void__(wally_tx_set_input_txhash);
%returns_void__(wally_tx_set_input_witness);
%returns_void__(wally_tx_set_input_blinding_nonce);
%returns_void__(wally_tx_set_input_entropy);
%returns_void__(wally_tx_set_input_inflation_keys);
%returns_void__(wally_tx_set_input_inflation_keys_rangeproof);
%returns_void__(wally_tx_set_input_issuance_amount);
%returns_void__(wally_tx_set_input_issuance_amount_rangeproof);
%returns_void__(wally_tx_set_output_satoshi);
%returns_void__(wally_tx_set_output_script);
%returns_void__(wally_tx_set_output_value);
%returns_void__(wally_tx_set_output_asset);
%returns_void__(wally_tx_set_output_nonce);
%returns_void__(wally_tx_set_output_surjectionproof);
%returns_void__(wally_tx_set_output_rangeproof);
%returns_size_t(wally_tx_to_bytes);
%returns_string(wally_tx_to_hex);
%returns_size_t(wally_tx_vsize_from_weight);
%returns_void__(wally_tx_witness_stack_add);
%returns_void__(wally_tx_witness_stack_add_dummy);
%returns_void__(wally_tx_witness_stack_free);
%returns_struct(wally_tx_witness_stack_init_alloc, wally_tx_witness_stack);
%rename("tx_witness_stack_init") wally_tx_witness_stack_init_alloc;
%returns_struct(wally_tx_witness_stack_clone_alloc, wally_tx_witness_stack);
%rename("tx_witness_stack_clone") wally_tx_witness_stack_clone_alloc;
%returns_void__(wally_tx_witness_stack_set);
%returns_void__(wally_tx_witness_stack_set_dummy);
%returns_size_t(wally_varbuff_get_length);
%returns_size_t(wally_varbuff_to_bytes);
%returns_size_t(wally_varint_get_length);
%returns_size_t(wally_varint_to_bytes);
%returns_string(wally_wif_from_bytes);
%returns_size_t(wally_wif_to_bytes);
%rename("_wif_is_uncompressed") wally_wif_is_uncompressed;
%returns_size_t(_wif_is_uncompressed);
%returns_size_t(wally_wif_to_public_key);
%returns_string(wally_wif_to_address);
%returns_string(wally_scriptpubkey_to_address);
%returns_size_t(wally_witness_program_from_bytes);
%returns_size_t(wally_witness_program_from_bytes_and_version);
%returns_array_(wally_symmetric_key_from_seed, 3, 4, HMAC_SHA512_LEN);
%returns_array_(wally_symmetric_key_from_parent, 6, 7, HMAC_SHA512_LEN);
%returns_size_t(wally_asset_pak_whitelistproof_size);
%returns_size_t(wally_asset_pak_whitelistproof);
%returns_array_(wally_s2c_sig_from_bytes, 10, 11, EC_SIGNATURE_LEN);
%returns_void__(wally_s2c_commitment_verify);
%returns_array_(wally_ae_host_commit_from_bytes, 4, 5, WALLY_HOST_COMMITMENT_LEN);
%returns_array_(wally_ae_signer_commit_from_bytes, 8, 9, WALLY_S2C_OPENING_LEN);
%returns_array_(wally_ae_sig_from_bytes, 8, 9, EC_SIGNATURE_LEN);
%returns_void__(wally_ae_verify);

%rename("_cleanup") wally_cleanup;
%returns_void__(_cleanup)

%include "../include/wally_core.h"
%include "../include/wally_address.h"
%include "../include/wally_anti_exfil.h"
%include "../include/wally_bip32.h"
%include "bip32_int.h"
%include "../include/wally_bip38.h"
%include "../include/wally_bip39.h"
%include "../include/wally_crypto.h"
%include "../include/wally_psbt.h"
%include "psbt_int.h"
%include "../include/wally_script.h"
%include "../include/wally_symmetric.h"
%include "../include/wally_transaction.h"
%include "transaction_int.h"
%include "../include/wally_elements.h"

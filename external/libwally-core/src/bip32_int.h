#ifndef LIBWALLY_CORE_BIP32_INT_H
#define LIBWALLY_CORE_BIP32_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#ifdef __cplusplus
extern "C" {
#endif

WALLY_CORE_API int bip32_key_get_chain_code(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_parent160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_priv_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_hash160(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int bip32_key_get_pub_key(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
#ifdef BUILD_ELEMENTS
WALLY_CORE_API int bip32_key_get_pub_key_tweak_sum(const struct ext_key *hdkey, unsigned char *bytes_out, size_t len);
#endif /* BUILD_ELEMENTS */

WALLY_CORE_API int bip32_key_get_depth(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_child_num(const struct ext_key *hdkey, size_t *written);
WALLY_CORE_API int bip32_key_get_version(const struct ext_key *hdkey, size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* SWIG_JAVA_BUILD/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD */

#endif /* LIBWALLY_CORE_BIP32_INT_H */

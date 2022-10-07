#ifndef LIBWALLY_HMAC_H
#define LIBWALLY_HMAC_H

struct sha256;
struct sha512;

/**
 * hmac_sha256 - Compute an HMAC using SHA-256
 *
 * @sha: Destination for the resulting HMAC.
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @msg: The message to hash
 * @msg_len: The length of @msg in bytes.
 */
void hmac_sha256_impl(struct sha256 *sha,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *msg, size_t msg_len);

/**
 * hmac_sha512 - Compute an HMAC using SHA-512
 *
 * @sha: Destination for the resulting HMAC.
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @msg: The message to hash
 * @msg_len: The length of @msg in bytes.
 */
void hmac_sha512_impl(struct sha512 *sha,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *msg, size_t msg_len);

#endif /* LIBWALLY_HMAC_H */

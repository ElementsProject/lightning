#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

/**
 * Calculate the base58 checksum of a block of binary data.
 *
 * @bytes: Binary data to calculate the checksum for.
 * @len: The length of @bytes in bytes.
 */
uint32_t base58_get_checksum(
    const unsigned char *bytes,
    size_t len);

#endif /* LIBWALLY_BASE58_H */

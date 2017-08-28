#ifndef LIBWALLY_BASE58_H
#define LIBWALLY_BASE58_H

/**
 * Calculate the base58 checksum of a block of binary data.
 *
 * @bytes_in: Binary data to calculate the checksum for.
 * @len: The length of @bytes_in in bytes.
 */
uint32_t base58_get_checksum(
    const unsigned char *bytes_in,
    size_t len);

#endif /* LIBWALLY_BASE58_H */

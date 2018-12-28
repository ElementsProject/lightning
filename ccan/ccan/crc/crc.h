/* Licensed under GPLv2+ - see LICENSE file for details */
#ifndef CCAN_CRC_H
#define CCAN_CRC_H
#include <stdint.h>
#include <stdlib.h>

/**
 * crc32c - Castagnoli 32 bit crc of string of bytes
 * @start_crc: the initial crc (usually 0)
 * @buf: pointer to bytes
 * @size: length of buffer
 *
 * If you don't know what crc32 to use, use this one: it's the best.
 *
 * @Article{castagnoli-crc,
 * author =       { Guy Castagnoli and Stefan Braeuer and Martin Herrman},
 * title =        {{Optimization of Cyclic Redundancy-Check Codes with 24
 *                 and 32 Parity Bits}},
 * journal =      IEEE Transactions on Communication,
 * year =         {1993},
 * volume =       {41},
 * number =       {6},
 * pages =        {},
 * month =        {June},
 *}
 * 32 bit CRC checksum using polynomial
 * X^32+X^28+X^27+X^26+X^25+X^23+X^22+X^20+X^19+X^18+X^14+X^13+X^11+X^10+X^9+X^8+X^6+X^0.
 *
 * You can calculate the CRC of non-contiguous arrays by passing @start_crc
 * as 0 the first time, and the current crc result from then on.
 *
 * Example:
 *	#include <sys/uio.h>
 *	...
 *	// Check that iovec has the crc we expect (Castagnoli version)
 *	static bool check_crc(uint32_t expected, const struct iovec *iov, int l)
 *	{
 *		uint32_t crc = 0;
 *		while (l >= 0) {
 *			crc = crc32c(crc, iov->iov_base, iov->iov_len);
 *			iov++;
 *		}
 *		return crc == expected;
 *	}
 */
uint32_t crc32c(uint32_t start_crc, const void *buf, size_t size);

/**
 * crc32c_table - Get the Castagnoli CRC table
 *
 * For special effects, you might want direct access to the table; this is
 * the standard 256-entry table for this algorithm.
 *
 * In theory, this might need to malloc(), and thus return NULL.
 *
 * Example:
 *	// This dumb code only handles Castagnoli, so assert that here.
 *	static void check_user_crc_table(const uint32_t *usertab)
 *	{
 *		const uint32_t *ctab = crc32c_table();
 *		if (!ctab || memcmp(ctab, usertab, 1024) != 0)
 *			abort();
 *	}
 */
const uint32_t *crc32c_table(void);

/**
 * crc32_ieee - IEEE 802.3 32 bit crc of string of bytes
 * @start_crc: the initial crc (usually 0)
 * @buf: pointer to bytes
 * @size: length of buffer
 *
 * 32 bit CRC checksum using polynomial
 * X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0.
 *
 * See crc32c() for details.
 */
uint32_t crc32_ieee(uint32_t start_crc, const void *buf, size_t size);

/**
 * crc32_ieee_table - Get the IEEE 802.3 CRC table
 *
 * See crc32c_table() for details.
 */
const uint32_t *crc32_ieee_table(void);

/**
 * crc64_iso - ISO 3309
 * @start_crc: the initial crc (usually 0)
 * @buf: pointer to bytes
 * @size: length of buffer
 *
 * 64 bit CRC checksum using polynomial
 * X^64 + X^4 + X^3 + X^1 + X^0
 *
 * See crc32c() for details.
 */
uint64_t crc64_iso(uint64_t start_crc, const void *buf, size_t size);

/**
 * crc64_iso_table - Get the ISO 3309 CRC table
 *
 * See crc32c_table() for details.
 */
const uint64_t *crc64_iso_table(void);

#endif /* CCAN_CRC_H */

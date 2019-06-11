/* Licensed under MIT - see LICENSE file for details */
#ifndef CCAN_CRC32C_H
#define CCAN_CRC32C_H
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

#endif /* CCAN_CRC32C_H */

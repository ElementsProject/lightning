/* Test vectors from https://tools.ietf.org/html/rfc3720#appendix-B.4 */

/* Get access to sw version explicitly */
#include <ccan/crc32c/crc32c.c>
#include <ccan/tap/tap.h>
#include <string.h>

#define BSWAP_32(val)					\
	((((uint32_t)(val) & 0x000000ff) << 24)		\
	 | (((uint32_t)(val) & 0x0000ff00) << 8)		\
	 | (((uint32_t)(val) & 0x00ff0000) >> 8)		\
	 | (((uint32_t)(val) & 0xff000000) >> 24))

#if HAVE_LITTLE_ENDIAN
#define BE32_TO_CPU(le_val) BSWAP_32((uint32_t)le_val)
#else
#define BE32_TO_CPU(le_val) ((uint32_t)(le_val))
#endif

int main(void)
{
	unsigned char m[48];

	plan_tests(5);

	/* 32 bytes of zeroes:

     Byte:        0  1  2  3

        0:       00 00 00 00
      ...
       28:       00 00 00 00

      CRC:       aa 36 91 8a
	*/

	memset(m, 0, 32);
	ok1(crc32c_sw(0, m, 32) == BE32_TO_CPU(0xaa36918a));

	/* 32 bytes of ones:

     Byte:        0  1  2  3

        0:       ff ff ff ff
      ...
       28:       ff ff ff ff

      CRC:       43 ab a8 62
	*/
	memset(m, 0xff, 32);
	ok1(crc32c_sw(0, m, 32) == BE32_TO_CPU(0x43aba862));

	/* 32 bytes of incrementing 00..1f:

     Byte:        0  1  2  3

        0:       00 01 02 03
      ...
       28:       1c 1d 1e 1f

      CRC:       4e 79 dd 46
	*/
	for (size_t i = 0; i < 32; i++)
		m[i] = i;
	ok1(crc32c_sw(0, m, 32) == BE32_TO_CPU(0x4e79dd46));

	/*  32 bytes of decrementing 1f..00:

     Byte:        0  1  2  3

        0:       1f 1e 1d 1c
      ...
       28:       03 02 01 00

      CRC:       5c db 3f 11
	*/
	for (size_t i = 0; i < 32; i++)
		m[i] = 31 - i;
	ok1(crc32c_sw(0, m, 32) == BE32_TO_CPU(0x5cdb3f11));

	/*  An iSCSI - SCSI Read (10) Command PDU
    Byte:        0  1  2  3

       0:       01 c0 00 00
       4:       00 00 00 00
       8:       00 00 00 00
      12:       00 00 00 00
      16:       14 00 00 00
      20:       00 00 04 00
      24:       00 00 00 14
      28:       00 00 00 18
      32:       28 00 00 00
      36:       00 00 00 00
      40:       02 00 00 00
      44:       00 00 00 00

     CRC:       56 3a 96 d9
	*/
	memset(m, 0, sizeof(m));
	m[0] = 0x01;
	m[1] = 0xc0;
	m[16] = 0x14;
	m[22] = 0x04;
	m[27] = 0x14;
	m[31] = 0x18;
	m[32] = 0x28;
	m[40] = 0x02;
	ok1(crc32c_sw(0, m, sizeof(m)) == BE32_TO_CPU(0x563a96d9));

	return exit_status();
}

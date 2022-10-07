#include <ccan/endian/endian.h>
#include <stdlib.h>
#include <stddef.h>
#include <ccan/tap/tap.h>

int main(int argc, char *argv[])
{
	union {
		uint64_t u64;
		unsigned char u64_bytes[8];
	} u64;
	union {
		uint32_t u32;
		unsigned char u32_bytes[4];
	} u32;
	union {
		uint16_t u16;
		unsigned char u16_bytes[2];
	} u16;

	plan_tests(48);

	/* Straight swap tests. */
	u64.u64_bytes[0] = 0x00;
	u64.u64_bytes[1] = 0x11;
	u64.u64_bytes[2] = 0x22;
	u64.u64_bytes[3] = 0x33;
	u64.u64_bytes[4] = 0x44;
	u64.u64_bytes[5] = 0x55;
	u64.u64_bytes[6] = 0x66;
	u64.u64_bytes[7] = 0x77;
	u64.u64 = bswap_64(u64.u64);
	ok1(u64.u64_bytes[7] == 0x00);
	ok1(u64.u64_bytes[6] == 0x11);
	ok1(u64.u64_bytes[5] == 0x22);
	ok1(u64.u64_bytes[4] == 0x33);
	ok1(u64.u64_bytes[3] == 0x44);
	ok1(u64.u64_bytes[2] == 0x55);
	ok1(u64.u64_bytes[1] == 0x66);
	ok1(u64.u64_bytes[0] == 0x77);

	u32.u32_bytes[0] = 0x00;
	u32.u32_bytes[1] = 0x11;
	u32.u32_bytes[2] = 0x22;
	u32.u32_bytes[3] = 0x33;
	u32.u32 = bswap_32(u32.u32);
	ok1(u32.u32_bytes[3] == 0x00);
	ok1(u32.u32_bytes[2] == 0x11);
	ok1(u32.u32_bytes[1] == 0x22);
	ok1(u32.u32_bytes[0] == 0x33);

	u16.u16_bytes[0] = 0x00;
	u16.u16_bytes[1] = 0x11;
	u16.u16 = bswap_16(u16.u16);
	ok1(u16.u16_bytes[1] == 0x00);
	ok1(u16.u16_bytes[0] == 0x11);

	/* Endian tests. */
	u64.u64 = cpu_to_le64(0x0011223344556677ULL);
	ok1(u64.u64_bytes[0] == 0x77);
	ok1(u64.u64_bytes[1] == 0x66);
	ok1(u64.u64_bytes[2] == 0x55);
	ok1(u64.u64_bytes[3] == 0x44);
	ok1(u64.u64_bytes[4] == 0x33);
	ok1(u64.u64_bytes[5] == 0x22);
	ok1(u64.u64_bytes[6] == 0x11);
	ok1(u64.u64_bytes[7] == 0x00);
	ok1(le64_to_cpu(u64.u64) == 0x0011223344556677ULL);

	u64.u64 = cpu_to_be64(0x0011223344556677ULL);
	ok1(u64.u64_bytes[7] == 0x77);
	ok1(u64.u64_bytes[6] == 0x66);
	ok1(u64.u64_bytes[5] == 0x55);
	ok1(u64.u64_bytes[4] == 0x44);
	ok1(u64.u64_bytes[3] == 0x33);
	ok1(u64.u64_bytes[2] == 0x22);
	ok1(u64.u64_bytes[1] == 0x11);
	ok1(u64.u64_bytes[0] == 0x00);
	ok1(be64_to_cpu(u64.u64) == 0x0011223344556677ULL);

	u32.u32 = cpu_to_le32(0x00112233);
	ok1(u32.u32_bytes[0] == 0x33);
	ok1(u32.u32_bytes[1] == 0x22);
	ok1(u32.u32_bytes[2] == 0x11);
	ok1(u32.u32_bytes[3] == 0x00);
	ok1(le32_to_cpu(u32.u32) == 0x00112233);

	u32.u32 = cpu_to_be32(0x00112233);
	ok1(u32.u32_bytes[3] == 0x33);
	ok1(u32.u32_bytes[2] == 0x22);
	ok1(u32.u32_bytes[1] == 0x11);
	ok1(u32.u32_bytes[0] == 0x00);
	ok1(be32_to_cpu(u32.u32) == 0x00112233);

	u16.u16 = cpu_to_le16(0x0011);
	ok1(u16.u16_bytes[0] == 0x11);
	ok1(u16.u16_bytes[1] == 0x00);
	ok1(le16_to_cpu(u16.u16) == 0x0011);

	u16.u16 = cpu_to_be16(0x0011);
	ok1(u16.u16_bytes[1] == 0x11);
	ok1(u16.u16_bytes[0] == 0x00);
	ok1(be16_to_cpu(u16.u16) == 0x0011);

	exit(exit_status());
}

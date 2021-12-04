#include <ccan/utf8/utf8.h>
/* Include the C files directly. */
#include <ccan/utf8/utf8.c>
#include <ccan/tap/tap.h>
#include <assert.h>

/* Stolen from https://github.com/chansen/c-utf8-valid/blob/master/test.c */

/*
 *  UTF-8
 *
 *     U+0000..U+007F         00..7F
 *                         n  C0..C1  80..BF
 *     U+0080..U+07FF         C2..DF  80..BF
 *                         n  E0      80..9F  80..BF
 *     U+0800..U+D7FF         E0..ED  A0..9F  80..BF
 *     U+D800..U+DFFF      s  ED      A0..BF  80..BF
 *     U+E000..U+FFFF         EE..EF  80..BF  80..BF
 *                         n  F0      80..8F  80..BF  80..BF
 *     U+0800..U+FFFF         F0      80..8F  A0..BF  80..BF
 *    U+10000..U+10FFFF       F0..F4  90..8F  80..BF  80..BF
 *
 *   U-110000..U-1FFFFF    x  F4..F7  90..BF  80..BF  80..BF
 *                         xn F8      80..87  80..BF  80..BF  80..BF
 *   U-200000..U-3FFFFFF   x  F8..FB  88..BF  80..BF  80..BF  80..BF
 *                         xn FC      80..83  80..BF  80..BF  80..BF  80..BF
 *  U-4000000..U-7FFFFFFF  x  FC..FD  84..BF  80..BF  80..BF  80..BF  80..BF
 * 
 *  Legend:
 *    n = Non-shortest form
 *    s = Surrogates
 *    x = Codepoints outside Unicode codespace
 */

/*
 *  Encodes the given ordinal [0, 7FFFFFFF] using the UTF-8 encoding scheme
 *  to the given sequence length [1, 6]. This routine can be used to
 *  produce well-formed and ill-formed UTF-8.
 *
 *  To encode a Unicode scalar value to a well-formed representation:
 *
 *   [U+0000, U+007F] should be encoded to a sequence length of 1
 *   [U+0080, U+07FF] should be encoded to a sequence length of 2
 *   [U+0800, U+D7FF] should be encoded to a sequence length of 3
 *   [U+E000, U+FFFF] should be encoded to a sequence length of 3
 *   [U+10000, U+10FFFF] should be encoded to a sequence length of 4
 *
 *  To encode a Unicode scalar value to non-shortest form representation:
 *
 *   [U+0000, U+007F] can be encoded to a sequence length of [2, 6]
 *   [U+0080, U+07FF] can be encoded to a sequence length of [3, 6]
 *   [U+0800, U+FFFF] can be encoded to a sequence length of [4, 6]
 *
 *  To encode an ordinal outside of Unicode codespace:
 *
 *   [110000, 1FFFFF] can be encoded to a sequence length of 4
 *   [200000, 3FFFFFF] can be encoded to a sequence length of 5
 *   [4000000, 7FFFFFFF] can be encoded to a sequence length of 6
 */

static char *
encode_ord(uint32_t ord, size_t len, char *dst) {
  static const uint32_t kMask[6] = { 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
  static const uint32_t kMax[6]  = { 1 <<  7, 1 << 11, 1 << 16, 
                                     1 << 21, 1 << 26, 1 << 31 };
  size_t i;

  assert(len >= 1);
  assert(len <= 6);
  assert(ord < kMax[len - 1]);

  for (i = len - 1; i > 0; i--) {
    dst[i] = (ord & 0x3F) | 0x80;
    ord >>= 6;
  }
  dst[0] = ord | kMask[len - 1];
  return dst;
}

static int utf8_check(const char *src, size_t len)
{
	bool decoded = false;
	struct utf8_state utf8_state = UTF8_STATE_INIT;
	size_t i;

	for (i = 0; i < len; i++) {
		decoded = utf8_decode(&utf8_state, src[i]);
		if (decoded) {
			if (errno != 0)
				return errno;
		}
	}
	if (!decoded)
		return EMLINK;
	return 0;
}

static void
test_utf8(const char *src, size_t len, int exp_err, unsigned line) {
  int got_err;

  assert(len <= 255);

  got_err = utf8_check(src, len);

  ok(got_err == exp_err, "Got result %i, expected %i at line %u",
     got_err, exp_err, line);
}

#define TEST_UTF8(src, len, exp) \
  test_utf8(src, len, exp, __LINE__)


static void
test_unicode_scalar_value(void) {
  uint32_t ord;
  char src[4];

  /* Unicode scalar value [U+0000, U+007F] */
  for (ord = 0x0001; ord <= 0x007F; ord++) {
    encode_ord(ord, 1, src);
    TEST_UTF8(src, 1, ord ? 0 : ERANGE);
  }

  /*
   * Unicode scalar value [U+0080, U+07FF]
   * The maximal subpart is the length of the truncated sequence
   */
  for (ord = 0x0080; ord <= 0x07FF; ord++) {
    encode_ord(ord, 2, src);
    TEST_UTF8(src, 2, 0);
  }

  /*
   * Unicode scalar value [U+0800, U+D7FF] and [U+E000, U+FFFF]
   * The maximal subpart is the length of the truncated sequence
   */
  for (ord = 0x0800; ord <= 0xFFFF && (ord & 0xF800) != 0xD800; ord++) {
    encode_ord(ord, 3, src);

    TEST_UTF8(src, 3, 0);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }

  /*
   * Unicode scalar value [U+10000, U+10FFF]
   * The maximal subpart is the length of the truncated sequence
   */
  for (ord = 0x10000; ord <= 0x10FFFF; ord++) {
    encode_ord(ord, 4, src);

    TEST_UTF8(src, 4, 0);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 3, EMLINK);
    if ((ord % (1 << 12)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }
}

static void
test_non_shortest_form(void) {
  uint32_t ord;
  char src[4];

  /*
   * Non-shortest form 2-byte sequence [U+0000, U+007F]
   * The maximal subpart is 1-byte
   */
  for (ord = 0x0001; ord <= 0x007F; ord++) {
    encode_ord(ord, 2, src);
    TEST_UTF8(src, 2, EFBIG);
  }

  /*
   * Non-shortest form 3-byte sequence [U+0000, U+07FF]
   * The maximal subpart is 1-byte
   */
  for (ord = 0x0001; ord <= 0x07FF; ord++) {
    encode_ord(ord, 3, src);

    TEST_UTF8(src, 3, EFBIG);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }

  /*
   * Non-shortest form 4-byte sequence [U+0000, U+FFFF]
   * The maximal subpart is 1-byte
   */
  for (ord = 0x0001; ord <= 0xFFFF; ord++) {
    encode_ord(ord, 4, src);

    TEST_UTF8(src, 4, EFBIG);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 3, EMLINK);
    if ((ord % (1 << 12)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }
}

static void
test_non_unicode(void) {
  uint32_t ord;
  char src[4];

  /*
   * Code point outside Unicode codespace
   * The maximal subpart is 1-byte
   */
  for (ord = 0x110000; ord <= 0x1FFFFF; ord++) {
    encode_ord(ord, 4, src);

    TEST_UTF8(src, 4, ERANGE);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 3, EMLINK);
    if ((ord % (1 << 12)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }
}

static void
test_surrogates(void) {
  uint32_t ord;
  char src[4];

  /*
   * Surrogates [U+D800, U+DFFF]
   * The maximal subpart is 1-byte
   */
  for (ord = 0xD800; ord <= 0xDFFF; ord++) {
    encode_ord(ord, 3, src);

    TEST_UTF8(src, 3, ERANGE);
    if ((ord % (1 << 6)) == 0)
      TEST_UTF8(src, 2, EMLINK);
  }
}

static void
test_continuations(void) {
  uint8_t ord;
  char src[4];

  /*
   * Missplaced continuation [\x80, \xBF]
   * The maximal subpart is 1-byte
   */
  for (ord = 0x80; ord <= 0xBF; ord++) {
    src[0] = ord;
    TEST_UTF8(src, 1, EINVAL);
  }
}

int
main(int argc, char **argv)
{
  plan_tests(2190906 - 1);
  test_unicode_scalar_value();
  test_surrogates();
  test_non_shortest_form();
  test_non_unicode();
  test_continuations();

  return exit_status();
}

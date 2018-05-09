#include <common/base32.h>
#include <sys/types.h>

/* This is a rework of what i found on the Net about base32
 *
 * so Orum (shallot) and Markus Gutschke (Google.inc) should be mentioned here
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define BASE32DATA "abcdefghijklmnopqrstuvwxyz234567"

char *b32_encode(char *dst, u8 * src, u8 ver)
{
	u16 byte = 0, poff = 0;
	for (; byte < ((ver == 2) ? 16 : 56); poff += 5) {
		if (poff > 7) {
			poff -= 8;
			src++;
		}
		dst[byte++] =
		    BASE32DATA[(htobe16(*(u16 *) src) >> (11 - poff)) & (u16)
			       0x001F];
	}
	dst[byte] = 0;
	return dst;
}

//FIXME quiknditry

void b32_decode(u8 * dst, u8 * src, u8 ver)
{
	int rem = 0;
	int i;
	u8 *p = src;
	int buf;
	u8 ch;
	for (i = 0; i < ((ver == 2) ? 16 : 56); p++) {
		ch = *p;
		buf <<= 5;
		if ((ch >= 'a' && ch <= 'z')) {
			ch = (ch & 0x1F) - 1;
		} else if (ch != '.') {
			ch -= '2' - 0x1A;
		} else return;
		buf = buf | ch;
		rem = rem + 5;
		if (rem >= 8) {
			dst[i++] = buf >> (rem - 8);
			rem -= 8;
		}
	}
}

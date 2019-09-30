/* Start of run.c test */
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ccan/base64/base64.h>
#include <ccan/tap/tap.h>

#include <ccan/base64/base64.c>
#include "moretap.h"

static void * xmalloc(size_t size);

/* not defined in terms of test_encode_using_maps so we cross
   appropriate paths in library */
#define test_encode(src,srclen,expected)			\
	do {							\
		size_t destlen;					\
		char * dest;					\
		destlen = base64_encoded_length(srclen);	\
		destlen++; /* null termination */		\
		dest = xmalloc(destlen);			\
		ok1(base64_encode(dest,destlen,src,srclen) != -1);	\
		is_str(dest,expected);					\
		free(dest);						\
	} while (0)

#define test_encode_using_alphabet(alphastring,src,srclen,expected)	\
	do {								\
		size_t destlen;						\
		char * dest;						\
		base64_maps_t maps;				\
		base64_init_maps(&maps,alphastring);		\
		destlen = base64_encoded_length(srclen);		\
		destlen++; /* null termination */		\
		dest = xmalloc(destlen);				\
		ok1(base64_encode_using_maps(&maps,dest,destlen,src,srclen) != -1); \
		is_str(dest,expected);					\
		free(dest);						\
	} while (0)

/* not defined in terms of test_decode_using_alphabet so we cross
   appropriate paths in library */
#define test_decode(src,srclen,expected,expectedlen)			\
	do {								\
		size_t destlen;						\
		size_t bytes_used;					\
		char * dest;						\
		destlen = base64_decoded_length(srclen);		\
		dest = xmalloc(destlen);				\
		ok1((bytes_used = base64_decode(dest,destlen,src,srclen)) != -1); \
		is_size_t(bytes_used,expectedlen);			\
		is_mem(dest,expected,bytes_used);			\
		free(dest);						\
	} while (0)

#define test_decode_using_alphabet(alphastring,src,srclen,expected,expectedlen) \
	do {								\
		size_t destlen;						\
		size_t bytes_used;					\
		char * dest;						\
		base64_maps_t maps;				\
									\
		base64_init_maps(&maps,alphastring);		\
		destlen = base64_decoded_length(srclen);		\
		dest = xmalloc(destlen);				\
		ok1((bytes_used = base64_decode_using_maps(&maps,dest,destlen,src,srclen)) != -1); \
		is_size_t(bytes_used,expectedlen);			\
		is_mem(dest,expected,bytes_used);			\
		free(dest);						\
	} while (0)

#define check_bad_range_decode(stuff_to_test,stufflen)	\
do {							\
	char dest[10];							\
	errno = 0;							\
	is_size_t(base64_decode(dest,sizeof(dest),stuff_to_test,(size_t)stufflen), \
		  (size_t)-1);						\
	is_int(errno,EDOM);						\
} while (0)

int
main(int argc, char *argv[])
{
	plan_tests(131);

	is_size_t(base64_encoded_length(0),(size_t)0);
	is_size_t(base64_encoded_length(1),(size_t)4);
	is_size_t(base64_encoded_length(2),(size_t)4);
	is_size_t(base64_encoded_length(3),(size_t)4);
	is_size_t(base64_encoded_length(512),(size_t)684);

	/* straight from page 11 of http://tools.ietf.org/html/rfc4648 */
	test_encode("",0,"");
	test_encode("f",1,"Zg==");
	test_encode("fo",2,"Zm8=");

	test_encode("foo",3,"Zm9v");
	test_encode("foob",4,"Zm9vYg==");
	test_encode("fooba",5,"Zm9vYmE=");
	test_encode("foobar",6,"Zm9vYmFy");

	/* a few more */
	test_encode("foobarb",7,"Zm9vYmFyYg==");
	test_encode("foobarba",8,"Zm9vYmFyYmE=");
	test_encode("foobarbaz",9,"Zm9vYmFyYmF6");

	test_encode("foobart",7,"Zm9vYmFydA==");

	test_encode("abcdefghijklmnopqrstuvwxyz",26,"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=");
	test_encode("\x05\x05\x01\x00\x07",5,"BQUBAAc=");

	test_encode("FOO",3,"Rk9P");
	test_encode("Z",1,"Wg==");

	/* decode testing */

	test_decode("",0,"",0);
	test_decode("Zg==",4,"f",1);
	test_decode("Zm8=",4,"fo",2);
	test_decode("Zm9v",4,"foo",3);
	test_decode("Zm9vYg==",8,"foob",4);
	test_decode("Zm9vYmE=",8,"fooba",5);
	test_decode("Zm9vYmFy",8,"foobar",6);
	test_decode("Zm9vYmFyYg==",12,"foobarb",7);
	test_decode("Zm9vYmFyYmE=",12,"foobarba",8);
	test_decode("Zm9vYmFyYmF6",12,"foobarbaz",9);

	test_decode("Rk9P",4,"FOO",3);

	test_decode("Wg==",4,"Z",1);
	test_decode("AA==",4,"\0",1);
	test_decode("AAA=",4,"\0\0",2);

	{
		const char *binary = "\x01\x00\x03";
		const size_t binarylen = 3;

		char * decoded;
		char * encoded;
		size_t encoded_len;
		size_t decoded_len;
		size_t decoded_space_required;

		size_t encoded_space_required = base64_encoded_length(binarylen);
		encoded_space_required++; /* null termination */
		encoded = xmalloc(encoded_space_required);
		encoded_len = base64_encode(encoded,encoded_space_required,binary,binarylen);
		is_mem(encoded,"AQAD",encoded_len);

		decoded_space_required = base64_decoded_length(encoded_len);
		decoded = xmalloc(decoded_space_required);
		decoded_len = base64_decode(decoded,decoded_space_required,encoded,encoded_len);
		is_size_t(decoded_len,binarylen);
		is_mem(binary,decoded,decoded_len);
	}

	/* some expected encode failures: */
	{
		size_t destlen = 1;
		char dest[destlen];
		errno = 0;
		is_size_t(base64_encode(dest,destlen,"A",1),(size_t)-1);
		is_int(errno,EOVERFLOW);
	}

	/* some expected decode failures: */
	{
		base64_maps_t maps;
		const char * src = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		base64_init_maps(&maps,src);

		is_int(sixbit_from_b64(&maps,'\xfe'),(signed char)-1);
		is_int(errno,EDOM);
	}
	{
		size_t destlen = 10;
		char dest[destlen];
		errno = 0;
		is_size_t(base64_decode(dest,destlen,"A",1),(size_t)-1);
		is_int(errno,EINVAL);
	}
	{
		size_t destlen = 1;
		char dest[destlen];
		errno = 0;
		is_size_t(base64_decode(dest,destlen,"A",1),(size_t)-1);
		is_int(errno,EOVERFLOW);
	}
	{
		/* (char)1 is not a valid base64 character: */
		check_bad_range_decode("A\x01",2);
		/* (char)255 is not a valid base64 character: (char is signed on most platforms, so this is actually < 0 */
		check_bad_range_decode("\xff""A",2);
		check_bad_range_decode("A\xff",2);
		check_bad_range_decode("AA\xff",3);
		check_bad_range_decode("A\xff""A",3);
		check_bad_range_decode("\xff""AA",3);
		check_bad_range_decode("AAA\xff",4);
		check_bad_range_decode("\xff\x41\x41\x41\x41",5);
		check_bad_range_decode("A\xff\x41\x41\x41\x41",6);
		check_bad_range_decode("AA\xff\x41\x41\x41\x41",7);
		check_bad_range_decode("AAA\xff\x41\x41\x41\x41",8);
	}
	/* trigger some failures in the sixbit-to-b64 encoder: */
	/* this function now aborts rather than returning -1/setting errno */
	/* { */
	/* 	is_int(sixbit_to_b64(base64_maps_rfc4648,'\x70'),(char)-1); */
	/* 	is_int(sixbit_to_b64(base64_maps_rfc4648,'\xff'),(char)-1); */
	/* } */
	/* following tests all of the mapping from b64 chars to 6-bit values: */
	test_decode("//+FwHRSRIsFU2IhAEGD+AMPhOA=",28,"\xff\xff\x85\xc0\x74\x52\x44\x8b\x05\x53\x62\x21\x00\x41\x83\xf8\x03\x0f\x84\xe0",20);
	test_encode("\xff\xff\x85\xc0\x74\x52\x44\x8b\x05\x53\x62\x21\x00\x41\x83\xf8\x03\x0f\x84\xe0",20,"//+FwHRSRIsFU2IhAEGD+AMPhOA=");


	/* check the null-padding stuff */
	{
		size_t destlen = 8;
		char dest[destlen];
		memset(dest,'\1',sizeof(dest));
		is_size_t(base64_encode(dest,destlen,"A",1),(size_t)4);
		is_mem(&dest[4],"\0\0\0\0",4);
	}
	{
		size_t destlen = 3;
		char dest[destlen];
		memset(dest,'\1',sizeof(dest));
		is_size_t(base64_decode(dest,destlen,"Wg==",4), 1);
		is_mem(&dest[1],"\0",2);
	}

	/* test encoding using different alphabets */
	{
		char alphabet_fs_safe[64];
		memcpy(alphabet_fs_safe,base64_maps_rfc4648.encode_map,sizeof(alphabet_fs_safe));
		alphabet_fs_safe[62] = '-';
		alphabet_fs_safe[63] = '_';
		test_encode_using_alphabet(alphabet_fs_safe,"\xff\xff\x85\xc0\x74\x52\x44\x8b\x05\x53\x62\x21\x00\x41\x83\xf8\x03\x0f\x84\xe0",20,"__-FwHRSRIsFU2IhAEGD-AMPhOA=");
	}

	/* test decoding using different alphabets */
	{
		char alphabet_fs_safe[64];
		#define src "__-FwHRSRIsFU2IhAEGD-AMPhOA="
		#define expected "\xff\xff\x85\xc0\x74\x52\x44\x8b\x05\x53\x62\x21\x00\x41\x83\xf8\x03\x0f\x84\xe0"

		memcpy(alphabet_fs_safe,base64_maps_rfc4648.encode_map,sizeof(alphabet_fs_safe));
		alphabet_fs_safe[62] = '-';
		alphabet_fs_safe[63] = '_';

		test_decode_using_alphabet(alphabet_fs_safe,src,strlen(src),expected,20);
		#undef src
		#undef expected
	}

	/* explicitly test the non-maps encode_triplet and
	   encode_tail functions */
	{
		size_t destlen = 4;
		char dest[destlen];
		const char *src = "AB\04";
		memset(dest,'\1',sizeof(dest));
		base64_encode_triplet(dest,src);
		is_mem(dest,"QUIE",sizeof(dest));
	}
	{
		size_t destlen = 4;
		char dest[destlen];
		const char *src = "A";
		memset(dest,'\1',sizeof(dest));
		base64_encode_tail(dest,src,strlen(src));
		is_mem(dest,"QQ==",sizeof(dest));
	}

	/* test the alphabet inversion */
	{
		base64_maps_t dest;
		const char expected_inverse[] =
			"\xff\xff\xff\xff\xff" /* 0 */
			"\xff\xff\xff\xff\xff" /* 5 */
			"\xff\xff\xff\xff\xff" /* 10 */
			"\xff\xff\xff\xff\xff" /* 15 */
			"\xff\xff\xff\xff\xff" /* 20 */
			"\xff\xff\xff\xff\xff" /* 25 */
			"\xff\xff\xff\xff\xff" /* 30 */
			"\xff\xff\xff\xff\xff" /* 35 */
			"\xff\xff\xff\x3e\xff" /* 40 */
			"\xff\xff\x3f\x34\x35" /* 45 - */
			"\x36\x37\x38\x39\x3a" /* 50 */
			"\x3b\x3c\x3d\xff\xff" /* 55 */
			"\xff\xff\xff\xff\xff" /* 60 */
			"\x00\x01\x02\x03\x04" /* 65 A */
			"\x05\x06\x07\x08\x09" /* 70 */
			"\x0a\x0b\x0c\x0d\x0e" /* 75 */
			"\x0f\x10\x11\x12\x13" /* 80 */
			"\x14\x15\x16\x17\x18" /* 85 */
			"\x19\xff\xff\xff\xff" /* 90 */
			"\xff\xff\x1a\x1b\x1c" /* 95 _ */
			"\x1d\x1e\x1f\x20\x21" /* 100 */
			"\x22\x23\x24\x25\x26" /* 105 */
			"\x27\x28\x29\x2a\x2b" /* 110 */
			"\x2c\x2d\x2e\x2f\x30" /* 115 */
			"\x31\x32\x33\xff\xff" /* 120 */
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 125 */
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 155 */
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 185 */
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 215 */
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
			"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 245 */
			;
		const char * src = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		base64_init_maps(&dest, src);
		is_mem((const char *)dest.decode_map, expected_inverse, 256);
		ok1(base64_char_in_alphabet(&dest,'A'));
		ok1(!base64_char_in_alphabet(&dest,'\n'));
	}

	/* explicitly test the non-alpha decode_tail and decode_quartet */
	{
		char dest[4];
		const char *src = "QQ==";
		const char * expected = "A";
		memset(dest, '%', sizeof(dest));
		base64_decode_tail(dest,src,4);
		is_mem(dest, expected, 1);
	}
	{
		char dest[4];
		const char *src = "Zm9v";
		const char * expected = "foo";
		memset(dest, '%', sizeof(dest));
		base64_decode_quartet(dest,src);
		is_mem(dest, expected, 1);
	}

	exit(exit_status());
}

static void * xmalloc(size_t size)
{
	char * ret;
	ret = malloc(size);
	if (ret == NULL) {
		perror("malloc");
		abort();
	}
	return ret;
}

/* End of run.c test */

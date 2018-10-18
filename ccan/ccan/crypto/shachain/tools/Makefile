#! /usr/bin/make

CCANDIR=../../../..
CFLAGS=-Wall -Werror -O3 -I$(CCANDIR) -DSHACHAIN_BITS=48
#CFLAGS=-Wall -Werror -g3 -I$(CCANDIR) -DSHACHAIN_BITS=48

# 48 bit index for shachain.  This is what lightning uses.
CCAN_OBJS:=ccan-str.o ccan-err.o ccan-hex.o ccan-shachain.o ccan-sha256.o ccan-rbuf.o ccan-membuf.o

all: shachain48

shachain48: shachain48.o $(CCAN_OBJS)

shachain48.o: $(CCANDIR)/ccan/crypto/shachain/shachain.h	\
	$(CCANDIR)/ccan/str/hex/hex.h			\
	$(CCANDIR)/ccan/str/str.h				\
	$(CCANDIR)/ccan/err/err.h				\
	$(CCANDIR)/ccan/membuf/membuf.h				\
	$(CCANDIR)/ccan/rbuf/rbuf.h

shachain48.o $(CCAN_OBJS): $(CCANDIR)/config.h

$(CCANDIR)/config.h:
	$(MAKE) -C $(CCANDIR) config.h

clean:
	rm -f shachain *.o

ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-rbuf.o: $(CCANDIR)/ccan/rbuf/rbuf.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-membuf.o: $(CCANDIR)/ccan/membuf/membuf.c
	$(CC) $(CFLAGS) -c -o $@ $<

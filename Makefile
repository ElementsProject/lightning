#! /usr/bin/make

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

# Alpha has checksequenceverify, segregated witness+input-amount-in-sig+confidentual-transactions, schnorr
FEATURES := -DHAS_CSV=1 -DALPHA_TXSTYLE=1 -DUSE_SCHNORR=1
# Bitcoin uses DER for signatures
#FEATURES := -DSCRIPTS_USE_DER

PROGRAMS := test-cli/open-channel test-cli/open-anchor-scriptsigs test-cli/open-commit-sig test-cli/check-commit-sig test-cli/check-anchor-scriptsigs test-cli/get-anchor-depth test-cli/create-steal-tx test-cli/create-commit-spend-tx test-cli/close-channel test-cli/create-close-tx test-cli/update-channel test-cli/update-channel-accept test-cli/update-channel-signature test-cli/update-channel-complete test-cli/create-commit-tx

BITCOIN_OBJS := bitcoin/address.o bitcoin/base58.o bitcoin/pubkey.o bitcoin/script.o bitcoin/shadouble.o bitcoin/signature.o bitcoin/tx.o

HELPER_OBJS := lightning.pb-c.o pkt.o permute_tx.o anchor.o commit_tx.o opt_bits.o close_tx.o find_p2sh_out.o protobuf_convert.o

CCAN_OBJS := ccan-crypto-sha256.o ccan-crypto-shachain.o ccan-err.o ccan-tal.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-read_write_all.o ccan-str-hex.o ccan-tal-grab_file.o ccan-noerr.o

HEADERS := $(wildcard *.h)

CCANDIR := ccan/
CFLAGS := -g -Wall -I $(CCANDIR) -I secp256k1/include/ -DVALGRIND_HEADERS=1 $(FEATURES)
LDLIBS := -lcrypto -lprotobuf-c
$(PROGRAMS): CFLAGS+=-I.

default: $(PROGRAMS)

TAGS: FORCE
	$(RM) TAGS; find . -name '*.[ch]' | xargs etags --append
FORCE::

# We build a static libsecpk1, since we need schnorr for alpha
# (and it's not API stable yet!).
libsecp256k1.a:
	cd secp256k1 && ./autogen.sh && ./configure --enable-static=yes --enable-shared=no --enable-tests=no --libdir=`pwd`/..
	$(MAKE) -C secp256k1 install-exec

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	$(PROTOCC) lightning.proto --c_out=.

$(PROGRAMS): % : %.o $(HELPER_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS) libsecp256k1.a
$(PROGRAMS:=.o) $(HELPER_OBJS): $(HEADERS)

$(CCAN_OBJS) $(HELPER_OBJS) $(PROGRAM_OBJS) $(BITCOIN_OBJS): ccan/config.h

ccan/config.h: ccan/tools/configurator/configurator
	$< > $@

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | sed s,/_info,, | sort` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan describe` >> ccan/README
	$(RM) -r ccan.old

distclean: clean
	$(RM) lightning.pb-c.c lightning.pb-c.h ccan/config.h

clean:
	$(RM) $(PROGRAMS) test-cli/leak-anchor-sigs
	$(RM) bitcoin/*.o *.o $(CCAN_OBJS)

ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<


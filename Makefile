#! /usr/bin/make

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

PROGRAMS := test-cli/open-channel test-cli/open-anchor-scriptsigs test-cli/leak-anchor-sigs test-cli/open-commit-sig test-cli/check-commit-sig test-cli/check-anchor-scriptsigs test-cli/get-anchor-depth test-cli/create-steal-tx test-cli/create-commit-spend-tx test-cli/close-channel test-cli/create-close-tx test-cli/update-channel test-cli/update-channel-accept test-cli/update-channel-signature test-cli/update-channel-complete test-cli/create-commit-tx

BITCOIN_OBJS := bitcoin/address.o bitcoin/base58.o bitcoin/pubkey.o bitcoin/script.o bitcoin/shadouble.o bitcoin/signature.o bitcoin/tx.o

HELPER_OBJS := lightning.pb-c.o pkt.o permute_tx.o anchor.o commit_tx.o opt_bits.o close_tx.o find_p2sh_out.o protobuf_convert.o

CCAN_OBJS := ccan-crypto-sha256.o ccan-crypto-shachain.o ccan-err.o ccan-tal.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-read_write_all.o ccan-str-hex.o ccan-tal-grab_file.o ccan-noerr.o

HEADERS := $(wildcard *.h)

CCANDIR := ../ccan/
CFLAGS := -g -Wall -I $(CCANDIR)
LDLIBS := -lcrypto -lprotobuf-c
$(PROGRAMS): CFLAGS+=-I.

default: $(PROGRAMS)

TAGS: FORCE
	$(RM) TAGS; find . -name '*.[ch]' | xargs etags --append
FORCE::

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	$(PROTOCC) lightning.proto --c_out=.

$(PROGRAMS): % : %.o $(HELPER_OBJS) $(BITCOIN_OBJS) $(CCAN_OBJS)
$(PROGRAMS:=.o) $(HELPER_OBJS): $(HEADERS)

distclean: clean
	$(RM) lightning.pb-c.c lightning.pb-c.h

clean:
	$(RM) $(PROGRAMS)
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


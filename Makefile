#! /usr/bin/make

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

PROGRAMS := open-channel open-anchor-scriptsigs leak-anchor-sigs open-commit-sig check-commit-sig check-anchor-scriptsigs get-anchor-depth create-steal-tx create-commit-spend-tx close-channel create-close-tx update-channel update-channel-accept update-channel-complete

HELPER_OBJS := base58.o lightning.pb-c.o shadouble.o pkt.o bitcoin_script.o permute_tx.o signature.o bitcoin_tx.o bitcoin_address.o anchor.o commit_tx.o pubkey.o opt_bits.o close_tx.o find_p2sh_out.o

CCAN_OBJS := ccan-crypto-sha256.o ccan-crypto-shachain.o ccan-err.o ccan-tal.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-read_write_all.o ccan-str-hex.o ccan-tal-grab_file.o ccan-noerr.o

HEADERS := $(wildcard *.h)

CCANDIR := ../ccan/
CFLAGS := -g -Wall -I $(CCANDIR) #-I $(PROTO_INCLUDE_DIR)
LDLIBS := -lcrypto -lprotobuf-c

default: $(PROGRAMS)

TAGS: FORCE
	etags *.[ch] 
FORCE::

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	$(PROTOCC) lightning.proto --c_out=.

$(PROGRAMS): % : %.o $(HELPER_OBJS) $(CCAN_OBJS)
$(PROGRAMS:=.o) $(HELPER_OBJS): $(HEADERS)

distclean: clean
	$(RM) lightning.pb-c.c lightning.pb-c.h

clean:
	$(RM) $(PROGRAMS)
	$(RM) *.o $(CCAN_OBJS)

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


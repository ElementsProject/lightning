COMMON_TEST_SRC := $(wildcard common/test/run-*.c)

COMMON_TEST_OBJS := $(COMMON_TEST_SRC:%.c=$(BUILDDIR)/%.o)
COMMON_TEST_PROGRAMS := $(COMMON_TEST_OBJS:.o=)

COMMON_TEST_COMMON_OBJS :=				\
	$(addprefix $(BUILDDIR)/, 			\
	common/autodata.o				\
	common/randbytes.o				\
	common/clock_time.o				\
	common/setup.o					\
	common/utils.o					\
	)

$(COMMON_TEST_PROGRAMS): $(COMMON_TEST_COMMON_OBJS) $(BITCOIN_OBJS)
$(COMMON_TEST_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC) common/test/Makefile

ALL_C_SOURCES += $(COMMON_TEST_SRC)
ALL_TEST_PROGRAMS += $(COMMON_TEST_PROGRAMS)

# Make them all depend on common/ files, for simplicity (they directly #include some)
$(COMMON_TEST_OBJS): $(COMMON_SRC)

# Sphinx test wants to decode TLVs.
$(BUILDDIR)/common/test/run-sphinx: $(addprefix $(BUILDDIR)/,wire/onion_wiregen.o wire/towire.o wire/fromwire.o)
$(BUILDDIR)/common/test/run-blindedpath_enctlv $(BUILDDIR)/common/test/run-blindedpath_onion: $(addprefix $(BUILDDIR)/,common/base32.o common/wireaddr.o wire/onion_wiregen.o wire/peer_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o)
$(BUILDDIR)/common/test/run-route_blinding_test: $(addprefix $(BUILDDIR)/,wire/onion_wiregen.o wire/peer_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o common/coin_mvt.o)
$(BUILDDIR)/common/test/run-route_blinding_override_test: $(addprefix $(BUILDDIR)/,common/base32.o common/wireaddr.o wire/onion_wiregen.o wire/peer_wiregen.o wire/towire.o wire/fromwire.o wire/tlvstream.o common/coin_mvt.o)

$(BUILDDIR)/common/test/run-param			\
$(BUILDDIR)/common/test/run-json:			\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/base32.o					\
	common/bigsize.o				\
	common/channel_id.o				\
	common/coin_mvt.o				\
	common/json_stream.o				\
	common/lease_rates.o				\
	common/node_id.o				\
	common/pseudorand.o				\
	common/randbytes.o			\
	common/wireaddr.o				\
	wire/fromwire.o					\
	wire/onion_wiregen.o				\
	wire/peer_wiregen.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-route			\
$(BUILDDIR)/common/test/run-route-specific		\
$(BUILDDIR)/common/test/run-route-infloop:		\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/dijkstra.o				\
	common/fp16.o					\
	common/gossmap.o				\
	common/node_id.o				\
	common/pseudorand.o				\
	common/randbytes.o				\
	common/route.o					\
        common/gossip_store_wiregen.o			\
	wire/fromwire.o					\
	wire/peer_wiregen.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-gossmap_local:		\
	$(addprefix $(BUILDDIR)/,			\
	common/base32.o					\
	common/wireaddr.o				\
	wire/fromwire.o					\
	wire/peer_wiregen.o				\
	wire/tlvstream.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-gossmap_canned:		\
	$(addprefix $(BUILDDIR)/,			\
	common/base32.o					\
	common/wireaddr.o				\
	wire/fromwire.o					\
	wire/peer_wiregen.o				\
	wire/tlvstream.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-bolt12_merkle:		\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/bigsize.o				\
	common/base32.o					\
	common/bech32.o					\
	common/bech32_util.o				\
	common/bolt12.o					\
	common/node_id.o				\
	common/wireaddr.o				\
	wire/bolt12_wiregen.o				\
	wire/fromwire.o					\
	wire/tlvstream.o				\
	wire/peer_wiregen.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-bolt12_merkle-partial:	\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/bigsize.o				\
	common/base32.o					\
	common/bech32.o					\
	common/bech32_util.o				\
	common/bolt12.o					\
	common/node_id.o				\
	common/wireaddr.o				\
	wire/bolt12_wiregen.o				\
	wire/fromwire.o					\
	wire/tlvstream.o				\
	wire/peer_wiregen.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-bolt12-format-string-test:	\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/bigsize.o				\
	common/base32.o					\
	common/bech32.o					\
	common/bech32_util.o				\
	common/bolt12.o					\
	common/node_id.o				\
	wire/bolt12_wiregen.o				\
	wire/tlvstream.o				\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-bolt12_merkle-json:		\
	$(addprefix $(BUILDDIR)/,			\
	common/base32.o					\
	common/wireaddr.o				\
	)

$(BUILDDIR)/common/test/run-bolt12_proof		\
$(BUILDDIR)/common/test/run-bolt12_proof_vectors:	\
	$(addprefix $(BUILDDIR)/,			\
	common/bolt12.o					\
	common/bigsize.o				\
	common/amount.o					\
	common/sciddir_or_pubkey.o			\
	wire/bolt12_wiregen.o				\
	wire/onion_wiregen.o				\
	wire/tlvstream.o				\
	wire/fromwire.o					\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-version:			\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o                                 \
	wire/fromwire.o					\
	wire/towire.o					\
	)


$(BUILDDIR)/common/test/run-splice_script:		\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/node_id.o				\
	common/bech32.o					\
	common/splice_script.o				\
	common/wireaddr.o				\
	common/base32.o					\
	wire/fromwire.o					\
	wire/towire.o					\
	)


$(BUILDDIR)/common/test/run-trace:			\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o                                 \
	common/memleak.o				\
	common/pseudorand.o				\
	common/randbytes.o				\
	common/trace.o					\
	wire/fromwire.o					\
	wire/towire.o					\
	)

$(BUILDDIR)/common/test/run-mkdatastorekey:		\
	$(addprefix $(BUILDDIR)/,			\
	common/pseudorand.o				\
	)

$(BUILDDIR)/common/test/run-htable:			\
	$(addprefix $(BUILDDIR)/,			\
	common/randbytes.o				\
	common/pseudorand.o				\
	)

$(BUILDDIR)/common/test/run-shutdown_scriptpubkey:	\
	$(addprefix $(BUILDDIR)/,			\
	wire/towire.o					\
	wire/fromwire.o					\
	)

$(BUILDDIR)/common/test/run-wireaddr:			\
	$(addprefix $(BUILDDIR)/,			\
	wire/towire.o					\
	wire/fromwire.o					\
	)

$(BUILDDIR)/common/test/run-jsonrpc_io:			\
	$(addprefix $(BUILDDIR)/,			\
	common/json_parse_simple.o			\
	)

$(BUILDDIR)/common/test/run-close_tx:			\
	$(addprefix $(BUILDDIR)/,			\
	common/amount.o					\
	common/close_tx.o				\
	common/permute_tx.o				\
	common/psbt_keypath.o			\
	common/pseudorand.o				\
	wire/fromwire.o					\
	wire/towire.o					\
	)

check-units: $(COMMON_TEST_PROGRAMS:%=unittest/%)

obsclean::
	$(RM) common/test/*.o

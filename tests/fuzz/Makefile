LIBFUZZ_SRC := tests/fuzz/libfuzz.c
LIBFUZZ_HEADERS := $(LIBFUZZ_SRC:.c=.h)
LIBFUZZ_OBJS := $(LIBFUZZ_SRC:.c=.o)

tests/fuzz/fuzz-connectd-handshake-act*.o: tests/fuzz/connectd_handshake.h
tests/fuzz/fuzz-ripemd160: LDLIBS += -lcrypto
tests/fuzz/fuzz-sha256: LDLIBS += -lcrypto
tests/fuzz/fuzz-wire-*.o: tests/fuzz/wire.h

FUZZ_TARGETS_SRC := $(wildcard tests/fuzz/fuzz-*.c)
FUZZ_TARGETS_OBJS := $(FUZZ_TARGETS_SRC:.c=.o)
FUZZ_TARGETS_BIN := $(FUZZ_TARGETS_SRC:.c=)

FUZZ_COMMON_OBJS := \
	common/amount.o					\
	common/addr.o					\
	common/autodata.o				\
	common/base32.o					\
	common/base64.o					\
	common/bech32.o					\
	common/bech32_util.o				\
	common/bip32.o					\
	common/bigsize.o				\
	common/blockheight_states.o			\
	common/bolt11.o					\
	common/channel_config.o				\
	common/close_tx.o				\
	common/configdir.o				\
	common/configvar.o				\
	common/channel_id.o				\
	common/channel_type.o				\
	common/cryptomsg.o				\
	common/daemon.o					\
	common/daemon_conn.o				\
	common/derive_basepoints.o			\
	common/descriptor_checksum.o			\
	common/features.o				\
	common/fee_states.o				\
	common/hash_u5.o				\
	common/hsm_encryption.o				\
	common/htlc_state.o				\
	common/permute_tx.o				\
	common/initial_channel.o			\
	common/initial_commit_tx.o			\
	common/key_derive.o				\
	common/keyset.o					\
	common/msg_queue.o				\
	common/memleak.o				\
	common/node_id.o				\
	common/psbt_keypath.o				\
	common/wireaddr.o				\
	common/setup.o					\
	common/status.o					\
	common/status_wire.o				\
	common/status_wiregen.o				\
	common/type_to_string.o				\
	common/utils.o					\
	common/version.o				\
	wire/fromwire.o					\
	wire/onion_wiregen.o				\
	wire/peer_wire.o				\
	wire/peer_wiregen.o				\
	wire/channel_type_wiregen.o			\
	wire/tlvstream.o				\
	wire/towire.o					\
	wire/wire_io.o					\
	wire/wire_sync.o

$(FUZZ_TARGETS_OBJS): $(COMMON_HEADERS) $(WIRE_HEADERS) $(COMMON_SRC)
$(FUZZ_TARGETS_BIN): $(LIBFUZZ_OBJS) $(FUZZ_COMMON_OBJS) $(BITCOIN_OBJS)

ALL_C_SOURCES += $(FUZZ_TARGETS_SRC) $(LIBFUZZ_SRC)
ALL_FUZZ_TARGETS += $(FUZZ_TARGETS_BIN)

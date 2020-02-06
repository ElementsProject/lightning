#! /usr/bin/make

# Designed to be run at the top
rmthsmd-wrongdir:
	$(MAKE) -C ../.. lightningd/hsm-all

default: rmthsmd-all

LIGHTNINGD_RMTHSM_SRC := contrib/remote_hsmd/hsmd.c	\
	contrib/remote_hsmd/gen_hsm_wire.c \
	contrib/remote_hsmd/remotesigner.pb.cc \
	contrib/remote_hsmd/remotesigner.grpc.pb.cc \
	contrib/remote_hsmd/dump.cc \
	contrib/remote_hsmd/proxy.cc
LIGHTNINGD_RMTHSM_HEADERS := contrib/remote_hsmd/gen_hsm_wire.h \
	contrib/remote_hsmd/remotesigner.pb.h \
	contrib/remote_hsmd/remotesigner.grpc.pb.h
LIGHTNINGD_RMTHSM_CCOBJS := $(LIGHTNINGD_RMTHSM_SRC:.cc=.o)
LIGHTNINGD_RMTHSM_OBJS := $(LIGHTNINGD_RMTHSM_CCOBJS:.c=.o)

HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)
CXX = g++
CXXFLAGS += -std=c++11 \
	-I. \
	-Iccan \
	-Iexternal/libwally-core/include \
	-Iexternal/libwally-core/src/secp256k1/include \
	-g
PROTOC = protoc
GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`
PROTOS_PATH = contrib/remote_hsmd

# Common source we use.
RMTHSMD_COMMON_OBJS :=				\
	common/amount.o				\
	common/bigsize.o			\
	common/bip32.o				\
	common/daemon.o				\
	common/daemon_conn.o			\
	common/derive_basepoints.o		\
	common/funding_tx.o			\
	common/gen_status_wire.o		\
	common/hash_u5.o			\
	common/key_derive.o			\
	common/memleak.o			\
	common/msg_queue.o			\
	common/node_id.o			\
	common/permute_tx.o			\
	common/status.o				\
	common/status_wire.o			\
	common/subdaemon.o			\
	common/type_to_string.o			\
	common/utils.o				\
	common/utxo.o				\
	common/version.o			\
	common/withdraw_tx.o

# For checking
LIGHTNINGD_RMTHSM_ALLSRC_NOGEN := $(filter-out contrib/remote_hsmd/gen_%, $(LIGHTNINGD_RMTHSM_SRC) $(LIGHTNINGD_RMTHSM_SRC))
LIGHTNINGD_RMTHSM_ALLHEADERS_NOGEN := $(filter-out contrib/remote_hsmd/gen_%, $(LIGHTNINGD_RMTHSM_HEADERS))

$(LIGHTNINGD_RMTHSM_OBJS): $(LIGHTNINGD_HEADERS)

# Make sure these depend on everything.
ALL_OBJS += $(LIGHTNINGD_RMTHSM_OBJS)
ALL_PROGRAMS += lightningd/remote_hsmd
ALL_GEN_HEADERS += contrib/remote_hsmd/gen_hsm_wire.h
ALL_GEN_HEADERS += contrib/remote_hsmd/remotesigner.pb.h contrib/remote_hsmd/remotesigner.grpc.pb.h

rmthsmd-all: lightningd/remote_hsmd

lightningd/remote_hsmd: $(LIGHTNINGD_RMTHSM_OBJS) $(LIGHTNINGD_LIB_OBJS) $(RMTHSMD_COMMON_OBJS) $(BITCOIN_OBJS) $(WIRE_OBJS)

contrib/remote_hsmd/remotesigner.pb.o: $(ALL_GEN_HEADERS)

contrib/remote_hsmd/remotesigner.grpc.pb.o contrib/remote_hsmd/remotesigner.pb.o contrib/remote_hsmd/proxy.o contrib/remote_hsmd/dump.o : CPPFLAGS +=  $(CMNFLAGS) `pkg-config --cflags protobuf grpc`
lightningd/remote_hsmd: LDLIBS += -L/usr/local/lib \
	`pkg-config --libs protobuf grpc++`\
	-pthread\
	-Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
	-ldl
lightningd/remote_hsmd: LDLIBS += -lstdc++

contrib/remote_hsmd/gen_hsm_wire.h: $(WIRE_GEN) contrib/remote_hsmd/hsm_wire.csv
	$(WIRE_GEN) --page header $@ hsm_wire_type < contrib/remote_hsmd/hsm_wire.csv > $@

contrib/remote_hsmd/gen_hsm_wire.c: $(WIRE_GEN) contrib/remote_hsmd/hsm_wire.csv
	$(WIRE_GEN) --page impl ${@:.c=.h} hsm_wire_type < contrib/remote_hsmd/hsm_wire.csv > $@

check-source: $(LIGHTNINGD_RMTHSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_RMTHSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_RMTHSM_SRC:%=bolt-check/%)

check-whitespace: $(LIGHTNINGD_RMTHSM_ALLSRC_NOGEN:%=check-whitespace/%) $(LIGHTNINGD_RMTHSM_ALLHEADERS_NOGEN:%=check-whitespace/%)

clean: lightningd/rmthsm-clean

lightningd/rmthsm-clean:
	$(RM) $(LIGHTNINGD_RMTHSM_OBJS) contrib/remote_hsmd/gen_*
	$(RM) contrib/remote_hsmd/*.pb.cc contrib/remote_hsmd/*.pb.h

.PRECIOUS: %.grpc.pb.cc
%.grpc.pb.cc: %.proto
	$(PROTOC) -I $(PROTOS_PATH) --grpc_out=contrib/remote_hsmd --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

.PRECIOUS: %.pb.cc
%.pb.cc: %.proto
	$(PROTOC) -I $(PROTOS_PATH) --cpp_out=contrib/remote_hsmd $<

-include contrib/remote_hsmd/test/Makefile

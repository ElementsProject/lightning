cln-rpc-wrongdir:
	$(MAKE) -C .. cln-rpc-all

CLN_RPC_GENALL = cln-rpc/src/model.rs cln-rpc/src/notifications.rs cln-rpc/src/hooks.rs
CLN_RPC_SOURCES = $(shell find cln-rpc -name *.rs) ${CLN_RPC_GENALL}
DEFAULT_TARGETS += $(CLN_RPC_GENALL)

MSGGEN_GENALL += $(CLN_RPC_GENALL)

ifneq ($(RUST),0)
CLN_RPC_EXAMPLES := $(RUST_TARGET_DIR)/examples/cln-rpc-getinfo
DEFAULT_TARGETS += $(CLN_RPC_EXAMPLES)

$(RUST_TARGET_DIR)/examples/cln-rpc-getinfo: ${CLN_RPC_SOURCES} cln-rpc/examples/getinfo.rs
	$(CARGO) build ${CARGO_OPTS} --example cln-rpc-getinfo
endif

cln-rpc-all: ${CLN_RPC_GENALL} ${CLN_RPC_EXAMPLES}

cln-rpc-wrongdir:
	$(MAKE) -C .. cln-rpc-all

CLN_RPC_EXAMPLES := target/${RUST_PROFILE}/examples/cln-rpc-getinfo
CLN_RPC_GENALL = cln-rpc/src/model.rs cln-rpc/src/notifications.rs
CLN_RPC_SOURCES = $(shell find cln-rpc -name *.rs) ${CLN_RPC_GENALL}
DEFAULT_TARGETS += $(CLN_RPC_EXAMPLES) $(CLN_RPC_GENALL)

MSGGEN_GENALL += $(CLN_RPC_GENALL)

target/${RUST_PROFILE}/examples/cln-rpc-getinfo: ${CLN_RPC_SOURCES} cln-rpc/examples/getinfo.rs
	cargo build ${CARGO_OPTS} --example cln-rpc-getinfo

target/${RUST_PROFILE}/examples/cln-plugin-startup: ${CLN_RPC_SOURCES} plugins/examples/cln-plugin-startup.rs
	cargo build ${CARGO_OPTS} --example cln-plugin-startup

target/${RUST_PROFILE}/examples/cln-plugin-reentrant: ${CLN_RPC_SOURCES} plugins/examples/cln-plugin-reentrant.rs
	cargo build ${CARGO_OPTS} --example cln-plugin-reentrant


cln-rpc-all: ${CLN_RPC_GEN_ALL} ${CLN_RPC_EXAMPLES}

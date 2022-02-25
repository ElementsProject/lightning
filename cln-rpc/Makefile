cln-rpc-wrongdir:
	$(MAKE) -C .. cln-rpc-all

CLN_RPC_EXAMPLES := target/debug/examples/cln-rpc-getinfo
CLN_RPC_GENALL = cln-rpc/src/model.rs
CLN_RPC_SOURCES = $(shell find cln-rpc -name *.rs) ${CLN_RPC_GENALL}
JSON_SCHEMA = doc/schemas/*.schema.json
DEFAULT_TARGETS += $(CLN_RPC_EXAMPLES) $(CLN_RPC_GENALL)

$(CLN_RPC_GENALL): $(JSON_SCHEMA)
	PYTHONPATH=contrib/msggen python3 contrib/msggen/msggen/__main__.py

target/debug/examples/cln-rpc-getinfo: $(shell find cln-rpc -name *.rs)
	cargo build ${CARGO_OPTS} --example cln-rpc-getinfo

cln-rpc-all: ${CLN_RPC_GEN_ALL} ${CLN_RPC_EXAMPLES}

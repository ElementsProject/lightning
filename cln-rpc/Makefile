CLN_RPC_EXAMPLES += target/debug/examples/cln-rpc-getinfo

cln-rpc-wrongdir:
	$(MAKE) -C .. cln-rpc-all

CLN_RPC_RESPONSES = \
	cln-rpc/src/responses/getinfo.rs

CLN_RPC_REQUESTS = \
	cln-rpc/src/requests/getinfo.rs

CLN_RPC_GENALL = ${CLN_RPC_REQUESTS} ${CLN_RPC_RESPONSES}

CLN_RPC_SOURCES = $(shell find cln-rpc -name *.rs) ${CLN_RPC_GENALL}

$(CLN_RPC_RESPONSES): cln-rpc/src/responses/%.rs: doc/schemas/%.schema.json tools/gen-rust-rpc.py
	tools/gen-rust-rpc.py $< $@

$(CLN_RPC_REQUESTS): cln-rpc/src/requests/%.rs: doc/schemas/%.request.json tools/gen-rust-rpc.py
	tools/gen-rust-rpc.py $< $@

target/debug/cln-rpc-getinfo: $(shell find cln-rpc -name *.rs)
	cargo build --example cln-rpc-getinfo

cln-rpc-all: ${CLN_RPC_RESPONSES} ${CLN_RPC_REQUESTS} ${CLN_RPC_EXAMPLES}

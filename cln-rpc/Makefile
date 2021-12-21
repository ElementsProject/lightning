CLN_RPC_EXAMPLES += target/debug/examples/cln-rpc-getinfo

cln-rpc-wrongdir:
	$(MAKE) -C .. cln-rpc-all

CLN_RPC_RESPONSES =

$(CLN_RPC_RESPONSES): cln-rpc/src/responses/%.rs: doc/schemas/%.schema.json tools/gen-rust-rpc.py
	tools/gen-rust-rpc.py $< $@


cln-rpc-all: ${CLN_RPC_RESPONSES}

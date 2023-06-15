cln-grpc-wrongdir:
	$(MAKE) -C .. cln-grpc-all

CLN_GRPC_EXAMPLES :=
CLN_GRPC_GENALL = cln-grpc/proto/node.proto \
	cln-grpc/src/convert.rs \
	cln-grpc/src/server.rs

DEFAULT_TARGETS += $(CLN_GRPC_EXAMPLES) $(CLN_GRPC_GENALL)

MSGGEN_GENALL += $(CLN_GRPC_GENALL) contrib/pyln-testing/pyln/testing/grpc2py.py

cln-grpc-all: ${CLN_GRPC_GENALL} ${CLN_GRPC_EXAMPLES}

cln-grpc-wrongdir:
	$(MAKE) -C .. cln-grpc-all

CLN_GRPC_EXAMPLES :=
CLN_GRPC_GENALL = cln-grpc/proto/node.proto \
	cln-grpc/src/convert.rs

DEFAULT_TARGETS += $(CLN_GRPC_EXAMPLES) $(CLN_GRPC_GENALL)

$(CLN_GRPC_GENALL): $(JSON_SCHEMA)
	PYTHONPATH=contrib/msggen python3 contrib/msggen/msggen/__main__.py

cln-grpc-all: ${CLN_GRPC_GENALL} ${CLN_GRPC_EXAMPLES}

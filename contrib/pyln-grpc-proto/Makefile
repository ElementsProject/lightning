#!/usr/bin/make
.PHONY: clean protos

PKG=grpc
VERSION := $(shell grep 'version' pyproject.toml | head -n1 | cut -d'"' -f2)

PROTOS = \
	pyln/grpc/node_pb2.py \
	pyln/grpc/node_pb2.pyi \
	pyln/grpc/node_pb2_grpc.py \
	pyln/grpc/primitives_pb2.py \
	pyln/grpc/primitives_pb2.pyi

PROTOSRC = \
	../../cln-grpc/proto/node.proto \
	../../cln-grpc/proto/primitives.proto

${PROTOS} &: ${PROTOSRC}
	uv run \
	  -m grpc_tools.protoc \
	  -I ../../cln-grpc/proto \
	  ../../cln-grpc/proto/node.proto \
	  --python_out=pyln/grpc \
	  --grpc_python_out=pyln/grpc \
          --mypy_out=pyln/grpc \
	  --experimental_allow_proto3_optional

	python \
	  -m grpc_tools.protoc \
	  -I ../../cln-grpc/proto \
	  ../../cln-grpc/proto/primitives.proto \
	  --python_out=pyln/grpc \
          --mypy_out=pyln/grpc \
	  --experimental_allow_proto3_optional


	# The package logic in grpc is very inflexible, let's rewrite
	# the references between the generated sources
	sed -i 's/import primitives_pb2 as primitives__pb2/from pyln.grpc import primitives_pb2 as primitives__pb2/g' pyln/grpc/node_pb2.py
	sed -i 's/import primitives_pb2/from pyln.grpc import primitives_pb2/g' pyln/grpc/node_pb2.pyi
	sed -i 's/import node_pb2 as node__pb2/from pyln.grpc import node_pb2 as node__pb2/g' pyln/grpc/node_pb2_grpc.py

protos: ${PROTOS}

clean:
	rm -f ${PROTOS}

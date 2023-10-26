#!/usr/bin/make
PKG=grpc
VERSION := $(shell poetry version -s)

PROTOS = \
	pyln/grpc/node_pb2.py \
	pyln/grpc/node_pb2_grpc.py \
	pyln/grpc/primitives_pb2.py \

PROTOSRC = \
	../../cln-grpc/proto/node.proto \
	../../cln-grpc/proto/primitives.proto

${PROTOS} &: ${PROTOSRC}
	python \
	  -m grpc_tools.protoc \
	  -I ../../cln-grpc/proto \
	  ../../cln-grpc/proto/node.proto \
	  --python_out=pyln/grpc \
	  --grpc_python_out=pyln/grpc \
	  --experimental_allow_proto3_optional

	python \
	  -m grpc_tools.protoc \
	  -I ../../cln-grpc/proto \
	  ../../cln-grpc/proto/primitives.proto \
	  --python_out=pyln/grpc \
	  --experimental_allow_proto3_optional


	# The package logic in grpc is very inflexible, let's rewrite
	# the references between the generated sources
	sed -i 's/import primitives_pb2 as primitives__pb2/from pyln.grpc import primitives_pb2 as primitives__pb2/g' pyln/grpc/node_pb2.py
	sed -i 's/import node_pb2 as node__pb2/from pyln.grpc import node_pb2 as node__pb2/g' pyln/grpc/node_pb2_grpc.py

# Having versions in two places sucks, but so does every other option :(
# See https://github.com/python-poetry/poetry/issues/144
upgrade-version:
	if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	poetry version $(NEW_VERSION)
	sed 's/^__version__ = .*/__version__ = "$(NEW_VERSION)"/' < pyln/$(PKG)/__init__.py > pyln/$(PKG)/__init__.py.new && mv pyln/$(PKG)/__init__.py.new pyln/$(PKG)/__init__.py

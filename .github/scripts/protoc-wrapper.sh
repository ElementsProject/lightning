#!/bin/sh
# Wrapper script that delegates to the protoc bundled with grpcio-tools.
# This ensures the protoc compiler version matches the Python protobuf
# runtime and gencode versions exactly.
exec uv run python -m grpc_tools.protoc "$@"

# MsgGen - Generating language bindings and docs from schemas and wire descriptions

MsgGen is a collection of tools that are used to parse schemas and
(eventually) protocol wire CSVs into an intermediate representation in
memory, and then generate language specific bindings and
documentation from it.


The dependency graph looks like this:


```dot
digraph {
  "JSON-RPC Schemas" -> "msggen model";
  "msggen model" -> "grpc proto file";
  "msggen model" -> "Rust From<JsonRpc> Converters";
  "grpc proto file" -> "Rust grpc bindings"
  "Rust grpc bindings" -> "cln-grpc";
  "Rust From<JsonRpc> Converters" -> "cln-grpc";
  "msggen model" -> "Rust JSON-RPC structs";
  "Rust JSON-RPC structs" -> "cln-rpc";
}
```

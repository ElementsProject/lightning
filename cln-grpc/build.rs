fn main() {
    let builder = tonic_prost_build::configure();
    builder
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/node.proto"], &["proto"])
        .unwrap();
}

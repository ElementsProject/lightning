fn main() {
    let builder = tonic_build::configure();
    builder
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["proto/node.proto"], &["proto"])
        .unwrap();
}

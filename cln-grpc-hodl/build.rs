fn main() {
    let builder = tonic_build::configure();
    builder
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["proto/hodl.proto"], &["proto"])
        .unwrap();
}

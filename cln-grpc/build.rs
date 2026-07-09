fn main() {
    let builder = tonic_prost_build::configure();
    let protoc = protoc_bin_vendored::protoc_bin_path().unwrap();
    unsafe { std::env::set_var("PROTOC", protoc) };
    builder
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/node.proto"], &["proto"])
        .unwrap();
}

fn main() {
    tonic_build::compile_protos("proto/node.proto").unwrap();
}

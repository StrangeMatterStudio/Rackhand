fn main() -> std::io::Result<()> {
    let protos = ["common", "join", "probe", "peer", "operator", "tunnel"].map(|p| format!("proto/{p}.proto"));
    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    let mut config = prost_build::Config::new();
    config.btree_map(["."]); // deterministic encoding of map fields (golden files)
    // Ubuntu 22.04's protoc (3.12) needs this flag for proto3 `optional`; newer versions accept and ignore it.
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.compile_protos(&protos, &["proto"])
}

fn main() {
    // If the builder set DEEZNS_SOCKET_PATH in the environment, forward it
    // verbatim.  Otherwise fall back to a sensible default.
    //
    // `cargo:rustc-env=K=V` makes `env!("K")` resolve to V at compile time
    // for every crate in this package (bin + lib).
    let path = std::env::var("DEEZNS_SOCKET_PATH")
        .unwrap_or_else(|_| "/run/deezns/resolve.sock".to_string());

    println!("cargo:rustc-env=DEEZNS_SOCKET_PATH={path}");

    // Re-run if the variable changes between builds.
    println!("cargo:rerun-if-env-changed=DEEZNS_SOCKET_PATH");
}

fn main() {
    // If the builder set DEEZNS_SOCKET_PATH in the environment, forward it
    // verbatim.  Otherwise fall back to a sensible default.
    //
    // The path is fixed at build time rather than read at runtime because
    // the NSS module has no way to be configured: glibc dlopen()s
    // libnss_deezns.so.2 into arbitrary processes and passes it only the
    // name being looked up.  nsswitch.conf carries no module settings, and
    // environment variables are unreliable there (unset for setuid programs
    // and system services).  Baking the path into the shared object, and the
    // same path into the daemon, is what keeps the two in agreement.
    //
    // `cargo:rustc-env=K=V` makes `env!("K")` resolve to V at compile time
    // for every crate in this package (bin + lib).
    let path = std::env::var("DEEZNS_SOCKET_PATH")
        .unwrap_or_else(|_| "/run/deezns/resolve.sock".to_string());

    println!("cargo:rustc-env=DEEZNS_SOCKET_PATH={path}");

    // Re-run if the variable changes between builds.
    println!("cargo:rerun-if-env-changed=DEEZNS_SOCKET_PATH");
}

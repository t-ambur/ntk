fn main() {
    if cfg!(feature = "with-libpcap") && cfg!(target_os = "windows") {
        if cfg!(target_arch = "x86_64") {
            println!("cargo:rustc-link-search=Npcap/Lib/x64");
        } else if cfg!(target_arch = "x86") {
            println!("cargo:rustc-link-search=Npcap/Lib");
        }
        println!("cargo:rustc-link-lib=Packet");
        // println!("cargo:rustc-link-lib=wpcap");
    }
}
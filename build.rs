fn main() {
    println!("cargo:rerun-if-changed=c_src/set_wifi_channel.c");
    
    cc::Build::new()
        .file("c_src/set_wifi_channel.c")
        .include("/usr/include/libnl3")
        .flag("-I/usr/include/libnl3")
        .compile("wifichannel");
    
    println!("cargo:rustc-link-lib=nl-3");
    println!("cargo:rustc-link-lib=nl-genl-3");
}
fn main() {
    println!("cargo:rerun-if-changed=c_src/set_wifi_channel.c");
    println!("cargo:rerun-if-changed=c_src/wifi_scan.c");
    println!("cargo:rerun-if-changed=c_src/wifi_scan.h");

    let libnl_include = "/usr/include/libnl3";

    cc::Build::new()
        .file("c_src/set_wifi_channel.c")
        .include(libnl_include)
        .compile("wifichannel");

    cc::Build::new()
        .file("c_src/wifi_scan.c")
        .include("c_src")
        .include(libnl_include)
        .compile("wifiscan");

    println!("cargo:rustc-link-lib=nl-3");
    println!("cargo:rustc-link-lib=nl-genl-3");
}

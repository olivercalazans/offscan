<h1 align="center"> OffScan </h1>

**OffScan** is a command-line tool developed in Rust for network exploration, device and service enumeration, and offensive security testing on Linux. It provides a compact, efficient interface for scanning, probing, and capturing network data, aimed at defenders and red‑teamers alike. What it can do:

<br>

- **Network Mapping**
- **Port Scanning**
- **Packet Flooding**
- **Protocol Tunneling test**

<br>


## Dependencies

This project uses **Cargo**, Rust's package manager and build system, to manage its Rust dependencies.  
If you don't have Cargo installed, follow the steps on the [official Rust installation page](https://www.rust-lang.org/tools/install).

All Rust dependencies are managed automatically by Cargo — no manual installation required.  
You can find them listed in the [Cargo.toml](https://github.com/olivercalazans/offscan/blob/main/Cargo.toml) file.

> [!IMPORTANT]
> In addition to Cargo-managed crates, this project requires some **system-level dependencies**:
>
> - `libpcap-dev` — required for network packet capture  
> - A C compiler and linker (e.g. `gcc` or `clang`) — required to build and link Rust binaries  
>
> Make sure these are installed before building.

> [!NOTE]
> The code is primarily designed for Linux systems, but it can also run on Windows via **WSL (Windows Subsystem for Linux)**.

<br>



## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

<h1 align="center"> OffScan </h1>

**OffScan** is a command-line tool developed in Rust for network exploration, device and service enumeration, and offensive security testing on Linux. It provides a compact, efficient interface for scanning, probing, and capturing network data, aimed at defenders and red‑teamers alike. What it can do:

<br>

<table align="center" style="width: 90%; border-collapse: collapse; margin-bottom: 20px;">
  <tr>
    <th style="width: 50%; text-align: center; padding: 10px; color: #58A6FF; font-size: 1.1em; border-bottom: 2px solid #30363D;">
      Offensive Tests
    </th>
    <th style="width: 50%; text-align: center; padding: 10px; color: #58A6FF; font-size: 1.1em; border-bottom: 2px solid #30363D;">
      Network Exploration
    </th>
  </tr>
  <tr>
    <td style="width:50%; vertical-align: top; padding: 15px; background-color: #0D1117; color: #C9D1D9; border-radius: 8px; height: 150px;">
      <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        <li><strong><em>Authentication Flooding</em></strong></li>
        <li><strong><em>Packet Flooding</em></strong></li>
        <li><strong><em>Protocol Tunneling test</em></strong></li>
      </ul>
    </td>
    <td style="width:50%; vertical-align: top; padding: 15px; background-color: #0D1117; color: #C9D1D9; border-radius: 8px; height: 150px;">
      <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        <li><strong><em>Banner Grabbing</em></strong></li>
        <li><strong><em>Network Mapping</em></strong></li>
        <li><strong><em>Port Scanning</em></strong></li>
        <li><strong><em>Wifi Mapping</em></strong></li>
      </ul>
    </td>
  </tr>
</table>



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

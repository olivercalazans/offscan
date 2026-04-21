<h1 align="center"> OffScan </h1>

**OffScan** is a command-line tool developed in Go for network exploration, device enumeration, and offensive security testing on Linux. It provides a compact, efficient interface for scanning, probing, and capturing network data, aimed at defenders and red‑teamers alike. What it can do:

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
        <li><strong><em>Deauthentication Attack</em></strong></li>
        <li><strong><em>Beacon Flooding</em></strong></li>
        <li><strong><em>Ping Flooding</em></strong></li>
        <li><strong><em>TCP Flooding</em></strong></li>
      </ul>
    </td>
    <td style="width:50%; vertical-align: top; padding: 15px; background-color: #0D1117; color: #C9D1D9; border-radius: 8px; height: 150px;">
      <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        <li><strong><em>Network Mapping</em></strong></li>
        <li><strong><em>Port Scanning</em></strong></li>
        <li><strong><em>Wifi Mapping</em></strong></li>
      </ul>
    </td>
  </tr>
</table>

<br>

## Dependencies

This project uses **Go modules** to manage its dependencies.  
If you don't have Go installed, follow the instructions on the [official Go website](https://go.dev/dl/).

All Go dependencies are managed automatically via the `go.mod` file – no manual installation required.  
You can find them listed in the [`go.mod`](https://github.com/olivercalazans/offscan/blob/main/go.mod) file.

However, because OffScan relies on libpcap for low-level network operations, **you must install the libpcap development headers** on your system before compiling.
```bash
sudo apt install libpcap-dev
```

<br>

> [!WARNING]
> The code is primarily designed for Linux systems. While it can run on Windows via WSL (Windows Subsystem for Linux), network interface limitations in WSL may restrict functionality and cause unreliable behavior.

<br>

## Legal and ethical use warning
> [!CAUTION] 
> **This is an offensive security tool for authorized testing and education.**
> 
> **PROHIBITED:**
> - Testing without **explicit written permission**
> - Any illegal activity
> - Unauthorized access or disruption
> 
> **YOU AGREE TO:**
> 1. Use only with **proper authorization**
> 2. Comply with **all applicable laws**
> 3. Assume **full liability** for misuse
> 
> **The Developer assumes NO liability. See [LEGAL.md](LEGAL.md) for full policy.**

<br>

## License
This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

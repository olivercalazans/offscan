<h1 align="center"> OffScan </h1>

<div align="center">
  <img src="https://img.shields.io/badge/tool-offsec-ff0000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/license-GPL%20v3-F0B400?style=for-the-badge" />
</div>

<br>

**OffScan** is a Go-based command-line tool for Wi-Fi penetration testing, offensive security assessments, and active attacks on Linux. It provides a compact, efficient interface for scanning, probing, and capturing network traffic, designed for both defenders and red-teamers. What it can do:

<br>


<table align="center" style="width: 90%; border-collapse: collapse; margin-bottom: 20px;">
  <tr>
    <th style="width: 50%; text-align: center; padding: 10px; color: #58A6FF; font-size: 1.1em; border-bottom: 2px solid #30363D;">
      Attacks
    </th>
    <th style="width: 50%; text-align: center; padding: 10px; color: #58A6FF; font-size: 1.1em; border-bottom: 2px solid #30363D;">
      Scannings
    </th>
  </tr>
  <tr>
    <td style="width:50%; vertical-align: top; padding: 15px; background-color: #0D1117; color: #C9D1D9; border-radius: 8px; height: 150px;">
      <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        <li><strong><em>ARP Poisoning Attack</em></strong></li>
        <li><strong><em>Beacon Flooding</em></strong></li>
        <li><strong><em>Deauthentication Attack</em></strong></li>
        <li><strong><em>Pixie Dust Attack</em></strong></li>
      </ul>
    </td>
    <td style="width:50%; vertical-align: top; padding: 15px; background-color: #0D1117; color: #C9D1D9; border-radius: 8px; height: 150px;">
      <ul style="list-style-type: none; padding-left: 0; margin: 0;">
        <li><strong><em>Layer 3 Host Discovery</em></strong></li>
        <li><strong><em>Layer 2 Host Discovery</em></strong></li>
        <li><strong><em>Wi-Fi/AP Mapping</em></strong></li>
      </ul>
    </td>
  </tr>

</table>

<br>

## Dependencies

This project uses **Go modules** to manage its dependencies.  
If you don't have Go installed, follow the instructions on the [official Go website](https://go.dev/dl/) to install the **latest version**.

All Go dependencies are managed automatically via the `go.mod` file – no manual installation required.  
You can find them listed in the [`go.mod`](https://github.com/olivercalazans/offscan/blob/main/go.mod) file.

However, because OffScan relies on `libpcap` for low-level network operations and `iw` command, **you must install both** on your system before compiling.
```bash
sudo apt install libpcap-dev iw
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

<h1 align="center"> OffScan </h1>

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

## Requirements & Compatibility

### Hardware Requirements
- Wireless network interface supporting **Monitor Mode** and **Packet Injection** (e.g., Atheros AR9271, Realtek RTL8812AU, or equivalent chipset).

### Software & Operating System
- **Operating System:** Native Linux (Debian, Ubuntu, Kali, Arch, Raspberry Pi OS, etc.)
- **Go Compiler:** Version 1.25.0 or higher ([official Go website](https://go.dev/dl/))

> [!WARNING]
> **Linux Only:**
>
> OffScan interacts directly with low-level network sockets and wireless PHY drivers for monitor mode and raw 802.11 frame injection. Therefore, **it only works on Linux**. It will **not** function on Windows, macOS, WSL (Windows Subsystem for Linux), or standard virtualized network adapters.

<br>

## Installation & Build

Clone the repository and compile the binary using Go:

```bash
# Clone the repository
git clone https://github.com/olivercalazans/offscan.git
cd offscan

# Option A: Build a fully static binary (Recommended for portability)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o offscan main.go

# Option B: Standard Go build
go build -o offscan main.go

# Run the CLI
sudo ./offscan --help
```

<br>

## Basic Usage
```Bash
# Display help and available commands
sudo ./offscan --help

# Activate monitor mode
sudo ./offscan ifmode -i <IFACE> --mon

# Example: Run a Wi-Fi AP scan
sudo ./offscan wmap -i <IFACE>

# Deactivate monitor mode
sudo ./offscan ifmode -i <IFACE> --man

# Example: Run a Deauthentication Attack
sudo ./offscan deauth -i <IFACE> -b <BSSID> -t <TARGET_MAC> -c <CHANNEL>
```


<br>

## Acknowledgments & Credits
* **[Aircrack-ng](https://www.aircrack-ng.org/):** Inspired the 802.11 monitor mode frame construction, raw packet injection mechanisms, and deauthentication logic.
* **[Nmap](https://nmap.org/):** Inspired the Layer 2 (ARP) and Layer 3 host discovery algorithms and packet crafting design patterns.
* **[Pixiewps](https://github.com/wiire-a/pixiewps):** Reference logic for the offline WPS Pixie Dust attack implementation.

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

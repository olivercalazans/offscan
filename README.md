<h1 align="center"> OffScan </h1>

**OffScan** is a Go-based command-line tool for Wi-Fi penetration testing, offensive security assessments, and active attacks on Linux. It provides a compact, efficient interface for scanning, probing, and capturing network traffic, designed for both defenders and red-teamers. What it can do:

<br>

<p align="center"><strong>
Host Discovery -
Wifi Mapping -
ARP Poisoning -
Beacon Flooding -
Deauthentication Attack
</strong></p>

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

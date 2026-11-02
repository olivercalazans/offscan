# Hardware Compatibility & Test Results

This document records the exact hardware configurations tested with this Wi-Fi pentesting tool, along with their outcomes, operational environments, and technical root causes for failures.

<br>

## Quick Compatibility Matrix

| Device Name | Chipset / Source | Release Year | Architecture | Status | Core Functionality | Notes |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| Qualcomm Atheros AR9485 | Atheros AR9485 | ~2011/2012 | x86_64 | 🟢 **PASSED** | Full Support | Monitor mode, packet injection, and handshake capture work flawlessly. |
| Ralink RT5390 | Ralink RT5390 | ~2011 | i686 (32-bit) | 🟢 **PASSED** | Full Support | Fully functional under legacy 32-bit environments using native drivers. |
| Broadcom CYW43438 | CYW43438 (RPi Zero W) | 2017 | armv6l | 🔴 **FAILED** | None | Fails on Raspbian and Kali 2025.2 due to firmware lock (`DEL_INTERFACE: errno 524`). |

<br>


## Detailed Test Environments & Hardware Reports

### Environment 1: Modern x86_64 Host
* **OS:** Debian GNU/Linux 13 (trixie)
* **Kernel Version:** 6.12.113+deb13-amd64
* **Architecture:** x86_64
* **CPU:** Intel(R) Core(TM) i5-3230M @ 2.60GHz

#### Tested Device: Qualcomm Atheros AR9485 (Internal PCIe)
* **Chipset:** Qualcomm Atheros AR9485 Wireless Network Adapter
* **Hardware Release Year:** ~2011/2012
* **Bands:** 2.4 GHz (802.11b/g/n)
* **Driver:** `ath9k` (Native Linux Kernel Driver)
* **Status:** 🟢 **PASSED**
* **Script Performance:** The tool performed all core automated tasks—including network sniffing, targeted deauthentication (deauth) attacks, and WPA/WPA2 handshake capturing—without any packet loss or interface freezes.
* **Notes:** Even though this is a legacy internal laptop card, the mature, open-source nature of the `ath9k` driver in modern Linux kernels ensures highly stable raw frame manipulation.

---

### Environment 2: Legacy 32-bit (i686) Host
* **OS:** Debian GNU/Linux 12 (bookworm)
* **Kernel Version:** 6.1.0-54-686-pae
* **Architecture:** i686 (32-bit)
* **CPU:** Intel(R) Pentium(R) P6200 @ 2.13GHz

#### Tested Device: Ralink RT5390 (Internal PCIe)
* **Chipset:** Ralink corp. RT5390 Wireless 802.11n 1T/1R PCIe
* **Hardware Release Year:** ~2011
* **Bands:** 2.4 GHz (802.11b/g/n)
* **Driver:** `rt2800pci` (Native Linux Kernel Driver)
* **Status:** 🟢 **PASSED**
* **Script Performance:** Fully functional. Despite running on a legacy 32-bit architecture, the script successfully initiated monitor mode and executed stable raw frame injection via the `rt2800pci` driver framework without kernel panics or interface hangs.

---

### Environment 3: Single-Board Computer (SBC) Host
* **OS Tested:** Raspbian GNU/Linux 13 (trixie) & Kali Linux 2025.2 (Final official release for this hardware architecture)
* **Kernel Version:** 6.18.50+rpt-rpi-v6 (and equivalents)
* **Architecture:** armv6l (32-bit ARM)
* **CPU:** ARMv6-compatible processor rev 7 (v6l) (Raspberry Pi Zero W)

#### Tested Device: Broadcom CYW43438 (Integrated Wireless)
* **Chipset:** Broadcom / Cypress CYW43438
* **Hardware Release Year:** 2017 (via Raspberry Pi Zero W launch)
* **Bands:** 2.4 GHz
* **Driver:** `brcmfmac` (Native Linux Kernel Driver)
* **Status:** 🔴 **FAILED**

##### Technical Analysis & Failure Root Cause:
* **Symptoms:** The script fails immediately on both Raspbian 13 and Kali Linux 2025.2 when attempting to switch the integrated wireless interface into monitor mode. Automated execution and tools like `airmon-ng` produce the exact kernel error: `DEL_INTERFACE: errno 524`.
* **Root Cause:** Testing across both operating systems confirms that the stock firmware shipped for the `brcmfmac` driver explicitly locks down raw 802.11 frame manipulation. Since Kali Linux 2025.2 is the final official release for the Raspberry Pi Zero W, subsequent out-of-the-box system configurations will not solve this hardware-level restriction.
* **Remediation Note:** To bypass this vendor lock, users must manually compile and flash a custom community-patched firmware (such as the *Nexmon* framework) to force hardware-level monitor mode support. Out-of-the-box deployment on this specific single-board computer is completely unsupported.

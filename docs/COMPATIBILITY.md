# Hardware Compatibility & Test Results

This document records the exact hardware configurations tested with this Wi-Fi pentesting tool, along with their outcomes, operational environments, and technical root causes for failures.

<br>

## Quick Compatibility Matrix

| Device Name | Chipset / Source | Release Year | Architecture | Status | Core Functionality | Notes |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| Qualcomm Atheros AR9485 | Atheros AR9485 | ~2011/2012 | x86_64 | 🟢 **PASSED** | Full Support | Monitor mode, packet injection, and handshake capture work flawlessly. |
| Ralink RT5390 | Ralink RT5390 | ~2011 | i686 (32-bit) | 🟢 **PASSED** | Full Support | Fully functional under legacy 32-bit environments using native drivers. |
| Intel Wireless 7265 | Intel 7265 (rev 61) | ~2014 | x86_64 | 🟢 **PASSED** | Full Support | Monitor mode, frame injection, and handshake capture function properly on modern kernel 6.12. |
| Intel Wireless 8260 | Intel Wireless 8260 (rev 3a) | ~2015 | x86_64 | 🟢 **PASSED** | Full Support | Tested on Xiaomi Mi Notebook Air 12.5; monitor mode and packet injection function flawlessly. |
| Realtek RTL8852AE | Realtek RTL8852AE | ~2020/2021 | x86_64 | 🟢 **PASSED** | Full Support | Monitor mode and frame injection function flawlessly under modern kernels. |
| Broadcom CYW43438 | CYW43438 (RPi Zero W) | 2017 | armv6l | 🟡 **PARTIAL** | Non-Monitor Only | Core scanning and raw packet manipulation fail, but generic internal utility features function. |
| Broadcom BCM43228 | Broadcom BCM43228 | ~2012 | x86_64 | 🟡 **PARTIAL** | Non-Monitor Only | Sub-interface hooks fail under proprietary drivers; tool features not requiring monitor mode work. |

<br>

## Detailed Test Environments & Hardware Reports

### Environment 1: Modern x86_64 Host
- **OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Version:** 6.12.113+deb13-amd64
- **Architecture:** x86_64
- **CPU:** Intel(R) Core(TM) i5-3230M @ 2.60GHz

#### Tested Device: Qualcomm Atheros AR9485 (Internal PCIe)
- **Chipset:** Qualcomm Atheros AR9485 Wireless Network Adapter
- **Hardware Release Year:** ~2011/2012
- **Bands:** 2.4 GHz (802.11b/g/n)
- **Driver:** `ath9k` (Native Linux Kernel Driver)
- **Status:** 🟢 **PASSED**
- **Notes:** Even though this is a legacy internal laptop card, the mature, open-source nature of the `ath9k` driver in modern Linux kernels ensures highly stable raw frame manipulation.

---

### Environment 2: Legacy 32-bit (i686) Host
- **OS:** Debian GNU/Linux 12 (bookworm)
- **Kernel Version:** 6.1.0-54-686-pae
- **Architecture:** i686 (32-bit)
- **CPU:** Intel(R) Pentium(R) P6200 @ 2.13GHz

#### Tested Device: Ralink RT5390 (Internal PCIe)
- **Chipset:** Ralink corp. RT5390 Wireless 802.11n 1T/1R PCIe
- **Hardware Release Year:** ~2011
- **Bands:** 2.4 GHz (802.11b/g/n)
- **Driver:** `rt2800pci` (Native Linux Kernel Driver)
- **Status:** 🟢 **PASSED**

---

### Environment 3: AMD x86_64 Host
- **OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Version:** 6.12.113+deb13-amd64
- **Architecture:** x86_64
- **CPU:** AMD PRO A10-8700B R6, 10 Compute Cores 4C+6G @ 1.80GHz

#### Tested Device: Intel Corporation Wireless 7265 (Internal PCIe)
- **Chipset:** Intel Corporation Wireless 7265 (rev 61)
- **Hardware Release Year:** ~2014
- **Bands:** Dual-band 2.4 GHz / 5 GHz (802.11a/b/g/n/ac)
- **Driver:** `iwlwifi` (Native Linux Kernel Driver)
- **Status:** 🟢 **PASSED**

---

### Environment 4: Ultra-portable Intel x86_64 Host (Xiaomi Laptop)
- **OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Version:** 6.12.113+deb13-amd64
- **Architecture:** x86_64
- **CPU:** Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz
- **Device Model:** Xiaomi Mi Notebook Air 12.5

#### Tested Device: Intel Corporation Wireless 8260 (Internal PCIe)
- **Chipset:** Intel Corporation Wireless 8260 (rev 3a)
- **Hardware Release Year:** ~2015
- **Bands:** Dual-band 2.4 GHz / 5 GHz (802.11a/b/g/n/ac)
- **Driver:** `iwlwifi` (Native Linux Kernel Driver)
- **Status:** 🟢 **PASSED**

---

### Environment 5: Raspberry PI Zero W (Single-Board Computer Host)
- **OS Tested:** Raspbian GNU/Linux 13 (trixie) & Kali Linux 2025.2 (Final official release for this hardware architecture)
- **Kernel Version:** 6.18.50+rpt-rpi-v6 (and equivalents)
- **Architecture:** armv6l (32-bit ARM)
- **CPU:** ARMv6-compatible processor rev 7 (v6l) (Raspberry Pi Zero W)
- **Device Model**: Raspberry PI Zero W

#### Tested Device: Broadcom CYW43438 (Integrated Wireless)
- **Chipset:** Broadcom / Cypress CYW43438
- **Hardware Release Year:** 2017 (via Raspberry Pi Zero W launch)
- **Bands:** 2.4 GHz
- **Driver:** `brcmfmac` (Native Linux Kernel Driver)
- **Status:** 🟡 **PARTIAL SUPPORT**

##### Technical Analysis & Failure Root Cause:
- **Symptoms:** The script fails immediately on both Raspbian 13 and Kali Linux 2025.2 when attempting to switch the integrated wireless interface into monitor mode. Automated execution and tools like `airmon-ng` produce the exact kernel error: `DEL_INTERFACE: errno 524`.
- **Root Cause:** Testing across both operating systems confirms that the stock firmware shipped for the `brcmfmac` driver explicitly locks down raw 802.11 frame manipulation. Since Kali Linux 2025.2 is the final official release for the Raspberry Pi Zero W, subsequent out-of-the-box system configurations will not solve this hardware-level restriction.
- **Operational Scope:** While active over-the-air exploitation and raw capturing are blocked due to the firmware monitor mode constraint, all secondary features within the tool architecture—such as static `.pcap` log analysis, report generation, and network utilities that interact over regular client connections—remain completely operational on this host.
- **Remediation Note:** To bypass this vendor lock for full monitor mode support, users must manually compile and flash a custom community-patched firmware (such as the *Nexmon* framework) to force hardware-level monitor mode support.

---

### Environment 6: HP ProBook 6460b (Legacy x86_64 Host)
- **OS Tested:** Debian GNU/Linux 13 (trixie) (Live Session)
- **Kernel Version:** 6.12.107-amd64
- **Architecture:** x86_64
- **CPU:** AMD A8-4500M APU with Radeon(tm) HD Graphics
- **Device Model:** HP ProBook 6460b

#### Tested Device: Broadcom Inc. BCM43228 (Internal PCIe)
- **Chipset:** Broadcom Inc. and subsidiaries BCM43228 802.11a/b/g/n
- **Hardware Release Year:** ~2012
- **Bands:** Dual-band 2.4 GHz / 5 GHz (802.11a/b/g/n)
- **Driver:** `wl` (Proprietary Broadcom STA Driver)
- **Status:** 🟡 **PARTIAL SUPPORT**

##### Technical Analysis & Failure Root Cause:
- **Symptoms:** When initiating the custom scanning tool or running automated management tools like `airmon-ng`, the script crashes during the initialization phase yielding the specific driver exception: `[ERROR] Unable to delete interface wlo1: nl80211 DEL_INTERFACE: operation not supported`.
- **Root Cause:** The standard proprietary Linux driver (`wl`) for the BCM43228 chipset is strictly tailored for station (managed) client use. It restricts configuration via the modern Linux `nl80211` / `mac80211` netlink architecture. The driver exposes a pseudo-monitor mode interface structure that refuses dynamic virtual interface teardown or sub-interface modifications required by professional automation scripts.
- **Operational Scope:** The tool's core automation crashes only when interacting with the hardware layer to enforce raw sniffing states. Any modular components of the software that execute independently of monitor mode execute successfully without any disruption.
- **Remediation Note:** Out-of-the-box deployment using the standard vendor driver fails to fulfill core testing tasks. Users require an external dedicated USB network interface card (NIC) containing open-source architecture components (such as *Atheros AR9271* or *MediaTek MT7612U*) to guarantee structural packet manipulation on this host environment.

---

### Environment 7: High-Performance AMD x86_64 Host
- **OS:** Debian GNU/Linux 13 (trixie)
- **Kernel Version:** 6.12.107+deb13-amd64
- **Architecture:** x86_64
- **CPU:** AMD Ryzen 7 5700G with Radeon Graphics (16 threads, 8 cores)

#### Tested Device: Realtek Semiconductor Co., Ltd. RTL8852AE 802.11ax PCIe Wireless Network Adapter
- **Chipset:** Realtek RTL8852AE
- **Hardware Release Year:** ~2020/2021
- **Bands:** Dual-band 2.4 GHz / 5 GHz (802.11a/b/g/n/ac/ax Wi-Fi 6)
- **Driver:** `rtw89_8852ae` (Native Linux Kernel Driver)
- **Status:** 🟢 **PASSED**

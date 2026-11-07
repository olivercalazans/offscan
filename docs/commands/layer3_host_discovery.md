# Host Discovery (`offscan hdisc`)

The **Host Discovery module** performs active network scanning to identify live hosts within an IP range across local (Layer 2) and routed (Layer 3) network segments.

`offscan hdisc` supports flexible probe selection (**ARP**, **ICMP Echo**, and **TCP SYN**) and features a custom IP range syntax to restrict scans to specific subnets or IP intervals.

* **ARP Probes (`--arp`):** Ultra-fast, un-firewallable Layer 2 discovery for hosts on the local Ethernet/Wi-Fi segment.
* **ICMP Probes (`--icmp`):** Standard Layer 3 Echo Request pings across local and routed networks.
* **TCP Probes (`--tcp`):** Layer 3 SYN probes aimed at common ports to detect active hosts even when ICMP traffic is filtered by host firewalls.

## Command Reference & Flags

```
sudo ./offscan hdisc [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Default | Description |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `-i` | `--iface` | string | Optional | System Default | Network interface to send probe packets |
| `-r` | `--range` | string | Optional | Full Subnet | IP range selection (`+IP`, `IP+IP`, or `IP+`) |
| | `--arp` | bool | Optional | Auto | Enable/restrict scan to ARP probes |
| | `--icmp` | bool | Optional | Auto | Enable/restrict scan to ICMP probes |
| | `--tcp` | bool | Optional | Auto | Enable/restrict scan to TCP SYN probes |

<br>

## IP Range Syntax (`-r` / `--range`)

`offscan hdisc` uses a streamlined range syntax to specify targeted IP boundaries without needing CIDR math:

| Syntax Format | Example | Description |
| :--- | :--- | :--- |
| `+<IP>` | `-r +192.168.1.50` | Scans from the **start of the subnet** up to `192.168.1.50`. |
| `<IP1>+<IP2>` | `-r 192.168.1.10+192.168.1.50` | Scans all IP addresses **between** `192.168.1.10` and `192.168.1.50`. |
| `<IP>+` | `-r 192.168.1.100+` | Scans from `192.168.1.100` up to the **end of the subnet**. |

<br>

## Execution Examples

### 1. Default Subnet Scan (Auto Probes)

Scans the local subnet using the default system network interface:

```
sudo ./offscan hdisc
```

### 2. Targeted Interval Scan using ARP Probes

Scans hosts between `192.168.1.10` and `192.168.1.30` on interface `eth0` using only ARP probes:

```
sudo ./offscan hdisc -i eth0 -r 192.168.1.10+192.168.1.30 --arp
```

### 3. Combined ICMP and TCP Probe Scan

Scans from the start of the subnet up to `10.0.0.100` using ICMP and TCP probes:

```
sudo ./offscan hdisc -i wlan0 -r +10.0.0.100 --icmp --tcp
```

### Output example

> [!NOTE]
>
> For privacy and security reasons, actual hardware MAC addresses and hostnames have been replaced with generic placeholders.

```bash
oliver@sigma:~$ sudo offscan hdisc -r 192.168.110.1+192.168.110.254 --icmp

OffScan - The offensive security and scanning tool for Wi-Fi
Repository: https://github.com/olivercalazans/offscan

[i] Iface..: wlp1s0
[i] Range..: 192.168.110.1 - 192.168.110.254
[i] Len IPs: 254
[i] Proto..: ARP, ICMP
[+] Sniffer started
[$] Packets received = 420
[-] Sniffer stopped

# 192.168.110.8    02:00:00:00:00:01  Unknown
# 192.168.110.30   02:00:00:00:00:02  sigma
# 192.168.110.72   02:00:00:00:00:03  Unknown
# 192.168.110.78   02:00:00:00:00:04  Unknown
# 192.168.110.163  02:00:00:00:00:05  Unknown
# 192.168.110.226  02:00:00:00:00:06  Unknown
# 192.168.110.228  02:00:00:00:00:07  Unknown

[$] 7 host(s) discovered
```

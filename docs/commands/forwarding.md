# IP Packet Forwarding Control (`offscan fwd`)

The **IP Packet Forwarding utility** manages the kernel-level IPv4 packet forwarding setting (`/proc/sys/net/ipv4/ip_forward`) on Linux systems.

During Man-in-the-Middle (MITM) operations like **ARP Poisoning**, packet forwarding must be enabled so that the attacker's system routes intercepted network packets between the target client and the Access Point/Gateway. If forwarding is disabled, intercepted traffic will be dropped, causing a Denial of Service (DoS) for the target instead of a silent MITM inspection.

`offscan fwd` provides manual control over this setting as a utility and troubleshooting fallback if packet forwarding is not automatically toggled or restored during ARP poisoning operations.


<br>


## Command Reference & Flags

```
sudo ./offscan fwd [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-e` | `--enable` | bool | Optional | Enable IPv4 packet forwarding in the Linux kernel |
| `-d` | `--disable` | bool | Optional | Disable IPv4 packet forwarding in the Linux kernel |

> **Note:** Choose either `--enable` or `--disable` per execution.

<br>

## Execution Examples

### Enable Packet Forwarding
```bash
sudo ./offscan fwd -e
```

### Disable Packet Forwarding
```bash
sudo ./offscan fwd -d
```

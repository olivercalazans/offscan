# ARP Poisoning Attack (`offscan arp`)

The **ARP Poisoning attack** (ARP Cache Poisoning / ARP Spoofing) intercepts communications between a target device and the Access Point (Gateway) on a local network.

`offscan arp` executes a bidirectional ARP poisoning mechanism:
1. **Poisoning the Target:** Sends forged ARP response packets to the target host, pretending to be the Access Point/Gateway.
2. **Poisoning the Access Point:** Sends forged ARP response packets to the Access Point/Gateway, pretending to be the target host.

By continuously corrupting the ARP cache tables of both parties simultaneously, all network traffic between the target and the Access Point is redirected through the attacker's system, establishing a Man-in-the-Middle (MITM) position.

<br>

## Command Reference & Flags

```bash
sudo ./offscan arp [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Description |
| :--- | :--- | :---: | :---: | :--- |
| `--tip` | `--tip` | string | **Yes** | Target IP address (`Target IP`) |
| `--tmac` | `--tmac` | string | **Yes** | Target MAC address (`Target MAC`) |

<br>

## Execution Example

To launch the bidirectional ARP poisoning attack against a target host:

```bash
sudo ./offscan arp --tip 192.168.1.50 --tmac 00:11:22:33:44:55
```

# Deauthentication Attack (`offscan deauth`)

The **Deauthentication Attack** transmits unencrypted 802.11 deauthentication management frames to sever the connection between a wireless target client and an Access Point (AP).

`offscan deauth` implements a **bidirectional frame injection** mechanism:

1. **Target Disconnection (AP Impersonation):** Injects spoofed deauthentication frames directed at the target client, pretending to originate from the Access Point.
2. **Access Point Disconnection (Client Impersonation):** Injects spoofed deauthentication frames directed at the Access Point, pretending to originate from the target client.

### Connection Block & Practical Behavior

Once the initial disconnection is forced, maintaining an active frame flood prevents the client device from re-establishing a successful connection or completing the 802.11 association handshake with the AP. In most practical testing scenarios, as long as `offscan deauth` continues broadcasting frames, the target remains continuously disconnected from the wireless network.

This module is primarily used to:
* Force target devices to disconnect and attempt reconnection in order to capture WPA/WPA2 4-way handshakes.
* Maintain a persistent denial-of-service (DoS) condition on targeted client devices.
* Test wireless driver behavior and compliance with IEEE 802.11w Protected Management Frames (PMF).

<br>

## Command Reference & Flags

```
sudo ./offscan deauth [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-b` | `--bssid` | string | **Yes** | BSSID / MAC address of the Access Point |
| `-c` | `--channel` | int | **Yes** | Operating wireless channel |
| `-i` | `--iface` | string | **Yes** | Network interface in monitor mode |
| `-t` | `--tmac` | string | **Yes** | Target client MAC address |
| `-d` | `--delay` | int | Optional | Delay between transmitted frames in milliseconds |

<br>

## Execution Example

To launch a continuous bidirectional deauthentication flood against client `AA:BB:CC:DD:EE:FF` connected to AP `00:11:22:33:44:55` on channel 6 with a 100ms interval:

```
sudo ./offscan deauth -i wlp2s0 -c 6 -b 00:11:22:33:44:55 -t AA:BB:CC:DD:EE:FF -d 100
```

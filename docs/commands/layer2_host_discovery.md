# Layer 2 Wireless Host Discovery (`offscan l2disc`)

The **Layer 2 Host Discovery module** passively analyzes 802.11 wireless traffic to map out active Access Points (APs) and their associated client devices without transmitting probe packets.

`offscan l2disc` requires a wireless interface operating in **Monitor Mode**.

### Under-the-Hood Mechanism

The module continuously captures raw 802.11 management and data frames across channels:

1. **Beacon Frame Capture:** Captures 802.11 Beacon frames broadcast by Access Points to identify active SSIDs, BSSIDs (MAC addresses), and operational channels.

2. **Data Frame Inspection:** Captures 802.11 Data frames passing through the air to extract Source and Destination MAC addresses.

3. **Frame Correlation:** Correlates the extracted frame parameters in real time, matching client MAC addresses with their respective Access Point BSSIDs. This allows `offscan l2disc` to accurately identify which devices are connected to each Wi-Fi network and calculate client density per AP.

<br>

## Command Reference & Flags

```
sudo ./offscan l2disc [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Default | Description |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `-i` | `--iface` | string | **Yes** | — | Wireless network interface in monitor mode |
| `-d` | `--delay` | float | Optional | `1.5` | Channel dwell time in seconds (hopping delay per channel) |

> **Prerequisite:** Ensure the interface is switched to Monitor Mode using `sudo ./offscan ifmode -i <iface> --mon` before running this command.

<br>

## Execution Example

To start sniffing and hopping channels with a 2.0-second delay per channel on interface `wlp2s0`:

```
sudo ./offscan l2disc -i wlp2s0 -d 2.0
```

# Wi-Fi AP Mapper (`offscan wmap`)

The **Wi-Fi AP Mapper module** discovers and maps nearby wireless Access Points (APs) by capturing 802.11 Beacon management frames broadcast by wireless networks.

`offscan wmap` operates in passive sniffing mode and requires a wireless network interface set to **Monitor Mode**.

### Captured Information

By parsing raw 802.11 Beacon frames across available Wi-Fi channels, `offscan wmap` extracts and formats key network parameters into tabular output:

* **SSID:** Broadcast network name (Service Set Identifier).

* **BSSID:** Physical MAC address of the Access Point radio interface.

* **Ch (Channel):** Operational Wi-Fi frequency channel.

* **Std (Standard):** Wireless protocol standard (e.g., `802.11n`, `802.11ac`, `802.11ax`).

* **Sec (Security):** Authentication and privacy suites (e.g., `WPA2-PSK`, `WPA3-SAE`, `Open`).

* **WPS:** Wi-Fi Protected Setup status and state.

* **UPTIME:** Operating uptime reported by the Access Point based on frame timestamps.

<br>

## Command Reference & Flags

```
sudo ./offscan wmap [FLAGS]

```

### Parameters

| Flag | Long Flag | Type | Required? | Description | 
| ----- | ----- | ----- | ----- | ----- | 
| `-i` | `--iface` | string | **Yes** | Wireless network interface in monitor mode | 

> **Prerequisite:** Switch the interface to Monitor Mode using `sudo ./offscan ifmode -i <iface> --mon` before running this command.

<br>

## Execution Example

To start mapping wireless Access Points on interface `wlp2s0`:

```
sudo ./offscan wmap -i wlp2s0

```

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

> [!NOTE]
>
> Real SSIDs and BSSIDs in the output have been obfuscated for privacy and security purposes.


```bash
oliver@omega:~$ sudo ./offscan wmap -i wlp1s0

OffScan - The offensive security and scanning tool for Wi-Fi
Repository: https://github.com/olivercalazans/offscan

[+] Sniffer started
[*] Sniffing beacons
[$] Packets received = 103
[-] Sniffer stopped

SSID                     BSSID              Ch   Std       Sec            WPS       UPTIME
-----------------------  -----------------  ---  --------  -------------  --------  ------
<hidden>                 02:00:00:00:00:01  1    802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
<hidden>                 02:00:00:00:00:02  3    802.11ac  WPA2-PSK-TKIP  0.0       3d 02h
<hidden>                 02:00:00:00:00:03  3    802.11ac  WPA2-PSK-TKIP  0.0       5d 02h
<hidden>                 02:00:00:00:00:04  3    802.11ac  WPA2-PSK-TKIP  0.0       8d 09h
<hidden>                 02:00:00:00:00:05  6    802.11n   WPA2-PSK-CCMP  2.0 CONF  43d 22h
<hidden>                 02:00:00:00:00:06  7    802.11n   WPA2-PSK-CCMP  0.0       80d 16h
<hidden>                 02:00:00:00:00:07  11   802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
<hidden>                 02:00:00:00:00:08  11   802.11n   WPA2-PSK-CCMP  0.0       3d 00h
<hidden>                 02:00:00:00:00:09  40   802.11ac  WPA2-PSK-TKIP  0.0       3d 02h
<hidden>                 02:00:00:00:00:0a  40   802.11ac  WPA2-PSK-TKIP  0.0       8d 09h
<hidden>                 02:00:00:00:00:0b  136  802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
<hidden>                 02:00:00:00:00:0c  153  802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
wifi1                    02:00:00:00:00:0d  11   802.11n   WPA2-PSK-TKIP  0.0       3d 00h
wifi2                    02:00:00:00:00:0e  2    802.11n   WPA2-PSK-CCMP  0.0       10d 12h
wifi3                    02:00:00:00:00:0f  3    802.11ac  WPA2-PSK-CCMP  2.0 CONF  3d 02h
wifi3                    02:00:00:00:00:10  40   802.11ac  WPA2-PSK-CCMP  2.0 CONF  8d 09h
wifi3                    02:00:00:00:00:11  40   802.11ac  WPA2-PSK-CCMP  2.0 CONF  3d 02h
wifi4                    02:00:00:00:00:12  3    802.11ac  WPA2-PSK-TKIP  0.0       5d 02h
wifi4                    02:00:00:00:00:13  3    802.11ac  WPA2-PSK-TKIP  0.0       3d 02h
wifi4                    02:00:00:00:00:14  3    802.11ac  WPA2-PSK-TKIP  0.0       8d 09h
wifi4                    02:00:00:00:00:15  40   802.11ac  WPA2-PSK-TKIP  0.0       3d 02h
wifi4                    02:00:00:00:00:16  40   802.11ac  WPA2-PSK-TKIP  0.0       8d 09h
wifi5                    02:00:00:00:00:17  1    802.11n   WPA2-PSK-CCMP  0.0       less than 1h
wifi6                    02:00:00:00:00:18  6    802.11n   WPA2-PSK-CCMP  2.0 CONF  3d 21h
wifi7                    02:00:00:00:00:19  6    802.11n   WPA2-PSK-CCMP  2.0 CONF  20d 19h
wifi8                    02:00:00:00:00:1a  1    802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
wifi8                    02:00:00:00:00:1b  11   802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
wifi8                    02:00:00:00:00:1c  136  802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
wifi8                    02:00:00:00:00:1d  153  802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
wifi9                    02:00:00:00:00:1e  6    802.11n   WPA2-PSK-CCMP  0.0       43d 22h
wifi9                    02:00:00:00:00:1f  6    802.11n   WPA2-PSK-CCMP  0.0       20d 19h
wifi10                   02:00:00:00:00:20  1    802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
wifi10                   02:00:00:00:00:21  11   802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
wifi10                   02:00:00:00:00:22  136  802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
wifi10                   02:00:00:00:00:23  153  802.11ac  WPA2-PSK-CCMP  0.0       3d 17h
wifi11                   02:00:00:00:00:24  10   802.11n   WPA2-PSK-CCMP  2.0 CONF  3h
wifi12                   02:00:00:00:00:25  11   802.11n   WPA2-PSK-CCMP  2.0 CONF  10d 12h
wifi13                   02:00:00:00:00:26  153  802.11ac  WPA2-PSK-CCMP  0.0       5h
wifi14                   02:00:00:00:00:27  10   802.11n   WPA2-PSK-CCMP  0.0       60d 06h
wifi15                   02:00:00:00:00:28  112  802.11ac  WPA2-PSK-CCMP  0.0       60d 06h
```

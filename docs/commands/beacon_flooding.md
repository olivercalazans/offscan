# Beacon Flooding Attack (`offscan beacon`)

The **Beacon Flooding attack** transmits continuous, forged 802.11 Beacon management frames into the air to advertise non-existent (fake) Access Points.

`offscan beacon` injects raw 802.11 Beacon frames directly through a monitor-mode wireless interface. This creates rogue SSID entries on nearby Wi-Fi scanners, mobile devices, and operating systems. It is commonly used to:

* Clutter and confuse wireless network scanning tools.
* Stress-test client Wi-Fi driver capabilities when handling numerous nearby APs.
* Disguise legitimate Access Points during security assessments.
* May overwhelm and crash resource-constrained IoT devices

<br>

## Command Reference & Flags

```
sudo ./offscan beacon [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-c` | `--channel` | int | **Yes** | Operating wireless channel (1–14) |
| `-i` | `--iface` | string | **Yes** | Network interface in monitor mode |
| `-s` | `--ssid` | string | **Yes** | Fake SSID/Network name to broadcast |

<br>

## Execution Example

To broadcast a fake Access Point named `"Free_Public_WiFi"` on channel 6:

```bash
sudo ./offscan beacon -i wlp2s0 -c 6 -s "Free_Public_WiFi"
```

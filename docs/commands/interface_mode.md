# Wireless Interface Mode Control (`offscan ifmode`)

The **Interface Mode Control utility** manages the operational state and mode of wireless network interfaces on Linux systems, allowing users to safely switch between **Monitor Mode** and **Managed Mode**.

### Under-the-Hood Mechanism

To prevent background network management services (such as `NetworkManager`, `wpa_supplicant`, or `systemd-networkd`) from automatically interfering, resetting, or recovering the wireless interface state, `offscan ifmode` executes a 4-step teardown and recreation sequence via netlink/nl80211:

1. **Interface Down:** Disables the current wireless interface.
2. **Interface Deletion:** Deletes the existing virtual interface from the system kernel to break active bindings and avoid automated service recovery.
3. **Interface Creation:** Re-creates a fresh virtual interface with the specified operational mode (`monitor` or `managed`).
4. **Interface Up:** Activates the newly created interface for use.

<br>

## Required Monitor Mode Dependencies

Several `offscan` offensive and mapping modules rely directly on raw 802.11 frame capture and packet injection capabilities provided by Monitor Mode. The following commands require setting the interface to `--mon` prior to execution:

* **`offscan wmap`** (Wi-Fi/AP Mapping)
* **`offscan l2disc`** (Layer 2 Host Discovery)
* **`offscan beacon`** (Beacon Flooding Attack)
* **`offscan deauth`** (Deauthentication Attack)

<br>


## Command Reference & Flags

```bash
sudo ./offscan ifmode -i <IFACE> [MODE_FLAG]
```

### Parameters

| Flag | Long Flag | Type | Required? | Description |
| :--- | :--- | :---: | :---: | :--- |
| `-i` | `--iface` | string | **Yes** | Target wireless network interface name (e.g., `wlan0`) |
| | `--mon` | bool | Option | Set the interface to **Monitor Mode** |
| | `--man` | bool | Option | Set the interface to **Managed Mode** |

> **Note:** Specify either `--mon` or `--man` per execution.

<br>

## Execution Examples

### 1. Enabling Monitor Mode (Pre-requisite for `wmap`, `l2disc`, `beacon`, `deauth`)

```bash
sudo ./offscan ifmode -i wlan0 --mon
```

### 2. Restoring Managed Mode

```bash
sudo ./offscan ifmode -i wlan0 --man
```

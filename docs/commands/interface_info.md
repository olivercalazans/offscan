# Network Interface Information (`offscan info`)

The **Network Interface Information utility** inspects and displays detailed network interface configuration metrics across the system. 

`offscan info` queries local kernel interfaces to aggregate physical, link-layer (Layer 2), and network-layer (Layer 3) properties, providing an essential diagnostic snapshot prior to running scanning or offensive modules.

### Reported Fields

For each interface, `offscan info` retrieves:
* **Interface State & Type:** Operational status (`UP`, `DOWN`, `UNKNOWN`) and hardware medium (`Loopback`, `Ethernet`, `Wireless`).
* **MAC Address:** Hardware MAC address of the interface.
* **IP & CIDR Notation:** Assigned IPv4 address and subnet mask notation (e.g., `192.168.1.197/24`).
* **Addressable Hosts (`Len hosts`):** Total number of usable host IP addresses within the current subnet.
* **MTU:** Maximum Transmission Unit size in bytes.
* **Gateway Details:** Discovered Gateway IP address and corresponding Gateway MAC address.
* **Broadcast Address:** Subnet broadcast IPv4 address.

<br>

## Command Reference & Flags

```
sudo ./offscan info [FLAGS]
```

### Parameters

| Flag | Long Flag | Type | Required? | Default | Description |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `-i` | `--iface` | string | Optional | All | Display metrics for a specific interface only |

<br>

## Execution Examples

### 1. Inspect All System Interfaces

```bash
./offscan info
```

### 2. Inspect a Specific Wireless Interface

```bash
./offscan info -i wlp2s0
```

<br>


## Output Log Example

```
OffScan - The offensive security and scanning tool for Wi-Fi
Repository: https://github.com/olivercalazans/offscan

# 1 Interface: lo - State: UNKNOWN
  - Type.......: Loopback
  - MAC........: 
  - IP.........: 127.0.0.1
  - CIDR.......: 127.0.0.1/8
  - Len hosts..: 16777214
  - MTU........: 65536
  - Gateway MAC: Unknown
  - Gateway IP.: Unknown
  - Broadcast..: None

# 2 Interface: enp1s0 - State: DOWN
  - Type.......: Ethernet
  - MAC........: 64:1c:67:69:71:61
  - IP.........: None
  - CIDR.......: Unknown
  - Len hosts..: None
  - MTU........: 1500
  - Gateway MAC: Unknown
  - Gateway IP.: Unknown
  - Broadcast..: Unknown

# 3 Interface: wlp2s0 - State: UP
  - Type.......: Wireless
  - MAC........: 34:23:87:76:8e:71
  - IP.........: 192.168.1.197
  - CIDR.......: 192.168.1.197/24
  - Len hosts..: 254
  - MTU........: 1500
  - Gateway MAC: 08:c7:f5:ba:89:ad
  - Gateway IP.: 192.168.1.1
  - Broadcast..: 192.168.1.255
```

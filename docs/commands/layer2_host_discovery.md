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

> [!NOTE]
>
> Real STA MAC addresses, BSSIDs, and SSIDs in the output have been obfuscated for privacy and security purposes.

```
oliver@omega:~$ sudo offscan l2disc -i wlp1s0

OffScan - The offensive security and scanning tool for Wi-Fi
Repository: https://github.com

[i] IFACE: wlp1s0
[i] DELAY: 1.50s
[+] Sniffing 802.11 frames. Press CTRL + C to stop
[+] Sniffer started

   STA MAC            BSSID              Ch   SSID
   -----------------  -----------------  ---  ----
1. 02:00:00:00:01:01  02:00:00:00:00:01  1    wifi1
2. 02:00:00:00:01:02  02:00:00:00:00:02  3    wifi2
3. 02:00:00:00:01:03  02:00:00:00:00:03  6    wifi3
4. 02:00:00:00:01:04  02:00:00:00:00:03  6    wifi3
5. 02:00:00:00:01:05  02:00:00:00:00:03  6    wifi3
6. 02:00:00:00:01:06  02:00:00:00:00:03  6    wifi3
7. 02:00:00:00:01:07  02:00:00:00:00:04  6    <hidden>
8. 02:00:00:00:01:08  02:00:00:00:00:03  6    wifi3
9. 02:00:00:00:01:09  02:00:00:00:00:05  6    wifi3
10. 02:00:00:00:01:0a  02:00:00:00:00:03  6    wifi3
11. 02:00:00:00:01:0b  02:00:00:00:00:04  6    <hidden>
12. 02:00:00:00:01:0c  02:00:00:00:00:04  6    <hidden>
13. 02:00:00:00:01:0d  02:00:00:00:00:04  6    <hidden>
14. 02:00:00:00:01:0e  02:00:00:00:00:04  6    <hidden>
15. 02:00:00:00:01:0f  02:00:00:00:00:04  6    <hidden>
16. 02:00:00:00:01:10  02:00:00:00:00:04  6    <hidden>
17. 02:00:00:00:01:11  02:00:00:00:00:04  6    <hidden>
18. 02:00:00:00:01:12  02:00:00:00:00:05  6    wifi3
19. 02:00:00:00:01:13  02:00:00:00:00:04  6    <hidden>
20. 02:00:00:00:01:14  02:00:00:00:00:03  6    wifi3
21. 02:00:00:00:01:15  02:00:00:00:00:03  6    wifi3
22. 02:00:00:00:01:16  02:00:00:00:00:05  6    wifi3
23. 02:00:00:00:01:17  02:00:00:00:00:04  6    <hidden>
24. 02:00:00:00:01:18  02:00:00:00:00:04  6    <hidden>
25. 02:00:00:00:01:19  02:00:00:00:00:04  6    <hidden>
26. 02:00:00:00:01:1a  02:00:00:00:00:04  6    <hidden>
27. 02:00:00:00:01:1b  02:00:00:00:00:06  10   wifi4
28. 02:00:00:00:01:1c  02:00:00:00:00:06  10   wifi4
29. 02:00:00:00:01:1d  02:00:00:00:00:06  10   wifi4
30. 02:00:00:00:01:1e  02:00:00:00:00:06  10   wifi4
31. 02:00:00:00:01:1f  02:00:00:00:00:06  10   wifi4
32. 02:00:00:00:01:20  02:00:00:00:00:06  10   wifi4
33. 02:00:00:00:01:21  02:00:00:00:00:07  11   wifi5
34. 02:00:00:00:01:22  02:00:00:00:00:08  40   wifi2
35. 02:00:00:00:01:23  02:00:00:00:00:09  153  wifi6
36. 02:00:00:00:01:24  02:00:00:00:00:09  153  wifi6
37. 02:00:00:00:01:25  02:00:00:00:00:09  153  wifi6
38. 02:00:00:00:01:26  02:00:00:00:00:09  153  wifi6
^C
[!] Interrupt received. Stopping...
[$] Packets received = 1420
[-] Sniffer stopped
[-] Process stopped
```

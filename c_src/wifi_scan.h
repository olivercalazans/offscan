// wifi_scan.h
#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stdint.h>

#define MAX_SSID_LEN 32

typedef struct {
    uint8_t  bssid[6];
    char     ssid[MAX_SSID_LEN + 1];
    uint32_t frequency;
} wifi_network_t;


int scan_wifi(
    const char *ifname,
    wifi_network_t **results,
    int *count
);


void free_scan_results(wifi_network_t *results);

#endif

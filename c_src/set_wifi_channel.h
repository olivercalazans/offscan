#ifndef WIFI_CHANNEL_H
#define WIFI_CHANNEL_H

#ifdef __cplusplus
extern "C" {
#endif

int set_wifi_channel(const char *interface_name, int channel);

#ifdef __cplusplus
}
#endif

#endif
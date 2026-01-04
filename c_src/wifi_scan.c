#include "wifi_scan.h"

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <linux/nl80211.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#define MAX_NETWORKS 256

static wifi_network_t *results = NULL;
static int result_count        = 0;


static int scan_dump_cb(struct nl_msg *msg, void *arg) {
    (void)arg;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS])
        return NL_SKIP;

    struct nlattr *bss[NL80211_BSS_MAX + 1];
    nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], NULL);

    if (!bss[NL80211_BSS_BSSID] || !bss[NL80211_BSS_INFORMATION_ELEMENTS])
        return NL_SKIP;

    if (result_count >= MAX_NETWORKS)
        return NL_SKIP;

    wifi_network_t *net = &results[result_count++];

    memcpy(net->bssid, nla_data(bss[NL80211_BSS_BSSID]), 6);

    net->frequency = bss[NL80211_BSS_FREQUENCY]
                     ? nla_get_u32(bss[NL80211_BSS_FREQUENCY])
                     : 0;

    memset(net->ssid, 0, sizeof(net->ssid));

    uint8_t *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    int ie_len  = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);

    for (int i = 0; i + 1 < ie_len; ) {
        uint8_t id  = ie[i];
        uint8_t len = ie[i + 1];

        if (id == 0 && len <= 32) {
            memcpy(net->ssid, &ie[i + 2], len);
            net->ssid[len] = '\0';
            break;
        }

        i += 2 + len;
    }

    return NL_OK;
}



static int scan_event_cb(struct nl_msg *msg, void *arg) {
    (void)arg;

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS ||
        gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
        return NL_STOP;
    }

    return NL_OK;
}



int scan_wifi(
    const char *ifname, 
    wifi_network_t **out,
    int *count
) {

    struct nl_sock *sock = NULL;
    int nl80211_id;
    int ifindex;
    int err;

    *out   = NULL;
    *count = 0;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -ENODEV;

    sock = nl_socket_alloc();
    if (!sock)
        return -ENOMEM;

    nl_socket_set_buffer_size(sock, 8192, 8192);

    if (genl_connect(sock))
        goto fail;

    nl80211_id = genl_ctrl_resolve(sock, "nl80211");
    if (nl80211_id < 0)
        goto fail;

    /* ---------- trigger scan ---------- */

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg)
        goto fail;

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    struct nl_msg *ssids = nlmsg_alloc();
    nla_put(ssids, 1, 0, "");

    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
    nlmsg_free(ssids);

    err = nl_send_auto(sock, msg);
    nlmsg_free(msg);

    if (err < 0)
        goto fail;

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, scan_event_cb, NULL);

    nl_recvmsgs_default(sock);

    usleep(2000 * 1000);

    /* ---------- dump ---------- */

    results = calloc(MAX_NETWORKS, sizeof(wifi_network_t));
    if (!results)
        goto fail;

    result_count = 0;

    msg = nlmsg_alloc();
    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, scan_dump_cb, NULL);

    nl_send_auto(sock, msg);
    nlmsg_free(msg);

    nl_recvmsgs_default(sock);

    nl_socket_free(sock);

    *out   = results;
    *count = result_count;
    return 0;

fail:
    if (sock)
        nl_socket_free(sock);
    if (results) {
        free(results);
        results = NULL;
    }
    return -1;
}



void free_scan_results(wifi_network_t *ptr) {
    free(ptr);
}

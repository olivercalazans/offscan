#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>



int set_wifi_channel(const char *interface_name, int channel) {
    struct nl_sock *sock = NULL;
    struct nl_cb *cb     = NULL;
    int ifindex          = 0;
    int err              = 0;
    int nl80211_id;

    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        return -1;
    }

    if (genl_connect(sock)) {
        fprintf(stderr, "Failed to connect to generic netlink\n");
        nl_socket_free(sock);
        return -1;
    }

    nl80211_id = genl_ctrl_resolve(sock, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "nl80211 not found\n");
        nl_socket_free(sock);
        return -1;
    }

    ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", interface_name);
        nl_socket_free(sock);
        return -1;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate netlink callback\n");
        nl_socket_free(sock);
        return -1;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message\n");
        nl_cb_put(cb);
        nl_socket_free(sock);
        return -1;
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_SET_CHANNEL, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, 2407 + channel * 5);
    nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);

    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send netlink message: %d\n", err);
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return -1;
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive netlink message: %d\n", err);
    }

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);

    return err;
}
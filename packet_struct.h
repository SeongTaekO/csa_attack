#ifndef PACKET_STRUCT_H
#define PACKET_STRUCT_H

#include <arpa/inet.h>

#define MAC_ADDR_LEN 6

// http://ktword.co.kr/test/view/view.php?no=2319
struct ieee80211_radiotap_header {
    u_int8_t hdr_revision;
    u_int8_t hdr_pad;
    u_int16_t hdr_length;
    u_int32_t present_flags;
    u_int8_t flags;
    u_int8_t data_rate;
    u_int16_t channel_freq;
    u_int16_t channel_flags;
    u_int8_t antenna_signal;
    u_int8_t antenna;
    u_int16_t rx_flags;
}__attribute__((packed));

struct ieee80211_mac_hdr {
    u_int16_t frame_control;
    u_int16_t duration;
    u_int8_t dst_addr[MAC_ADDR_LEN];
    u_int8_t src_addr[MAC_ADDR_LEN];
    u_int8_t BSSID[MAC_ADDR_LEN];
    u_int16_t seq_ctrl;
}__attribute__((packed));

struct ieee80211_frame_body {
    u_int8_t *wireless_management;
}__attribute__((packed));

struct ieee80211_Frame_Check_Sequence {
    u_int32_t FCS;
}__attribute__((packed));

struct ieee80211_beacon_frame {
    struct ieee80211_radiotap_header radiotap;
    struct ieee80211_mac_hdr mac_hdr;
    struct ieee80211_frame_body frame_body;
    struct ieee80211_Frame_Check_Sequence fcs;
}__attribute__((packed));

#endif /* PACKET_STRUCT_H */
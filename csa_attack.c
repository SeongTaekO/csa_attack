#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include "packet_struct.h"

#define MAC_ADDR_LEN 6
#define MAC_ADDR_FORMAT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

bool keyboard_interrupt = false;


void usage() {
    printf("syntax : csa_attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa_attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


void save_mac(const char *mac_str, uint8_t *mac) {
    int values[MAC_ADDR_LEN];
    if (sscanf(mac_str, MAC_ADDR_FORMAT, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != MAC_ADDR_LEN) {
        fprintf(stderr, "Invalid MAC address format: %s\n", mac_str);
        exit(EXIT_FAILURE);
    }
}


void sigint_handler(int signum) {
    printf("\nCaught SIGINT, exiting...\n");
    if (signum) {
        keyboard_interrupt = true;
    }
}


int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    uint8_t ap_mac[MAC_ADDR_LEN]; // 공유기
    uint8_t station_mac[MAC_ADDR_LEN]; // 연결된 장치들(스마트폰)

    if (argc < 2 || argc > 4) {
        usage();
        return -1;
    }
    else if (argc == 3) {
        save_mac(argv[2], ap_mac);
        save_mac("ff:ff:ff:ff:ff:ff", station_mac);
    }
    else if (argc == 4) {
        save_mac(argv[2], ap_mac);
        save_mac(argv[3], station_mac);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }

    struct ieee80211_beacon_frame frame;
    
    while (!keyboard_interrupt) {
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }

        int packet_len = header->caplen;
        int radiotap_len = sizeof(frame.radiotap);
        int macHdr_len = sizeof(frame.mac_hdr);
        int fcs_len = sizeof(frame.fcs);
        int body_len = packet_len - radiotap_len - macHdr_len - fcs_len;

        if (packet[radiotap_len] != 0x80) {
            printf("\n%02x: not beacon frame continue\n", packet[radiotap_len]);
            continue;
        }

        memcpy(&frame.radiotap, packet, radiotap_len);
        memcpy(&frame.mac_hdr, packet+radiotap_len, macHdr_len);

        frame.frame_body.wireless_management = (u_int8_t *)malloc(body_len);
        if (frame.frame_body.wireless_management == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            continue;
        }
        memcpy(frame.frame_body.wireless_management, packet+radiotap_len+macHdr_len, body_len);
        memcpy(&frame.fcs, packet+radiotap_len+macHdr_len+body_len, fcs_len);

        // printf("packet radiotab: ");
        // for (int i=0; i < radiotap_len; i++) {
        //     printf("%02x ", packet[i]);
        // }
        // printf("\npacket wirless management + FCS: ");
        // for (int i=radiotap_len; i < packet_len; i++) {
        //     printf("%02x ", packet[i]);
        // }
        // printf("\n========================\n");

        // printf("%02x\n", frame.radiotap.hdr_revision);
        // printf("%04x\n", frame.radiotap.hdr_length);
        // printf("%02x\n", frame.mac_hdr.frame_control);
        // for (int i=0; i<body_len; i++) {
        //     printf("%02x ", frame.frame_body.wireless_management[i]);
        // }
        // printf("\n");
        // printf("%08x\n", frame.fcs.FCS);
        // printf("packet len: %d\n", packet_len);
        // header->caplen = packet_len + 5;
        // printf("packet len: %d", header->caplen);
        // printf("\n========================\n");
    }

    free(frame.frame_body.wireless_management);
    pcap_close(pcap);
}
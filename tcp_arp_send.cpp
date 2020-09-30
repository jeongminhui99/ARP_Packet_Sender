#include <stdlib.h>
#include <stdio.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include<cstring>

struct eth_hdr {
    unsigned char h_dest[6];        //destination ether addr
    unsigned char h_source[6];      //source ether addr
    unsigned short h_proto;         //packet type id filed
} __attribute__((packed));

struct arp_hdr {
    unsigned short ar_hrd;          //hardware type : ethernet
    unsigned short ar_pro;          //protocol      : ip
    unsigned char  ar_hln;          //hardware size
    unsigned char  ar_pln;          //protocal size
    unsigned short ar_op;           //opcode request or reply
    unsigned char  ar_sha[6];       //sender mac
    unsigned char  ar_sip[4];       //sender IP
    unsigned char  ar_tha[6];       //Target mac (my)
    unsigned char  ar_tip[4];       //Target IP  (my)
} __attribute__((packed));

int main(int argc, char** argv)
{
    struct eth_hdr ether;
    struct arp_hdr arp;
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    static unsigned char g_buf[sizeof(struct eth_hdr) + sizeof(struct arp_hdr)];
    //u_char packet[100];
    int i;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        return -1;
    }

    /* Open the output device */
    if ((fp = pcap_open_live(argv[1],            // name of the device
        100,                // portion of the packet to capture (only the first 100 bytes)
        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
        1000,               // read timeout
        errbuf              // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
        return -1;
    }


    ether.h_dest[0] = 0xff;
    ether.h_dest[1] = 0xff;
    ether.h_dest[2] = 0xff;
    ether.h_dest[3] = 0xff;
    ether.h_dest[4] = 0xff;
    ether.h_dest[5] = 0xff;


    ether.h_source[0] = 0x00;
    ether.h_source[1] = 0x0c;
    ether.h_source[2] = 0x29;
    ether.h_source[3] = 0xf7;
    ether.h_source[4] = 0x62;
    ether.h_source[5] = 0x11;

    ether.h_proto = htons(0x0806); //ARP

    arp.ar_hrd = htons(0x0001);
    arp.ar_pro = htons(0x0800);
    arp.ar_hln = 0x06;
    arp.ar_pln = 0x04;
    arp.ar_op = htons(0x0001);

    arp.ar_sha[0] = 0x00;
    arp.ar_sha[1] = 0x0c;
    arp.ar_sha[2] = 0x29;
    arp.ar_sha[3] = 0xf7;
    arp.ar_sha[4] = 0x62;
    arp.ar_sha[5] = 0x11;

    arp.ar_sip[0] = 0xc0;
    arp.ar_sip[1] = 0xa8;
    arp.ar_sip[2] = 0x99;
    arp.ar_sip[3] = 0x33;

    arp.ar_tha[0] = 0x00;
    arp.ar_tha[1] = 0x00;
    arp.ar_tha[2] = 0x00;
    arp.ar_tha[3] = 0x00;
    arp.ar_tha[4] = 0x00;
    arp.ar_tha[5] = 0x00;

    arp.ar_tip[0] = 0xc0;
    arp.ar_tip[1] = 0xa8;
    arp.ar_tip[2] = 0x99;
    arp.ar_tip[3] = 0x32;

    memcpy(g_buf, &ether, sizeof(struct eth_hdr));
    memcpy(g_buf + 14, &arp, sizeof(struct arp_hdr));
    /* Send down the packet */
    if (pcap_sendpacket(fp, g_buf, sizeof(struct eth_hdr) + sizeof(struct arp_hdr) /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}
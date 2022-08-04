#pragma once
#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <cstdlib>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void argv_ip(char *argv, u_int8_t *dst);
void copy_ip(u_int8_t *src, u_int8_t *dst);
void print_ip(u_int8_t *ip);
void copy_mac(u_int8_t *src, u_int8_t *dst);
void print_mac(u_int8_t *mac);

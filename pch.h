#pragma once
#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct list final
{
    u_int8_t sender_ip[4];
    u_int8_t target_ip[4];
    u_int8_t sender_mac[6];
    u_int8_t target_mac[6];
};
#pragma pack(pop)

void argv_ip(char *argv, u_int8_t *dst);
void copy_ip(u_int8_t *src, u_int8_t *dst);
void print_ip(u_int8_t *ip);
void copy_mac(u_int8_t *src, u_int8_t *dst);
void print_mac(u_int8_t *mac);
bool if_same_mac(u_int8_t *mac1, u_int8_t *mac2);
bool if_same_ip(u_int8_t *mac1, u_int8_t *mac2);
void print_logo();
void sigint_handler(int signo);
void add_flow(list *targets, int *count);
void view_flow(list *targets, int count);
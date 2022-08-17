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

struct EthIpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef struct
{
    u_int8_t ip_hl : 4, /* header length */
        ip_v : 4;       /* version */
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_check;
    u_int8_t ip_source[4];
    u_int8_t ip_dest[4];
} ip_hdr;

typedef struct
{
    u_int16_t tcp_source;
    u_int16_t tcp_dest;
    u_int32_t tcp_seq;
    u_int32_t tcp_ack;
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;

} tcp_hdr;

void argv_ip(char *argv, u_int8_t *dst);
void copy_ip(u_int8_t *src, u_int8_t *dst);
void print_ip(u_int8_t *ip);
void copy_mac(u_int8_t *src, u_int8_t *dst);
void print_mac(u_int8_t *mac);
bool if_same_mac(u_int8_t *mac1, u_int8_t *mac2);
bool if_same_ip(u_int8_t *mac1, u_int8_t *mac2);
bool check_http(u_char *payload);
void infect(u_char *payload);
void copy_payload(char *src, char *dst);

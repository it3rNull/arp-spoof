#pragma once
#include "pch.h"
/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
#define ETHER_ADDR_LEN 6
typedef struct
{
    u_int8_t ether_dest[ETHER_ADDR_LEN];   /* destination ethernet address */
    u_int8_t ether_source[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
} ether_hdr;

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
    u_int32_t ip_source;
    u_int32_t ip_dest;
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
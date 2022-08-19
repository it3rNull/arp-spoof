#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct IpHdr final
{
    u_int8_t ip_hl : 4, /* header length */
        ip_v : 4;       /* version */
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_offset;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_check;
    u_int32_t ip_source;
    u_int32_t ip_dest;
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
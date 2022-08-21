#include "checksum.h"

uint16_t calc_checksum_ip(TcpIpPacket *ip_pkt)
{
    uint32_t sum = 0;
    uint16_t *block = (uint16_t *)ip_pkt;
    uint16_t *carry = (uint16_t *)sum;

    for (int i = 0; i < 10; i++)
    {
        sum += block[i];
    }

    printf("sum : %d\n");
}
#include "checksum.h"

uint16_t calc_checksum_ip(IpHdr *ip_)
{
    uint32_t sum = 0;
    uint16_t *block = (uint16_t *)ip_;
    uint16_t *carry = (uint16_t *)sum;

    for (int i = 0; i < 10; i++)
    {
        sum += block[i];
    }

    printf("sum : %d\n");
}
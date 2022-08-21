#include "checksum.h"

uint16_t calc_checksum_ip(IpHdr *ip_)
{
    uint32_t *sum = 0;
    uint16_t *block = (uint16_t *)ip_;
    uint16_t *carry;
    for (int i = 0; i < 10; i++)
    {
        *sum += block[i];
    }

    printf("sum : %x\n", *sum);
    carry = (uint16_t *)sum;

    printf("carry : %x\n", *carry);
}
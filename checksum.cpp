#include "checksum.h"

uint16_t calc_checksum_ip(IpHdr *ip_)
{
    uint32_t sum = 0;
    uint16_t *block = (uint16_t *)ip_;
    uint32_t carry;
    uint32_t temp;
    uint16_t ret;
    for (int i = 0; i < 10; i++)
    {
        if (i == 5)
        {
            continue;
        }
        sum += htons(block[i]);
    }

    temp = sum >> 16;
    sum %= 0x10000;
    sum += temp;
    temp = sum >> 16;
    sum %= 0x10000;
    sum += temp;
    ret = ~sum;

    return ret;
}
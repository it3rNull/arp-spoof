#include "checksum.h"

uint16_t calc_checksum_ip(IpHdr *ip_)
{
    uint32_t sum = 0;
    uint16_t *block = (uint16_t *)ip_;
    uint32_t carry;
    uint32_t temp;
    for (int i = 0; i < 20; i++)
    {
        if (i == 5)
        {
            break;
        }
        printf("%x", htons(block[i]));
        sum += block[i];

        printf("!%d ", i);
    }

    printf("sum : %x\n", sum);
}
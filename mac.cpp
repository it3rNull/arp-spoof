#include "mac.h"
int my_mac(char *argv, u_int8_t *mac)
{
    char *temp_mac;
    int sock;
    struct ifreq ifr;
    int fd;
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, argv);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock = socket(AF_INET, SOCK_STREAM, 0) < 0)
    {
        printf("socket error");
        return -1;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("ioctl");
        return -1;
    }

    temp_mac = ifr.ifr_hwaddr.sa_data;
    for (int i = 0; i < 6; i++)
    {
        mac[i] = temp_mac[i];
    }
    return 0;
}
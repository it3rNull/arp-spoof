#include "ip.h"

int s_getIpAddress(const char *ifr, u_int8_t *ip)
{
    char *out;
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in *sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0)
    {
        perror("ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy(out, (void *)&sin->sin_addr, sizeof(sin->sin_addr));
    close(sockfd);
    for (int i = 0; i < 4; i++)
    {
        ip[i] = out[i];
    }

    return 4;
}
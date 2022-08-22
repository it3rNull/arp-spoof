#include "pch.h"

void argv_ip(char *argv, u_int8_t *dst)
{
    char *result;
    result = strtok(argv, ".");
    dst[0] = atoi(result);
    for (int i = 1; i <= 3; i++)
    {
        result = strtok(NULL, ".");
        dst[i] = atoi(result);
    }
}
void copy_ip(u_int8_t *src, u_int8_t *dst)
{
    for (int i = 0; i < 4; i++)
    {
        dst[i] = src[i];
    }
}
void print_ip(u_int8_t *ip)
{
    for (int i = 0; i < 4; i++)
    {
        printf("%d", ip[i]);
        if (i != 3)
        {
            printf(".");
        }
    }
    printf("\n");
}
void copy_mac(u_int8_t *src, u_int8_t *dst)
{
    for (int i = 0; i < 6; i++)
    {
        dst[i] = src[i];
    }
}
void print_mac(u_int8_t *mac)
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", mac[i]);
        if (i != 5)
        {
            printf(":");
        }
    }
    printf("\n");
}

bool if_same_mac(u_int8_t *mac1, u_int8_t *mac2)
{
    for (int i = 0; i < 6; i++)
    {
        if (mac1[i] == mac2[i])
            ;
        else
        {
            return false;
        }
    }
    return true;
}

bool if_same_ip(u_int8_t *ip1, u_int8_t *ip2)
{
    for (int i = 0; i < 4; i++)
    {
        if (ip1[i] == ip2[i])
            ;
        else
        {
            return false;
        }
    }
    return true;
}

void print_logo()
{
    printf("\n █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗██╗███╗   ██╗ ██████╗ \n");
    printf("██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██║████╗  ██║██╔════╝ \n");
    printf("██████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗  ██║██╔██╗ ██║██║  ███╗\n");
    printf("██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██║██║╚██╗██║██║   ██║\n");
    printf("██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║     ██║██║ ╚████║╚██████╔╝\n");
    printf("╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ \n");
    printf("+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+\n");
    printf("|20220822|  |BOB11th|   |Network|\n");
    printf("|m|a|d|e| |b|y| |i|t|3|r|N|u|l|l|\n");
    printf("+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+\n");
    printf("git clone https://github.com/it3rNull/arp-spoof.git to use!\n\n");

    printf("+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    printf("|How to use?\n");
    printf("|syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("|sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2n\n");
    printf("+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

void sigint_handler(int signo)
{
    int choice;
    printf("You want to quit? this way doesn't guarantee ARP table recovering\n");
    while (1)
    {
        printf("1. Quit\n");
        printf("2. Keep Attack\n");
        scanf("%d", &choice);

        if (choice == 1)
        {
            printf("byebye! \n");
            exit(0);
        }
        else if (choice == 2)
        {
            printf("continue ... \n");
            return;
        }
    }
}

void add_flow(list *targets, int *count)
{
    targets = (list *)realloc(targets, sizeof(list) * (*count) + 1);
    char ip[30];
    char mac[30];
    printf("Enter sender ip address: ");
    scanf("%s", ip);
    argv_ip(ip, targets[*count].sender_ip);
    printf("Enter target ip address: ");
    scanf("%s", ip);
    argv_ip(ip, targets[*count].target_ip);
    for (int i = 0; i < *count + 1; i += 1)
    {
        printf("+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+\n");
        printf("flow %d info\n", i);
        printf("sender_%d ip addr : ", i);
        print_ip(targets[i].sender_ip);
        printf("target_%d ip addr : ", i);
        print_ip(targets[i].target_ip);
        printf("+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+\n\n");
    }

    (*count)++;
}

void view_flow(list *targets, int count)
{
    if (count == 0)
    {
        printf("no flow yet ! please Add flow to start attack\n\n");
    }
    for (int i = 0; i < count; i += 1)
    {
        printf("\n+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+\n");
        printf("flow %d info\n", i);
        printf("sender_%d ip addr : ", i);
        print_ip(targets[i].sender_ip);
        printf("target_%d ip addr : ", i);
        print_ip(targets[i].target_ip);
        printf("+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+\n\n");
    }
}
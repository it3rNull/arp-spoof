#pragma once

#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#pragma pack(push, 1)
struct EthHdr final
{
	u_int8_t dmac_[6];
	u_int8_t smac_[6];
	uint16_t type_;

	uint16_t type() { return ntohs(type_); }
	// Type(type_)
	enum : uint16_t
	{
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)

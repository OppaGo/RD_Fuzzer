#pragma once

#include <stdint.h>

/* L2 Ethernet header */
#define TYPE_IP 0x8
#define ETHERNET_SIZE sizeof(ether_h)
typedef struct _ETHERNET_HEADER {
	uint8_t		Dest[6];
	uint8_t		Source[6];
	uint16_t	Type;
} ether_h, *pether_h;


/* L3 IP header */
#define IP_MIN_SIZE 0x14
#define TCP_PROTOCOL 0x6
#define UDP_PROTOCOL 0x11
#define IPV6_PROTOCOL 0x29

typedef struct _IP_HEADER {
	uint8_t		version : 4;
	uint8_t		length : 4;
	uint8_t		service : 4;
	uint8_t		type : 4;
	uint16_t    total_len;
	uint16_t    identification;
	uint16_t	flag : 3;
	uint16_t    fragmentation : 13;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	checksum;
	uint32_t	source;
	uint32_t	destination;
	union   _ip_pad {
		uint8_t options[40];
		uint8_t pad[40];
	} ip_pad;
} ip_h, *pip_h;


/*
L4 TCP header
*/
#define TCP_MIN_SIZE	0x14
#define TCP_MAX_SIZE	sizeof(tcp_h)

typedef struct _TCP_HEADER {
	uint16_t	source;
	uint16_t	destination;
	uint32_t	sequence_number;
	uint32_t	acknowledgment_number;
	uint16_t	length : 4;
	uint16_t	reserved : 4;
	uint16_t    tcp_flags : 8;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgent;
	union   _tcp_pad {
		uint8_t options[40];
		uint8_t pad[40];
	} tcp_pad;
} tcp_h, *ptcp_h;


/*
################################################################################
# Copyright (c) 2025-present VoerEir AB - All Rights Reserved                  #
# Unauthorized copying of this file, via any medium is strictly prohibited     #
# Proprietary and confidential                                                 #
# Written by Priyangshu Bose <priyangshu@voereir.com>, Apr 2025                #
################################################################################
*/

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_icmp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define BROADCAST_MAC "FF:FF:FF:FF:FF:FF"

// ICMPv6 Message Types
#define ICMPV6_NEIGHBOR_SOLICIT 135
#define ICMPV6_NEIGHBOR_ADVERTISEMENT 136

bool is_verbose = false;

typedef enum {
	IPV4 = 4,
	IPV6 = 6
} ip_version_t;



void derive_multicast_mac_from_ipv6(struct in6_addr *ipv6_addr, struct rte_ether_addr *dst_mac) {
    // Solicited-node multicast address starts with 33:33 for MAC
    dst_mac->addr_bytes[0] = 0x33;
    dst_mac->addr_bytes[1] = 0x33;
    // Use the last 32 bits of the IPv6 address for the MAC address
    dst_mac->addr_bytes[2] = ipv6_addr->s6_addr[12];
    dst_mac->addr_bytes[3] = ipv6_addr->s6_addr[13];
    dst_mac->addr_bytes[4] = ipv6_addr->s6_addr[14];
    dst_mac->addr_bytes[5] = ipv6_addr->s6_addr[15];
}

void log_hex_dump(const char *msg,struct rte_mbuf *mbuf, int allowed_verbosity_level){
	if (!is_verbose) return;

	rte_hexdump(stdout, msg, rte_pktmbuf_mtod(mbuf, void*), rte_pktmbuf_pkt_len(mbuf));
}
ip_version_t detect_ip_version(const char *ip_str) {
	/*
	Function to detect the IP version (IPv4 or IPv6) of a given IP address string.
	Parameters:
		ip_str: IP address as a string
	*/
    struct addrinfo *address_info;
	ip_version_t ip_version;
	getaddrinfo(ip_str, NULL, NULL, &address_info);
	ip_version=address_info->ai_family == AF_INET ? IPV4 : IPV6;
	freeaddrinfo(address_info);
	return ip_version;
}
void set_ethernet_header(struct rte_ether_hdr *eth_hdr,  struct rte_ether_addr *src_mac,
						struct rte_ether_addr *dst_mac, uint16_t ether_type) {
	/*
	Function to set up the Ethernet header.
	Parameters:
		eth_hdr: Pointer to the Ethernet header
		src_mac: Pointer to the source MAC address
		dst_mac: Pointer to the destination MAC address
	*/ 

	// Set up Ethernet header
	rte_ether_addr_copy(src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}
void set_arp_header(struct rte_arp_hdr *arp_hdr, struct rte_ether_addr *src_mac, 
					struct rte_ether_addr *dst_mac, uint32_t *src_ip, uint32_t *dst_ip) {
		/*
		Function to set up the ARP header.
		Parameters:
			arp_hdr: Pointer to the ARP header
			src_mac: Pointer to the source MAC address
			dst_mac: Pointer to the destination MAC address
			src_ip: Pointer to the source IP address (in network byte order)
			dst_ip: Pointer to the destination IP address (in network byte order)
		*/

		
		// Set up ARP header
		arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
		arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
		arp_hdr->arp_plen = sizeof(uint32_t);
		arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
		// Set source hardware address (MAC) and source protocol address (IP)
		rte_ether_addr_copy(src_mac, &arp_hdr->arp_data.arp_sha);
		arp_hdr->arp_data.arp_sip = *src_ip;
		// Set target hardware address (MAC) and target protocol address (IP)
		memset(&arp_hdr->arp_data.arp_tha, 0, sizeof(struct rte_ether_addr));  // Target MAC address unknown
		arp_hdr->arp_data.arp_tip = *dst_ip;
	}

void send_arp_request(struct rte_mempool *mbuf_pool, uint16_t port_id,
					const char *src_mac_str, const char *src_ip_str,
					const char *dst_ip_str) {
	/*
	Function to send an ARP request packet.
	Parameters:
		mbuf_pool: Pointer to the memory pool for mbufs
		port_id: Port ID to send the packet on
		src_mac_str: Source MAC address as a string
		src_ip_str: Source IP address as a string
		dst_ip_str: Destination IP address as a string
	*/
	

	// Memory allocation for mbuf
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf == NULL) {
		printf("Failed to allocate mbuf\n");
		return;
	}
	// Memory allocation for headers
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_ether_addr src_mac, dst_mac;
	uint32_t src_ip, dst_ip;
	// Convert MAC addresses from string
	rte_ether_unformat_addr(src_mac_str, &src_mac);
	rte_ether_unformat_addr(BROADCAST_MAC, &dst_mac);
	// Convert IP addresses from string
	inet_pton(AF_INET, src_ip_str, &src_ip);
	inet_pton(AF_INET, dst_ip_str, &dst_ip);
	
	// Set up Ethernet header
	set_ethernet_header(eth_hdr, &src_mac, &dst_mac, RTE_ETHER_TYPE_ARP);
	// Set up ARP header
	set_arp_header(arp_hdr, &src_mac, &dst_mac, &src_ip, &dst_ip);
	// Set the packet size
	mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	mbuf->pkt_len = mbuf->data_len;
	// Print hexdump
	log_hex_dump("ARP Packet Sent", mbuf, 1);
	// Send the packet
	const uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
	if (nb_tx != 1) {
		printf("Failed to send ARP request\n");
		rte_pktmbuf_free(mbuf);
	} else {
		printf("ARP request sent to IP: %s\n", dst_ip_str);
	}
}

// Function to read and process ARP packets
int read_arp_packets(uint16_t port_id, const char *dst_ip) {
	struct rte_mbuf *bufs[BURST_SIZE];
	const uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
	for (int i = 0; i < nb_rx; i++) {
		struct rte_mbuf *mbuf = bufs[i];
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
		if (arp_hdr->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		char sender_ip[INET_ADDRSTRLEN];
		char sender_mac[RTE_ETHER_ADDR_FMT_SIZE];

		inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, sender_ip, sizeof(sender_ip));
		if (strcmp(sender_ip, dst_ip) != 0) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		log_hex_dump( "ARP Packet Received", mbuf, 1);
		rte_ether_format_addr(sender_mac, RTE_ETHER_ADDR_FMT_SIZE, &arp_hdr->arp_data.arp_sha);
		rte_ether_format_addr(sender_mac, RTE_ETHER_ADDR_FMT_SIZE, &arp_hdr->arp_data.arp_sha);
		rte_ether_format_addr(sender_mac, RTE_ETHER_ADDR_FMT_SIZE, &arp_hdr->arp_data.arp_sha);
		printf("Received ARP reply from IP: %s, MAC Address: %s\n", sender_ip, sender_mac);
		rte_pktmbuf_free(mbuf);
		return 1;
	}
	printf("Timed out.\n");
    return 0;
}

void set_ipv6_header(struct rte_ipv6_hdr *ipv6_hdr, struct in6_addr *src_ip,
						struct in6_addr *dst_ip) {
	/*
	Function to set up the IPv6 header.
	Parameters:
		ipv6_hdr: Pointer to the IPv6 header
		src_ip: Pointer to the source IP address
		dst_ip: Pointer to the destination IP address
	*/
	ipv6_hdr->vtc_flow = 0x00000060; // Version and Traffic Class
	ipv6_hdr->payload_len = rte_cpu_to_be_16(32);
	ipv6_hdr->proto = IPPROTO_ICMPV6;
	ipv6_hdr->hop_limits = 255;
	rte_memcpy(&ipv6_hdr->src_addr, src_ip, sizeof(struct in6_addr));
	rte_memcpy(&ipv6_hdr->dst_addr, dst_ip, sizeof(struct in6_addr));
}

void set_icmp_header_and_body(struct rte_ipv6_hdr *ipv6_hdr, struct rte_icmp_hdr *icmp_hdr,
							struct in6_addr *icmp_target_addr, uint8_t *ndp_options,
							 struct in6_addr *dst_ip, struct rte_ether_addr *src_mac) {
	/*
	Function to set up the ICMP header.
	Parameters:
		icmp_hdr: Pointer to the ICMP header
	*/
	icmp_hdr->icmp_type = ICMPV6_NEIGHBOR_SOLICIT;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_cksum = 0;
	// checksum calculation using both IPv6 and ICMP headers
	icmp_hdr->icmp_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, icmp_hdr);
	// Target addr after ICMPv6 header
	memcpy(icmp_target_addr, dst_ip, sizeof(struct in6_addr));
	// ICMP Body
	memset(ndp_options, 0, 8); // Clear the options field
	ndp_options[0] = 1; // Type: Source Link-Layer Address
	ndp_options[1] = 1; // Length: 1 (1 * 8 bytes = 8 bytes)
	rte_memcpy(&ndp_options[2], src_mac, RTE_ETHER_ADDR_LEN);
}

// Function to send ICMPv6 packets
void send_ndp_request(struct rte_mempool *mbuf_pool, uint16_t port_id, const char *src_mac_str, const char *src_ip_str, const char *dst_ip_str) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf == NULL) {
		printf("Failed to allocate mbuf\n");
		return;
	}
	mbuf->ol_flags &= ~RTE_MBUF_F_TX_OFFLOAD_MASK;
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(ipv6_hdr + 1);
	struct in6_addr *icmp_target_addr = (struct in6_addr *)(icmp_hdr + 1);
	uint8_t *ndp_options;
	ndp_options = (uint8_t *)(icmp_target_addr + 1);
	// Convert IP addresses from string
	struct in6_addr src_ip, dst_ip;
	inet_pton(AF_INET6, src_ip_str, &src_ip);
	inet_pton(AF_INET6, dst_ip_str, &dst_ip);
	struct rte_ether_addr src_mac, dst_mac;
	int ret = rte_ether_unformat_addr(src_mac_str, &src_mac);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid source MAC address: %s\n", src_mac_str);
	// Solicited-node multicast address
	derive_multicast_mac_from_ipv6(&dst_ip, &dst_mac);
	// Set up Ethernet header
	set_ethernet_header(eth_hdr, &src_mac, &dst_mac, RTE_ETHER_TYPE_IPV6);
	set_ipv6_header(ipv6_hdr, &src_ip, &dst_ip);
	// Set up ICMPv6 header for Neighbor Solicitation
	set_icmp_header_and_body(ipv6_hdr, icmp_hdr, icmp_target_addr, ndp_options, &dst_ip, &src_mac);
	
	// Set the packet size
	mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_icmp_hdr) + sizeof(struct in6_addr)+ sizeof(ndp_options);
	mbuf->pkt_len = mbuf->data_len;
	mbuf->l2_len = sizeof(struct rte_ether_hdr);
	mbuf->l3_len = sizeof(struct rte_ipv6_hdr);
	mbuf->l4_len = sizeof(struct rte_icmp_hdr);
	log_hex_dump( "NS Packet Sent",mbuf,1);
	const uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
	if (nb_tx != 1) {
		printf("Failed to send Neighbor Solicitation packet\n");
	} else {
		printf("Neighbor Solicitation packet sent\n");
	}
	rte_pktmbuf_free(mbuf);
}
// Function to receive and process ICMPv6 packets
int read_ndp_packets(uint16_t port_id, const char *expected_ip) {
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

    for (int i = 0; i < nb_rx; i++) {
        struct rte_mbuf *mbuf = bufs[i];
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
		if (ipv6_hdr->proto != IPPROTO_ICMPV6) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(ipv6_hdr + 1);
		if (icmp_hdr->icmp_type != ICMPV6_NEIGHBOR_ADVERTISEMENT) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		char sender_ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ipv6_hdr->src_addr, sender_ip, sizeof(sender_ip));
		if (strcmp(sender_ip, expected_ip) != 0) {
			rte_pktmbuf_free(mbuf);
			continue;
		}
		log_hex_dump("NA Packet Received",mbuf,1);
		printf("Received NDP message from IP: %s\n", sender_ip);
		struct rte_ether_addr src_mac;
		rte_ether_addr_copy(&eth_hdr->src_addr, &src_mac);
		printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
				src_mac.addr_bytes[0], src_mac.addr_bytes[1],
				src_mac.addr_bytes[2], src_mac.addr_bytes[3],
				src_mac.addr_bytes[4], src_mac.addr_bytes[5]);
		rte_pktmbuf_free(mbuf);
		return 1;
    }
	printf("Timed out.\n");
    return 0;
}

int main(int argc, char *argv[]) {
	int ret, i;
	uint16_t port_id = 0;
	struct rte_ether_addr unformatted_mac;
	char *eal_args[argc];
	int eal_argc = 1;  // EAL arguments start at argv[1], argv[0] is the program name
	eal_args[0] = argv[0];
	int retries=5;
	char src_mac[32], src_ip[32], dst_ip[32];
	for(i=1; i < argc; i++){
		printf("argv[%d]: %s, sizeof: %ld\n", i, argv[i], sizeof(*argv[i]));
		if (strcmp(argv[i], "-v")==0){
			is_verbose = true;
			continue;
		}
		else if (strcmp(argv[i], "--retry") == 0) {
			if (i + 1 < argc) {
				retries = atoi(argv[i + 1]);
                if (retries <= 1) {
                    fprintf(stderr, "Invalid retry count: %d\n", retries);
                    return 1;
                }
                i++; 
			}
			else {
                fprintf(stderr, "--retry requires a numeric value\n");
                return 1;
            }
		}
		else{
			eal_args[eal_argc++] = argv[i];
		}
	}
	
	
	
	ret = rte_eal_init(eal_argc, eal_args);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	if (argc <= 3){
		rte_exit(EXIT_FAILURE, "Expected 3 arguments (src_mc, src_ip, dst_ip). Received: %d\n", argc - 1);
	}
	// Initialize the memory pool
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * 2, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	// At most 32 bytes will be copied. Will terminate at NULL, except when last param is set to 0;
	rte_strscpy(src_mac, argv[1], 32);
	rte_strscpy(src_ip, argv[2], 32);
	rte_strscpy(dst_ip, argv[3], 32);

	printf("Source Mac: %s\n", src_mac);
	printf("Source IP: %s\n", src_ip);
	printf("Destination IP: %s\n", dst_ip);
   	
	// Initialize Ethernet port
	struct rte_eth_conf port_conf = {0};
	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure Ethernet port\n");

	ret = rte_ether_unformat_addr(src_mac, &unformatted_mac);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid source MAC address: %s\n", src_mac);

	// Set the MAC address for the specified port
	ret = rte_eth_dev_default_mac_addr_set(port_id, &unformatted_mac);
	ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot setup RX queue\n");
	ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot setup TX queue\n");
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot start Ethernet port\n");
	ip_version_t ip_version = detect_ip_version(src_ip);
   	if (ip_version != detect_ip_version(dst_ip)) {
      	  rte_exit(EXIT_FAILURE, "Mismatch in IP Versions\n");
	}
	rte_eth_promiscuous_disable(port_id);
	if (ip_version == IPV6){
   		while(retries--){
			send_ndp_request(mbuf_pool, port_id, src_mac, src_ip, dst_ip);
			usleep(200);
			if(read_ndp_packets(port_id,dst_ip)){
						break;
			}
		}
	}
	else{
    	while(retries--){
      		send_arp_request(mbuf_pool, port_id, src_mac, src_ip, dst_ip);
			usleep(200);
     		if(read_arp_packets(port_id,dst_ip)){
        		break;
      		}
    	}
    }
    rte_eth_dev_stop(port_id);
   	rte_eth_dev_close(port_id);
   	return 0;
}

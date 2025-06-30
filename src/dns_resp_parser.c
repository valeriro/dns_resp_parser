#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dns_resp_parser.h"


#define ETHERNET_HEADER_LENGTH 14


struct dns_header {
    uint16_t 	id;
    uint8_t 	rd :1, tc :1, aa :1, opcode :4, qr :1;
    uint8_t 	rcode :4, z :3, ra :1;
    uint16_t 	q_count;
    uint16_t 	ans_count;
    uint16_t 	auth_count;
    uint16_t 	add_count;
};


/**
 * 1. Reads a DNS-encoded domain name from the packet buffer.
 * 2. Handles DNS name compression.
 *
 * Params:
 * 			reader        Pointer to current read position in DNS message
 * 			packet_start  Pointer to start of DNS packet (needed for jumps)
 * 			packet_end    Pointer to end of DNS packet (for bounds checking)
 * 			output        Output buffer for the decoded domain name
 * 			output_len    Length of the output buffer
 *
 * return 
 *			number of bytes processed from the original reader position (for non-jumped),
 *          or -1 on failure (malformed name or out-of-bounds)
 */


int read_dns_name(const uint8_t *reader,
                  const uint8_t *packet_start,
                  const uint8_t *packet_end,
                  char *output,
                  size_t output_len)
{
    const uint8_t *current = reader;
    size_t output_index = 0;
    int processed = 0;
    int jumped = 0;

    while (current < packet_end)
    {
        uint8_t label_len = *current;

        // End of name
        if (label_len == 0)
        {
            if (!jumped)
                processed++;
            break;
        }

        // Pointer (compressed name)
        if ((label_len & 0xC0) == 0xC0)
        {
            if (current + 1 >= packet_end)
                return -1;

            uint16_t offset = ((label_len & 0x3F) << 8) | current[1];
            const uint8_t *jump_target = packet_start + offset;

            if (jump_target >= packet_end)
                return -1;

            if (!jumped)
                processed += 2;

            current = jump_target;
            jumped = 1;
            continue;
        }

        // Regular label
        current++;
        if (!jumped)
            processed++;

        if (current + label_len > packet_end || output_index + label_len + 1 >= output_len)
            return -1;

        // Add dot if not first label
        if (output_index != 0)
            output[output_index++] = '.';
	
		memcpy(output + output_index, current, label_len);
		output_index += label_len;

        current += label_len;
        if (!jumped)
            processed += label_len;
    }

    // Null-terminate the output
    if (output_index >= output_len)
        return -1;
	
    output[output_index] = '\0';

    return processed;
}

/**
 * Parses a raw Ethernet packet to extract and display DNS response.
 *
 * This function assumes the packet is an Ethernet frame containing an IPv4/UDP/DNS packet.
 * It extracts the queried domain name and any A (IPv4) and AAAA (IPv6) answers from the
 * DNS section and prints them.
 *
 * Params:
 *			buffer -  Pointer to the raw packet data.
 * 			len    -  Length of the packet buffer.
 */
void process_dns_packet(uint8_t *buffer, int len) 
{
	if(! buffer)
		return;
	
	// Minimum required size: Ethernet + IP + UDP headers
	if (len < (ETHERNET_HEADER_LENGTH + sizeof(struct iphdr) + sizeof(struct udphdr)) ) 
		return;

	// IP header is after Ethernet header (14 bytes)
	struct iphdr *iph = (struct iphdr *)(buffer + ETHERNET_HEADER_LENGTH);
	
	// no need to check it (bpf)
	//if (iph->protocol != IPPROTO_UDP) 
	//	return;

    // Calculate IP header length (in bytes)
    int iphdrlen = iph->ihl * 4;

    // UDP header follows IP header
    struct udphdr *udph = (struct udphdr *)(buffer + ETHERNET_HEADER_LENGTH + iphdrlen);

    // DNS section follows UDP header
    uint8_t *dns_start = (uint8_t *)udph + sizeof(struct udphdr);
    uint8_t *end = buffer + len;

    // Basic safety check: DNS header must fit
    if (dns_start + sizeof(struct dns_header) > end)
        return;

    // Cast to DNS header structure
    struct dns_header *dns = (struct dns_header *)dns_start;

	// Only process DNS responses (qr == 1)
	if (dns->qr != 1)
		return;

	// optional check for authoritative answer
	/*
	if (dns->aa == 1) 
	{
		printf("This is an authoritative answer.\n");
	} 
	else 
	{
		printf("This is a non-authoritative answer (from a recursive resolver).\n");
	}
	*/
	
    // Pointer to the start of the Question section
    uint8_t *reader = dns_start + sizeof(struct dns_header);

    // Decode the queried domain name
    char domain[256];
    int processed = read_dns_name(reader, dns_start, end, domain, sizeof(domain));
    if (processed < 0) 
	{
        return;
    }
	
	#ifdef DNS_SNIFFER_DEBUG
		printf("read_dns_name (ret processed):%d\n", processed);
	#endif// DNS_SNIFFER_DEBUG
	
    reader += processed;

    // skip QTYPE (2 bytes) + QCLASS (2 bytes)
    if (reader + 4 > end) {
        return;
    }
    reader += 4;

    // Prepare storage for IPv4 and IPv6 results
    char ipv4_list[10][INET_ADDRSTRLEN];
    char ipv6_list[10][INET6_ADDRSTRLEN];
    int ipv4_cnt = 0, ipv6_cnt = 0;

    // Parse the Answer section
    int answer_count = ntohs(dns->ans_count);
    for (int i = 0; i < answer_count && reader < end; i++) 
	{
        // decode the answer's domain name (can be a pointer)
        char ans_name[256];
        int name_len = read_dns_name(reader, dns_start, end, ans_name, sizeof(ans_name));
        if (name_len < 0) 
		{
            break;
        }
		
		#ifdef DNS_SNIFFER_DEBUG
			printf("read_dns_name (ret name_len):%d\n", name_len);
		#endif// DNS_SNIFFER_DEBUG
		
        reader += name_len;

        // ensure space for TYPE, CLASS, TTL, RDLENGTH
        if (reader + 10 > end) {
            break;
        }

        uint16_t type = ntohs(*(uint16_t *)reader);
        reader += 2;
        reader += 2; // CLASS
        reader += 4; // TTL
        uint16_t data_len = ntohs(*(uint16_t *)reader);
        reader += 2;

        // Ensure data field fits in buffer
        if (reader + data_len > end) {
            break;
        }

        // Extract and format IP addresses
        if (type == 1 && data_len == 4 && ipv4_cnt < 10) 
		{
            // A record (IPv4)
            inet_ntop(AF_INET, reader, ipv4_list[ipv4_cnt++], INET_ADDRSTRLEN);
        } 
		else if (type == 28 && data_len == 16 && ipv6_cnt < 10) 
		{
            // AAAA record (IPv6)
            inet_ntop(AF_INET6, reader, ipv6_list[ipv6_cnt++], INET6_ADDRSTRLEN);
        }

        // Move past RDATA
        reader += data_len;
    }

    // display parsed output
    printf("\nDomain: %s\n", domain);

	if(ipv4_cnt)
	{
		printf("Address IPv4: ");
        for (int i = 0; i < ipv4_cnt; i++) 
		{
            printf("%s%s", ipv4_list[i], (i < ipv4_cnt - 1 ? ", " : "\n"));
        }
    }

  
	if(ipv6_cnt)
	{
		printf("Address IPv6: ");
        for (int i = 0; i < ipv6_cnt; i++) 
		{
            printf("%s%s", ipv6_list[i], (i < ipv6_cnt - 1 ? ", " : "\n"));
        }
    }
}


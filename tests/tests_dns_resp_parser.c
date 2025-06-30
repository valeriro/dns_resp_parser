#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/ip.h>

#include "dns_resp_parser.h"  // include the declaration of a source file

#define ETHERNET_HEADER_LENGTH  14

void test_read_dns_name_basic() {
    // Construct DNS name manually: 3www6google3com0
    uint8_t dns_packet[512];
    memset(dns_packet, 0, sizeof(dns_packet));

    uint8_t *p = dns_packet;
    *p++ = 3; memcpy(p, "www", 3); p += 3;
    *p++ = 6; memcpy(p, "google", 6); p += 6;
    *p++ = 3; memcpy(p, "com", 3); p += 3;
    *p++ = 0; // Null terminator

    char output[256];
    int res = read_dns_name(dns_packet, dns_packet, dns_packet + sizeof(dns_packet), output, sizeof(output));
	assert(res > 0);
    assert(strcmp(output, "www.google.com") == 0);
    printf("OK - Basic label test passed: %s\n", output);
}
void test_read_dns_name_with_pointer() {
    // Manually construct a message with pointer compression:
    //
    // offset 0x00: 3www7example3com0
    // offset 0x10: 0xC0 0x00 (pointer to offset 0)
    uint8_t dns_packet[512];
    memset(dns_packet, 0, sizeof(dns_packet));

    // Write original name at offset 0
    uint8_t *base = dns_packet;
    *base++ = 3; memcpy(base, "www", 3); base += 3;
    *base++ = 7; memcpy(base, "example", 7); base += 7;
    *base++ = 3; memcpy(base, "com", 3); base += 3;
    *base++ = 0;

    // Pointer at offset 0x20
    dns_packet[0x20] = 0xC0;
    dns_packet[0x21] = 0x00;

    char output[256];
    int res = read_dns_name(dns_packet + 0x20, dns_packet, dns_packet + sizeof(dns_packet), output, sizeof(output));
	assert(res > 0);
    assert(strcmp(output, "www.example.com") == 0);
    printf("OK - Pointer compression test passed: %s\n", output);
}

void test_read_dns_name_nested_pointer() {
    // Create nested compression:
    // offset 0x00: 7example3com0
    // offset 0x10: 3www C0 00
    // offset 0x20: C0 10

    uint8_t dns_packet[512];
    memset(dns_packet, 0, sizeof(dns_packet));

    // Offset 0x00: example.com
    uint8_t *p = dns_packet;
    *p++ = 7; memcpy(p, "example", 7); p += 7;
    *p++ = 3; memcpy(p, "com", 3); p += 3;
    *p++ = 0;

    // Offset 0x10: www.[pointer to 0x00]
    dns_packet[0x10] = 3; memcpy(&dns_packet[0x11], "www", 3);
    dns_packet[0x14] = 0xC0;  // pointer
    dns_packet[0x15] = 0x00;

    // Offset 0x20: pointer to 0x10
    dns_packet[0x20] = 0xC0;
    dns_packet[0x21] = 0x10;

    char output[256];
    int res = read_dns_name(dns_packet + 0x20, dns_packet, dns_packet + sizeof(dns_packet), output, sizeof(output));
	
	assert(res > 0);
    assert(strcmp(output, "www.example.com") == 0);
    printf("OK - Nested pointer test passed: %s\n", output);
}

void test_read_dns_name_truncated_output()
{
	uint8_t packet[] = {3,'a','b','c',3,'c','o','m',0};
	char small_buf[4]; // too small to hold full name
	int res = read_dns_name(packet, packet, packet + sizeof(packet), small_buf, sizeof(small_buf));
	assert(res == -1);
	printf("OK - Truncated output buffer correctly rejected.\n");
}

void test_read_dns_name_invalid_pointer() 
{
	uint8_t packet[64] = {0};
	packet[0] = 0xC0;
	packet[1] = 0x80; // pointer to 0xFF (out of bounds)

	char output[256];
	int res = read_dns_name(packet, packet, packet + sizeof(packet), output, sizeof(output));
	assert(res == -1);
	printf("OK - Out-of-bounds pointer correctly rejected.\n");
}

void test_dns_packet_simple_a_record()
{
	uint8_t packet[512] = {0};
	uint8_t* ptr = packet;

	// Ethernet header: dummy 14 bytes
	ptr += ETHERNET_HEADER_LENGTH;

	// IP header
	struct iphdr* ip = (struct iphdr*)ptr;
	ip->ihl = 5;
	ip->protocol = IPPROTO_UDP;
	ptr += 20;

	// UDP header
	//struct udphdr* udp = (struct udphdr*)ptr;
	ptr += 8;

	// DNS header
	ptr += 2;  // Skip ID field

	*ptr++ = 0x81; // Flags byte 1
	*ptr++ = 0x80; // Flags byte 2

	*ptr++ = 0x00; // QDCOUNT byte 1
	*ptr++ = 0x01; // QDCOUNT byte 2

	*ptr++ = 0x00; // ANCOUNT byte 1
	*ptr++ = 0x01; // ANCOUNT byte 2	

	// Question: www.example.com
	*ptr++ = 3; memcpy(ptr, "www", 3); ptr += 3;
	*ptr++ = 6; memcpy(ptr, "google", 6); ptr += 6;
	*ptr++ = 3; memcpy(ptr, "com", 3); ptr += 3;
	*ptr++ = 0;

	// QTYPE + QCLASS
	*ptr++ = 0x00; *ptr++ = 0x01;
	*ptr++ = 0x00; *ptr++ = 0x01;

	// Answer: Name (pointer to offset 0x0c)
	*ptr++ = 0xC0; *ptr++ = 0x0C;
	*ptr++ = 0x00; *ptr++ = 0x01; // TYPE = A
	*ptr++ = 0x00; *ptr++ = 0x01; // CLASS = IN
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x3C; // TTL = 60
	*ptr++ = 0x00; *ptr++ = 0x04; // RDLENGTH = 4
	*ptr++ = 142;  // 142.250.75.142
	*ptr++ = 250;
	*ptr++ = 75;
	*ptr++ = 142;

	int total_len = ptr - packet;

	printf("--- test_dns_packet_simple_a_record ---\n");
	process_dns_packet(packet, total_len);
	printf("---------------------------------------\n\n");
}


void test_dns_packet_aaaa_record()
{
    uint8_t packet[512] = {0};
    uint8_t* ptr = packet;

    ptr += ETHERNET_HEADER_LENGTH;

    struct iphdr* ip = (struct iphdr*)ptr;
    ip->version = 4; ip->ihl = 5; 
	//ip->protocol = IPPROTO_UDP;
    ptr += 20;
    ptr += 8; // UDP

    ptr += 2; // ID

    *ptr++ = 0x81; *ptr++ = 0x80;
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x01;

    *ptr++ = 3; memcpy(ptr, "www", 3); ptr += 3;
    *ptr++ = 6; memcpy(ptr, "google", 6); ptr += 6;
    *ptr++ = 3; memcpy(ptr, "com", 3); ptr += 3;
    *ptr++ = 0;

    *ptr++ = 0x00; *ptr++ = 0x1C; // QTYPE=28 (AAAA)
    *ptr++ = 0x00; *ptr++ = 0x01;

    *ptr++ = 0xC0; *ptr++ = 0x0C;
    *ptr++ = 0x00; *ptr++ = 0x1C; // type AAAA
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x3C; // TTL 60
    *ptr++ = 0x00; *ptr++ = 0x10; // RDLENGTH 16

    // IPv6 address: 2001:4860:4860::8888 (Google DNS)
    uint8_t ipv6_addr[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    memcpy(ptr, ipv6_addr, 16);
    ptr += 16;

    int total_len = ptr - packet;

    printf("--- test_dns_packet_aaaa_record ---\n");
    process_dns_packet(packet, total_len);
    printf("-----------------------------------\n\n");
}


void test_dns_packet_multiple_answers()
{
    uint8_t packet[512] = {0};
    uint8_t* ptr = packet;

    ptr += ETHERNET_HEADER_LENGTH;
    struct iphdr* ip = (struct iphdr*)ptr;
    ip->version = 4; ip->ihl = 5; 
	//ip->protocol = IPPROTO_UDP;
    ptr += 20;
    ptr += 8; // UDP

    ptr += 2; // ID

    *ptr++ = 0x81; *ptr++ = 0x80;
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x02; // ANCOUNT = 2

    *ptr++ = 3; memcpy(ptr, "www", 3); ptr += 3;
    *ptr++ = 6; memcpy(ptr, "google", 6); ptr += 6;
    *ptr++ = 3; memcpy(ptr, "com", 3); ptr += 3;
    *ptr++ = 0;

    *ptr++ = 0x00; *ptr++ = 0x01; // QTYPE=A
    *ptr++ = 0x00; *ptr++ = 0x01; // QCLASS=IN

    // Answer 1: A record
    *ptr++ = 0xC0; *ptr++ = 0x0C;
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x3C;
    *ptr++ = 0x00; *ptr++ = 0x04;
    *ptr++ = 142; *ptr++ = 250; *ptr++ = 75; *ptr++ = 142;

    // Answer 2: AAAA record
    *ptr++ = 0xC0; *ptr++ = 0x0C;
    *ptr++ = 0x00; *ptr++ = 0x1C;
    *ptr++ = 0x00; *ptr++ = 0x01;
    *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x3C;
    *ptr++ = 0x00; *ptr++ = 0x10;
    uint8_t ipv6_addr[16] = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,0,0,0x88,0x88};
    memcpy(ptr, ipv6_addr, 16);
    ptr += 16;

    int total_len = ptr - packet;

    printf("--- test_dns_packet_multiple_answers ---\n");
    process_dns_packet(packet, total_len);
    printf("----------------------------------------\n\n");
}

int main() {
    test_read_dns_name_basic();
    test_read_dns_name_with_pointer();
    test_read_dns_name_nested_pointer();
	test_read_dns_name_truncated_output();
	test_read_dns_name_invalid_pointer();
	test_dns_packet_simple_a_record();
	test_dns_packet_aaaa_record();
	test_dns_packet_multiple_answers();
	
    printf("\nAll read_dns_name() unit tests passed.\n");
    return 0;
}

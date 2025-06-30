#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <unistd.h>

#include "dns_resp_parser.h"


#define BUF_SIZE 65536


void print_packet_in_hex(uint8_t *buffer, int len)
{
	for(int i = 0; i<len; i++)
	{
		printf("%#x ", buffer[i]);
	}
}

int main() {
    int sockfd;
    uint8_t buffer[BUF_SIZE];

	struct sock_filter bpf_filter[] = {
    { 0x28, 0, 0, 12 },           // Load EtherType
    { 0x15, 0, 5, 0x0800 },       // IPv4?
    { 0x30, 0, 0, 23 },           // IP protocol
    { 0x15, 0, 3, 17 },           // UDP?
    { 0x28, 0, 0, 34 },           // UDP src port
    { 0x15, 0, 1, 53 },           // src DNS port == 53?
    { 0x6,  0, 0, 0xFFFF },       // accept
    { 0x6,  0, 0, 0 }             // drop
	};

	struct sock_fprog bpf_prog = 
	{
		.len = sizeof(bpf_filter) / sizeof(struct sock_filter),
		.filter = bpf_filter
	};
	
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket create error");
        return 1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0) 
	{
        perror("setsockopt(SO_ATTACH_FILTER) error");
        close(sockfd);
        return 1;
    }

    printf("Listening for DNS responses...\n");

    while (1) 
	{
        ssize_t len = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
        if (len > 0)
		{
			
	#ifdef DNS_SNIFFER_DEBUG
			print_packet_in_hex(buffer, len);
	#endif // #ifdef DNS_SNIFFER_DEBUG
	
            process_dns_packet(buffer, len);
		}
    }

    close(sockfd);
    return 0;
}
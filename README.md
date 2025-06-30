DNS Packet Sniffer
=======================================================================================
A DNS response parser for raw Ethernet packet data. This tool extracts domain names and 
resolved IP addresses (IPv4 and IPv6) from DNS responses.

This parser is designed to work with raw packet capture buffers and 
is typically fed data via AF_PACKET sockets. 
A BPF (Berkeley Packet Filter) is used to filter incoming traffic 
so that only DNS response packets (UDP port 53 with QR=1) are passed to user space.


Features
========================================================================================
Parses raw DNS response packets (IPv4/UDP).

BPF filter restricts incoming packets to DNS responses only, improving efficiency.

Supports DNS name compression (pointers and labels).

Extracts domain names and associated A (IPv4) and AAAA (IPv6) records.



Project Structure
========================================================================================


- `dns_resp_parser/`
  - `src/`
    - `dns_resp_parser.c` – Core DNS response parsing implementation
    - `dns_resp_parser.h` – DNS response parser header file
    - `main.c` – Main program (socket creation and BPF filter implementation)
    - `Makefile` – Builds the parser and example program
  - `tests/`
    - `tests_dns_resp_parser.c` – Unit tests for DNS response parser
    - `Makefile` – Builds and runs tests
- `README.md` – Project overview and instructions
- `.git/` – Git repository files



Build Instructions
=========================================================================================

Main parser:
-------------------------------------------------------
            cd src
	
	1. Build:
            make
	2. Clean:
            make clean
	3. Run:
            sudo ./dns_resp_parser

Unit tests:
-------------------------------------------------------
            cd tests
		
	1. Build:
            make
	2. Clean:
            make clean
	3. Run:
            ./tests_dns_resp_parser




Configuration
=======================================================================================
Optional defines (in dns_resp_parser.h):

    #define DNS_SNIFFER_DEBUG // Enables debug prints



Run the DNS parser example
=======================================================================================

The program will listen for DNS response packets  and print parsed domain names and their resolved IP addresses (both IPv4 and IPv6): 

1. Please run as the following (1st terminal):

         cd src
         sudo ./dns_resp_parser

2. Please run a DNS request (2nd terminal):

         nslookup www.google.com

3. Result (1st terminal):

         Domain: www.google.com
         Address IPv4: 142.250.75.132

         Domain: www.google.com
         Address IPv6: 2a00:1450:4028:806::2004




Unit tests:
======================================================================================

How to build and run:
--------------------------------------------------------
            cd tests
		
	1. Build:
            make
	2. Clean:
            make clean
	3. Run:
           ./tests_dns_resp_parser



Covered Test Cases:
--------------------------------------------------------
**test_read_dns_name_basic()**              Tests standard label-based domain like www.google.com
**test_read_dns_name_with_pointer()**       Tests DNS name using pointer compression (0xC0 offset)
**test_read_dns_name_nested_pointer()**     Tests nested pointers pointing to compressed names
**test_read_dns_name_truncated_output()**   Ensures output buffer overflow is safely handled
**test_read_dns_name_invalid_pointer()**    Ensures out-of-bound pointers are correctly rejected
**test_dns_packet_simple_a_record()**       Tests a complete DNS packet with an A record
**test_dns_packet_aaaa_record()**           Tests a DNS packet with an AAAA record (IPv6 address)
**test_dns_packet_multiple_answers()**      Tests DNS packet with multiple answers (A and AAAA)


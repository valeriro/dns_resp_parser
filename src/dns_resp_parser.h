/*
 * dns_resp_parser.h
 *
 *  Created on: Jun 27, 2025
 *      Author: Valeri Rozin
 */

#ifndef DNS_RESP_PARSER_H_
#define DNS_RESP_PARSER_H_

//#define DNS_SNIFFER_DEBUG // enables debug prints


int read_dns_name(const uint8_t *reader,
                  const uint8_t *packet_start,
                  const uint8_t *packet_end,
                  char *output,
                  size_t output_len);
				  
void process_dns_packet
				(uint8_t *buffer, 
				int len) ;


#endif /* DNS_RESP_PARSER_H_ */
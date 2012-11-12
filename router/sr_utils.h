/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

#include <stdbool.h>
#include "sr_router.h"

#define ETHERNET_MTU 1500

// ICMP Types
#define ICMP_UNREACHABLE_TYPE 3
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_TIME_EXCEEDED_TYPE 11

// ICMP Codes
#define ICMP_ECHO_CODE 0
#define ICMP_TIME_EXCEEDED_CODE 0
#define ICMP_NET_UNREACHABLE_CODE 0
#define ICMP_HOST_UNREACABLE_CODE 1
#define ICMP_PORT_UNREACHABLE_CODE 3


uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

/* Utilities for verifying size of packets */
/* All expect the size of just the entity being checked for
* i.e., don't pass the whole ethernet frame size unless that's
* what you want to verify */

/* Eth + IP Utilities */
//Check whether the given transmission was addressed to the given interface
bool is_dest_if(sr_instance_t *sr, uint8_t *eth_frame, char *if_name);

/* Ethernet Utilities */
bool valid_eth_size(unsigned int n);

/* IP Header Utilities */
void set_ip_checksum(sr_ip_hdr_t *header);
bool valid_ip_header(sr_ip_hdr_t *pkt); //only checks header
uint8_t dec_ttl(sr_ip_hdr_t *pkt_hdr);

/* ARP Utilities */
//bool valid_arp_size(unsigned int n);

/* ICMP Utilities */
bool valid_icmp_echo_request(uint8_t *eth_frame, unsigned int frame_len);
bool valid_icmp_checksum(sr_icmp_hdr_t *icmp_hdr, unsigned int icmp_len);
void set_icmp_checksum(sr_icmp_hdr_t *icmp_hdr, unsigned int icmp_len);
unsigned int icmp_len(uint8_t *eth_frame, unsigned int frame_len);

/* Extract higher layer headers from ethernet frame */
sr_ip_hdr_t *ip_header(uint8_t *eth_frame);
sr_icmp_hdr_t *icmp_header(uint8_t *eth_frame);

#endif /* -- SR_UTILS_H -- */

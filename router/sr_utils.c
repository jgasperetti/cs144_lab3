#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include <stdbool.h>

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}


bool valid_eth_size(unsigned int n) {
    if (n < sizeof(sr_ethernet_hdr_t)) return false;
    if (n > ETHERNET_MTU) return false;
    return true;
}

bool valid_ip_size(unsigned int n) {
    if (n < sizeof(sr_ip_hdr_t)) return false;
    if (n > ETHERNET_MTU) return false;
    return true;
}

bool valid_ip_header_size(unsigned int ihl) {
    if (ihl < 5) return false;
    if (ihl > 5) {
        printf("Longer than usual IP header: %d\n", ihl);
    }
    return true;
}

bool valid_arp_size(unsigned int n) {
    if (n < sizeof(sr_arp_hdr_t)) return false;
    return true;
}

#define BYTES_PER_IP_WORD 4
/**
* Assumes you've already checked that header length is valid.
**/
bool valid_ip_checksum(sr_ip_hdr_t *pkt) {
    uint16_t transmitted_cksum = pkt->ip_sum;
    pkt->ip_sum = 0;
    uint16_t computed_cksum = cksum(pkt, pkt->ip_hl * 4);
    pkt->ip_sum = transmitted_cksum;
    if (computed_cksum != transmitted_cksum) return false;
    return true;
}

void set_ip_checksum(sr_ip_hdr_t *header) {
    header->ip_sum = 0;
    header->ip_sum = cksum(header, header->ip_hl * BYTES_PER_IP_WORD);
}

/* Returns the length of the ICMP section of an ethernet frame */
unsigned int icmp_len(uint8_t *eth_frame, unsigned int frame_len) {
    sr_icmp_hdr_t *header = icmp_header(eth_frame);
    unsigned int eth_ip_hdr_size = (void *)header - (void *)eth_frame;
    return frame_len - eth_ip_hdr_size;
}

/* Assumes that icmp_len encompasses header + data which follows */
void set_icmp_checksum(sr_icmp_hdr_t *icmp_hdr, unsigned int icmp_len) {
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);
}

bool valid_icmp_checksum(sr_icmp_hdr_t *icmp_hdr, unsigned int icmp_len) {
    uint16_t transmitted = icmp_hdr->icmp_sum;
    set_icmp_checksum(icmp_hdr, icmp_len);
    uint16_t computed = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = transmitted;
    return (transmitted == computed);
}

//get addr of arp header from eth frame
sr_arp_hdr_t *arp_header(uint8_t *eth_frame) {
    return (sr_arp_hdr_t *)(eth_frame + sizeof(sr_ethernet_hdr_t));
}

bool valid_ip_header(sr_ip_hdr_t *pkt) {
    sr_ip_hdr_t *hdr = (sr_ip_hdr_t *)pkt;

    if(!valid_ip_header_size(hdr->ip_hl)) {
        printf("IP bad header size \n");
        return false;
    }

    if(!valid_ip_size(ntohs(hdr->ip_len))) {
        printf("IP bad size:%d \n", ntohs(hdr->ip_len));
        return false;
    }

    if(!valid_ip_checksum(hdr)) {
        printf("IP bad checksum\n");
        return false;
    }
    return true;
}

bool valid_icmp_echo_request(uint8_t *eth_frame,
    unsigned int frame_len) {
    
    //Check type and code
    sr_icmp_hdr_t *header = icmp_header(eth_frame);
    if (header->icmp_type != ICMP_ECHO_REQUEST_TYPE) return false;
    if (header->icmp_code != ICMP_ECHO_CODE) return false;

    //Check checksum
    if(!valid_icmp_checksum(header, icmp_len(eth_frame, frame_len))) return false;

    return true;
}

sr_ip_hdr_t *ip_header(uint8_t *eth_frame) {
    return (sr_ip_hdr_t *) (eth_frame + sizeof(sr_ethernet_hdr_t));
}

sr_icmp_hdr_t *icmp_header(uint8_t *eth_frame) {
    sr_ip_hdr_t *ip_hdr = ip_header(eth_frame);
    unsigned int icmp_hdr_offset = ip_hdr->ip_hl * BYTES_PER_IP_WORD;
    return (sr_icmp_hdr_t *) ((void *)ip_hdr + icmp_hdr_offset);
}


/**
* Decrements and returns the TTL of an ip packet
**/
uint8_t dec_ttl(sr_ip_hdr_t *pkt_hdr)
{
    uint8_t ttl = pkt_hdr->ip_ttl;
    if (ttl == 0) return 0;
    --ttl;
    pkt_hdr->ip_ttl = ttl;
    return ttl;
}

bool eth_addr_eq(uint8_t *addr1, uint8_t *addr2)
{
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if (addr1[i] != addr2[i]) return false;
    }
    return true;
}

/**
* Determines whether the given packet is destined for
* the given local interface
* Checks that the eth addr matches and that the ip
* matches any IP on the device.
**/
bool is_dest_if(sr_instance_t *sr, uint8_t *eth_frame,
    char *if_name)
{
    // Check for eth addr match
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) eth_frame;
    sr_if_t *iface = sr_get_interface(sr, if_name);
    if(!eth_addr_eq(eth_hdr->ether_dhost, iface->addr)) return false;

    sr_ip_hdr_t *ip_hdr = ip_header(eth_frame);
    uint32_t dst_ip = ip_hdr->ip_dst;

    for (struct sr_if *if_walker = sr->if_list;
         if_walker != NULL;
         if_walker=if_walker->next) {

        //uint32_t if_ip = if_walker->ip;
        if (if_walker->ip == dst_ip){
            printf("Match on interface %.4s\n", if_walker->name);
            print_addr_ip_int(if_walker->ip);
            printf("\n");
            print_addr_ip_int(dst_ip);
            
            return true;
        }

    }

    return false;
}

uint8_t *new_eth_frame(uint8_t *src_addr, 
                       uint8_t *dst_addr,
                       unsigned int data_len)
{
    sr_ethernet_hdr_t *hdr = malloc(sizeof(sr_ethernet_hdr_t) + data_len);
    memcpy(hdr->ether_dhost, dst_addr, ETHER_ADDR_LEN);
    memcpy(hdr->ether_shost, src_addr, ETHER_ADDR_LEN);

    return (uint8_t *)hdr;
}


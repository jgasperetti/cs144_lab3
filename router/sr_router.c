/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void transmit_ethernet_frame(sr_instance_t *sr, uint8_t *eth_frame,
    unsigned int frame_len)
{
    printf("\n\nWill try to transmit the following ethernet frame\n");
    printf("Length: %d\n", frame_len);
    print_hdrs(eth_frame, frame_len);
    printf("\nChecking Validity: ");
    if (valid_ip_header(ip_header(eth_frame))) {
        printf("Success!!\n"); 
    } else {
        printf("Utter failure!\n");
    }
    printf("Checking icmp checksum: ");
    if (valid_icmp_checksum(icmp_header(eth_frame),
                            icmp_len(eth_frame, frame_len))) {
        printf("Success!\n");
    } else {
        printf("Failure!\n");
    }
    printf("END\n\n");
}

enum icmp_response {
    icmp_echo_reply,
    icmp_dest_unreachable,
    icmp_dest_host_unreachable,
    icmp_port_unreachable,
    icmp_time_exceeded
};

void respond_with_icmp(sr_instance_t  *sr, uint8_t *eth_frame,
    unsigned int frame_len, char *incoming_if,
    enum icmp_response response_type)
{

    //sr_ip_hdr_t *ip_hdr = ip_header(eth_frame);

    switch(response_type) {
    case icmp_echo_reply:
        break;
    case icmp_dest_unreachable:
        break;
    case icmp_dest_host_unreachable:
        break;
    case icmp_port_unreachable:
        break;
    case icmp_time_exceeded:
        break;
    }

}

/**
* Call this method on incoming packets that need to be routed.
* This means doing all of the prep necessary to send it out,
* as well as actually dispatching it on an interface.
*
* Do not call this function on packets whose lives end at this hop.
**/
void route_ip_packet(sr_instance_t * sr, uint8_t *eth_frame,
    unsigned int frame_len, char *incoming_if)
{
    printf("Routing IP Packet\n");
    sr_ip_hdr_t *ip_hdr = ip_header(eth_frame);
    if (dec_ttl(ip_hdr) == 0) {
        //Send ICMP time expired
        return;
    }

    sr_rt_t *route = lookup_route(sr, ip_hdr->ip_dst);
    if(!route) {
        printf("No route to host:");
        print_addr_ip_int(ntohl(ip_hdr->ip_dst));
        printf("\n");
        //Send ICMP no route to host
        return;
    }

    sr_if_t *iface = sr_get_interface(sr, route->interface);

    //Set source Eth addr for outgoing interface
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth_frame;
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    uint32_t gw_ip = route->gw.s_addr;
    char *if_name = route->interface;

    set_dst_eth_and_transmit(sr, eth_frame, frame_len, gw_ip, if_name);

}

/**
* Packets addressed to an interface of this device are handled here.
* The only kind of message we care about is ICMP Echo Request, we drop
* anything else.
**/
void handle_local_packet(sr_instance_t *sr, uint8_t *eth_frame,
    unsigned int frame_len, char *interface)
{
    printf("Handling local packet\n");

    uint8_t *ip_pkt = (uint8_t *)ip_header(eth_frame);
    if (ip_protocol(ip_pkt) != ip_protocol_icmp) {
        printf("Got garbage other than ICMP addressed to router\n");
        //TODO send ICMP unreachable response of some sort?
        return;
    }

    printf("Handling ICMP message addressed to router\n");
    if (!valid_icmp_echo_request(eth_frame, frame_len)) {
        printf("Dropping ICMP that's not valid ECHO request\n");
        // TODO: respond with ICMP unreachable of some sort?
    }
   

    /** Transform ICMP Echo Request into Response **/
    
    //Change ICMP type
    sr_icmp_hdr_t *icmp_hdr = icmp_header(eth_frame);
    icmp_hdr->icmp_type = ICMP_ECHO_REPLY_TYPE; 

    //Set ICMP checksum
    set_icmp_checksum(icmp_hdr, icmp_len(eth_frame, frame_len));

    //IP Header - Flip addresses
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)ip_pkt;
    uint32_t old_src = ip_header->ip_src;
    ip_header->ip_src = ip_header->ip_dst;
    ip_header->ip_dst = old_src;
    
    //IP Header - Update TTL
    ip_header->ip_ttl = INIT_TTL;
    
    //IP Header - Recalc checksum
    set_ip_checksum(ip_header);

    //Flip Eth Header
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)eth_frame;
    uint8_t old_dhost[ETHER_ADDR_LEN];
    memcpy(old_dhost, eth_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, old_dhost, ETHER_ADDR_LEN);
   
    //Transmit packet
    transmit_ethernet_frame(sr, eth_frame, frame_len);
    int res = sr_send_packet(sr, eth_frame, frame_len, interface);
    printf("Sent Echo reply with result %d\n", res);
}


/**
* Checks for packet validity.
* Handles 2 types of incoming
* - IP packets to a connected host
* - ICMP packets to this router or a connected host that expire
*/
void handle_ip_packet(sr_instance_t *sr, uint8_t *eth_frame,
    unsigned int frame_len,
    char *interface)
{
    //uint8_t *ip_pkt = eth_frame + sizeof(sr_ethernet_hdr_t);
    //sr_ip_hdr_t *ip_hdr = (uint8_t *)ip_header(eth_frame);  <WARNING

    sr_ip_hdr_t *ip_hdr = ip_header(eth_frame);
    if (!valid_ip_header(ip_hdr)) return; //drop it
    printf("\n\nGot a valid packet!! YAYA!!\n\n");

    if (is_dest_if(sr, eth_frame, interface)) {
        handle_local_packet(sr, eth_frame, frame_len, interface);
    } else {
        route_ip_packet(sr, eth_frame, frame_len, interface);
    }

}

void handle_arp_packet(sr_instance_t *sr, uint8_t *eth_frame,
    unsigned int len,
    char *interface)
{

}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  if (!valid_eth_size(len)) return; //drop bad sizes

  uint16_t ethtype = ethertype(packet);

  switch(ethtype) {
  case ethertype_ip:
    printf("RECV IP\n");
    handle_ip_packet(sr, packet, len, interface);
    break;
  case ethertype_arp:
    printf("RECV ARP\n");
    handle_arp_packet(sr, packet, len, interface);
    break;
  }

}/* end sr_ForwardPacket */


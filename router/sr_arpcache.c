#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    //hope the arpcache is in sr
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

void check_arp_packet(uint8_t *pkt, unsigned int len) {
    printf("\n\nTransmitting ARP Packet\n");
    print_hdrs(pkt, len);
    printf("\nEND\n");
}

#define ARP_HRD 1
#define ARP_PRO 2048
#define ARP_REQ_OPCODE 1
#define ARP_REP_OPCODE 2

uint8_t eth_broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void send_arp_packet(sr_instance_t *sr, sr_arpreq_t *req) {

    //Figure out the sending interface
    char *if_name = req->packets->iface;
    sr_if_t *iface = sr_get_interface(sr, if_name);

    
    uint8_t *eth_frame = new_eth_frame(iface->addr,
                                    eth_broadcast,
                                    sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth_frame;
    eth_hdr->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t *header = arp_header(eth_frame);

    //Preamble
    header->ar_hrd = htons(ARP_HRD);
    header->ar_pro = htons(ARP_PRO);
    header->ar_hln = ETHER_ADDR_LEN;
    header->ar_pln = sizeof(uint32_t);
    header->ar_op = htons(ARP_REQ_OPCODE);

    //Addresses
    memcpy(header->ar_sha, iface->addr, ETHER_ADDR_LEN);
    header->ar_sip = iface->ip;

    memcpy(header->ar_tha, eth_broadcast, ETHER_ADDR_LEN);
    header->ar_tip = req->ip;

    int len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    check_arp_packet(eth_frame, len);
    int res = sr_send_packet(sr, eth_frame, len, if_name);

    free(eth_frame);
    printf("Sent arp request with result %d", res);
}

void send_arpreq(sr_instance_t *sr, sr_arpcache_t *cache, sr_arpreq_t *req) {
    if (difftime(time(NULL), req->sent) < 1) return;

    if (req->times_sent >= 5) {
        //send ICMP unreachable to all packets
        printf("ARP Requst timeout!!");
        sr_arpreq_destroy(cache, req);
    } else {
        send_arp_packet(sr, req);
        req->sent = time(NULL);
        req->times_sent++;
    }
}

/**
 * Transmits to the given gateway on the given interface
 * 
 * Expects complete packets except for ether_dhost
 **/
void set_dst_eth_and_transmit(struct sr_instance *sr, uint8_t *eth_frame,
                unsigned int len, uint32_t gw_ip, char *iface) {

    struct sr_arpcache *cache = &(sr->cache);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth_frame;

    struct sr_arpentry *cached = sr_arpcache_lookup(cache, gw_ip);
    if(cached) {
        printf("Have cached entry for ARP req for \n");
        print_addr_ip_int(ntohl(gw_ip));
        printf("\n");
        memcpy(eth_hdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);
        printf("transmitting:\n");
        print_hdrs(eth_frame, len);
        printf("\n\n");
        sr_send_packet(sr, eth_frame, len, iface);
        if(!valid_ip_header(ip_header(eth_frame))) printf("DANGER\n");
    } else {
        printf("ARP cache miss for %x\n", gw_ip);
        sr_arpreq_t *req =\
            sr_arpcache_queuereq(cache, gw_ip, eth_frame, len, iface);

        send_arpreq(sr, cache, req);
    }
}

/**
 * Processes incoming arp replies
 */
void cache_arp_reply(struct sr_instance *sr, uint8_t *ethernet_frame,
                      unsigned int len, char *if_name) {

    sr_arp_hdr_t *arp_hdr = arp_header(ethernet_frame);
    //TODO drop if not req or rep op code arp_hdr->ar_op;
    //TODO drop if not ar_hrd is ethernet and ar_pro is not ip

    uint32_t src_ip = arp_hdr->ar_sip;
    sr_arpreq_t *requests = sr_arpcache_insert(&(sr->cache),
                                arp_hdr->ar_sha, src_ip);

    printf("Added new entry to ARP table!\n");
    
    //printf("\n\n\n\n\nAFTER\n");
    //sr_arpcache_dump(&(sr->cache));

    if (requests == NULL) return;

    printf("And there were some waiting requests, oh my!\n");
    
    for(struct sr_packet *cur = requests->packets;
        cur != NULL;
        cur = cur->next) {
        
       set_dst_eth_and_transmit(sr, cur->buf, cur->len, src_ip, cur->iface);  
    }

}

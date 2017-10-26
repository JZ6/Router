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

/*
 * Written by Yu Jie Zuo
 * UTORid: zuoyu
 */

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

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
void sr_init(struct sr_instance *sr){
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

}/* -- sr_init -- */

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
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet/* lent */,
                     unsigned int len,
                     char *interface/* lent */){
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);

	/* fill in code here */

	sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
	if(len < sizeof(sr_ethernet_hdr_t)){
		return;
	}
	if(ntohs(ethernet_header->ether_type) == ethertype_ip){
		if(len < (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t))){
			return;
		}
		sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		uint16_t received_sum = ip_header->ip_sum;
		ip_header->ip_sum = 0;
		if(received_sum != cksum(ip_header, sizeof(sr_ip_hdr_t))){
			return;
		}
		ip_header->ip_sum = received_sum;

		if(ip_header->ip_ttl <= 1){
			exceed_time(sr, packet, len, interface);
		}

		struct sr_if *intface = sr->if_list;
		while(intface){
			if(intface->ip == ip_header->ip_dst){
				break;
			}
			intface = intface->next;
		}

		if(!intface){
			struct sr_rt *lpmatch = prematch(sr, ip_header->ip_dst);
			if(!lpmatch){       /* Not in Routing Table */
				uint8_t *unreach_packet = malloc(len);
				create_send(3, 0, sr_get_interface(sr, interface)->ip, unreach_packet, sr, packet, interface);
				struct sr_rt *source_match = prematch(sr, ip_header->ip_dst);
				if(source_match){
					struct sr_arpentry *arp_ent = sr_arpcache_lookup(&sr->cache, source_match->gw.s_addr);
					if(!arp_ent){
						struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, source_match->gw.s_addr,
						                                                 unreach_packet, len, source_match->interface);
						handle_arpreq(sr, arp_req);
					}else{
						struct sr_if *cache_intface = sr_get_interface(sr, source_match->interface);
						sr_ethernet_hdr_t *cache_ether_header = (sr_ethernet_hdr_t *) unreach_packet;
						memcpy(cache_ether_header->ether_dhost, arp_ent->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
						memcpy(cache_ether_header->ether_shost, cache_intface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
						sr_ip_hdr_t *cache_ip_header = (sr_ip_hdr_t *) (unreach_packet + sizeof(sr_ethernet_hdr_t));
						cache_ip_header->ip_src = sr_get_interface(sr, interface)->ip;
						cache_ip_header->ip_sum = 0;
						cache_ip_header->ip_sum = cksum(cache_ip_header, sizeof(sr_ip_hdr_t));

						sr_send_packet(sr, unreach_packet, len, cache_intface->name);
						free(arp_ent);
					}
					free(unreach_packet);
				}
			}else{
				struct sr_if *match_intface = sr_get_interface(sr, lpmatch->interface);
				struct sr_arpentry *match_arp_ent = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);
				if(!match_arp_ent){     /*No Match*/
					struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len,
					                                                 match_intface->name);
					handle_arpreq(sr, arp_req);
				}else{
					sr_ethernet_hdr_t *match_ether_header = (sr_ethernet_hdr_t *) packet;
					memcpy(match_ether_header->ether_shost, match_intface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
					memcpy(match_ether_header->ether_dhost, match_arp_ent->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
					sr_send_packet(sr, packet, len, match_intface->name);
				}
			}
		}else{      /* My Packet */
			if(ip_header->ip_p == ip_protocol_icmp){
				ip_icmp(sr, packet, len, interface);
			}else{
				uint8_t *send_packet = malloc(len);
				create_send(0, 0, intface->ip, send_packet, sr, packet, interface);
				sr_send_packet(sr, send_packet, len, interface);
				free(send_packet);
			}
		}
	}else{
		if(len < (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t))){
			return;
		}
		sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

		struct sr_if *dest_intface = sr->if_list;
		while(dest_intface){
			if(dest_intface->ip == arp_header->ar_tip){
				break;
			}
			dest_intface = dest_intface->next;
		}

		if(dest_intface){
			if(arp_op_request == ntohs(arp_header->ar_op)){
				uint8_t *arp_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

				sr_ethernet_hdr_t *arp_ether_header = (sr_ethernet_hdr_t *) arp_packet;
				memcpy(arp_ether_header->ether_shost, sr_get_interface(sr, interface)->addr,
				       sizeof(uint8_t) * ETHER_ADDR_LEN);
				memcpy(arp_ether_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
				arp_ether_header->ether_type = htons(ethertype_arp);

				sr_arp_hdr_t *send_arp_header = (sr_arp_hdr_t *) (arp_packet + sizeof(sr_ethernet_hdr_t));
				send_arp_header->ar_pln = arp_header->ar_pln;
				send_arp_header->ar_hln = arp_header->ar_hln;
				send_arp_header->ar_pro = arp_header->ar_pro;
				send_arp_header->ar_hrd = arp_header->ar_hrd;
				send_arp_header->ar_op = htons(arp_op_reply);

				memcpy(send_arp_header->ar_sha, dest_intface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
				send_arp_header->ar_sip = dest_intface->ip;
				memcpy(send_arp_header->ar_tha, arp_header->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
				send_arp_header->ar_tip = arp_header->ar_sip;

				sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), dest_intface->name);
				free(arp_packet);
			}else{
				struct sr_arpreq *arpeq = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
				if(arpeq){
					struct sr_packet *arpacket = arpeq->packets;
					while(arpacket){
						sr_ethernet_hdr_t *arp_ether_header = (sr_ethernet_hdr_t *) arpacket->buf;
						memcpy(arp_ether_header->ether_dhost, arp_header->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
						memcpy(arp_ether_header->ether_shost, sr_get_interface(sr, arpacket->iface)->addr,
						       sizeof(uint8_t) * ETHER_ADDR_LEN);
						sr_send_packet(sr, arpacket->buf, arpacket->len, arpacket->iface);
						arpacket = arpacket->next;
					}
					sr_arpreq_destroy(&sr->cache, arpeq);
				}
			}
		}
	}
}/* end sr_ForwardPacket */

void create_send(int type, int code, uint32_t source, uint8_t *send_packet, struct sr_instance *sr, uint8_t *packet,
                 char *interface){
	sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
	sr_ethernet_hdr_t *send_ether_header = (sr_ethernet_hdr_t *) send_packet;
	memcpy(send_ether_header->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(send_ether_header->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
	send_ether_header->ether_type = htons(ethertype_ip);

	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	sr_ip_hdr_t *send_ip_header = (sr_ip_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t));
	send_ip_header->ip_ttl = 64;
	send_ip_header->ip_v = 4;
	send_ip_header->ip_tos = 0;
	send_ip_header->ip_hl = (sizeof(sr_ip_hdr_t) / 4);
	send_ip_header->ip_id = htons(0);
	send_ip_header->ip_off = htons(IP_DF);
	send_ip_header->ip_src = source;
	send_ip_header->ip_dst = ip_header->ip_src;
	send_ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
	send_ip_header->ip_p = ip_protocol_icmp;
	send_ip_header->ip_sum = 0;
	send_ip_header->ip_sum = cksum(send_ip_header, sizeof(sr_ip_hdr_t));

	sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t) +
	                                                      sizeof(sr_ip_hdr_t));
	icmp_header->icmp_code = code;
	icmp_header->icmp_type = type;
	memcpy(icmp_header->data, ip_header, ICMP_DATA_SIZE);
	icmp_header->icmp_sum = 0;
	icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
}

void exceed_time(struct sr_instance *sr, uint8_t *packet/* lent */, unsigned int len, char *interface/* lent */){
	uint8_t *send_packet = malloc(len);
	create_send(11, 0, sr_get_interface(sr, interface)->ip, send_packet, sr, packet, interface);
	sr_ip_hdr_t *orig_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	struct sr_arpentry *arp_ent = sr_arpcache_lookup(&sr->cache, orig_ip_header->ip_src);
	if(!arp_ent){
		struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, orig_ip_header->ip_src, send_packet, len,
		                                                 interface);
		handle_arpreq(sr, arp_req);
	}else{
		sr_send_packet(sr, send_packet, len, interface);
	}
	free(send_packet);
}

void ip_icmp(struct sr_instance *sr, uint8_t *packet/* lent */, unsigned int len, char *interface/* lent */){

	sr_ethernet_hdr_t *icmp_ethernet_header = (sr_ethernet_hdr_t *) packet;
	memcpy(icmp_ethernet_header->ether_dhost, icmp_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(icmp_ethernet_header->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

	sr_ip_hdr_t *icmp_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	uint32_t source = icmp_ip_header->ip_src;
	icmp_ip_header->ip_src = icmp_ip_header->ip_dst;
	icmp_ip_header->ip_dst = source;
	icmp_ip_header->ip_sum = cksum(icmp_ip_header, sizeof(sr_ip_hdr_t));

	sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	if(icmp_header->icmp_type == 0){

		/* uint16_t received_icmp_sum = icmp_header->icmp_sum;
		 * assert(received_icmp_sum == cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));
		 * icmp_header->icmp_sum = received_icmp_sum;
		 */
		icmp_header->icmp_sum = 0;
		icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));
		icmp_header->icmp_type = 0;
		icmp_header->icmp_code = 0;

		struct sr_arpentry *arp_ent = sr_arpcache_lookup(&sr->cache, icmp_ip_header->ip_dst);
		if(!arp_ent){
			struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, icmp_ip_header->ip_dst, packet, len, interface);
			handle_arpreq(sr, req);
		}else{
			sr_send_packet(sr, packet, len, interface);
		}
	}
}

struct sr_rt *prematch(struct sr_instance *sr, uint32_t dest){
	struct sr_rt *srt = sr->routing_table;
	int cur_len = 0;
	struct sr_rt *result = 0;

	while(srt){
		if(((dest & srt->mask.s_addr) > cur_len) &&
		    ((srt->dest.s_addr & srt->mask.s_addr) == (dest & srt->mask.s_addr))){
			cur_len = dest & srt->mask.s_addr;
			result = srt;
		}
		srt = srt->next;
	}
	return result;
}

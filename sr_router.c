#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include <stdlib.h>
#include <string.h>

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

  /* fill in code here */
    if (sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "sr_handlepacket: packet length doesn't reach the min length.\n");
        return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    
    uint16_t packet_ether_type = ethertype(packet);
    
    switch (packet_ether_type) {
        /* It's a IP Packet*/
        case ethertype_ip:
            if ((sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) > len) {
                printf("sr_handlepacket: IP packet length doesn't reach the min length.\n");
                return;
            }

            /* Ethernet header is before ip header */
            sr_ip_hdr_t *header_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

            printf("----------- IP Packet ------------\n");
            print_hdr_eth(packet);
            print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
            printf("------------------------------------------\n");

            /* Verify cksum_ip */
            uint16_t cksum_ip = header_ip->ip_sum;
            header_ip->ip_sum = 0;
            if (cksum_ip != cksum(header_ip, sizeof(sr_ip_hdr_t))) {
                printf("sr_handlepacket: the checksum of ip packet is incorrect.\n");
                return;
            }

            /* Check if the IP address matches the current router's IP addresses */
            struct sr_if *interface_iterator = sr->if_list;
            struct sr_if *current_interface = sr_get_interface(sr, interface);
            while (interface_iterator) {
                if (interface_iterator->ip == header_ip->ip_dst)
                {
                    /* Get the struct from the name */
                    process_ip(sr, header_ip, current_interface, packet, len);
                    return;
                }
                interface_iterator = interface_iterator->next;
            }
            forward_ip(sr, header_ip, eth_hdr, packet, len, current_interface);
            break;
        /*it's a arp packet */
        case ethertype_arp:
            if ((sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t)) > len) {
                fprintf(stderr, "sr_handlepacket: ARP packet length doesn't meet min length.\n");
                return;
            }

            sr_arp_hdr_t *header_arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

            printf("------------ ARP Packet ----------------\n");
            print_hdr_eth(packet);
            print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
            printf("------------------------------------------------\n");

            /*
            * For ARP Requests: Send an ARP reply if the goal IP address is one of your router’s IP addresses.
            * For ARP Replies: Cache the entry if the goal IP address is one of your router’s IP addresses.
            * Check if goal IP is one of router's IP addresses.
            * */
            struct sr_if *interface_iterator2 = sr->if_list;
            while (interface_iterator2)
            {
                if (interface_iterator2->ip == header_arp->ar_tip)
                {
                    process_arp(sr, header_arp, packet, interface_iterator2);
                    return;
                }
                interface_iterator2 = interface_iterator2->next;
            }
            printf("sr_handlepacket: goal IP cannot be found.\n");
            break;
    }

}/* end sr_ForwardPacket */

void process_ip(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr, struct sr_if *inf, uint8_t *packet, unsigned int len)
{
    if (ip_hdr->ip_p != ip_protocol_icmp) {
        printf("TCP/UDP message.\n");
        /* Send ICMP type 3 code 3: Port Unreachable */
        send_icmp_message(sr, packet, inf, 3, 3, len);
    }
    else {
        printf("ICMP message.\n");

        if ((sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t)) > len) {
            printf("process_ip: ICMP header length doesn't reach minimum length.\n");
            return;
        }

        /* IP header is before icmp header */
        sr_icmp_hdr_t *header_icmp = (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
        printf("------------ ICMP HEADER ------------------\n");
        print_hdr_icmp(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
        printf("-----------------------------------------\n");

        /* if it's an ICMP echo request, send echo reply */
        if (header_icmp->icmp_type == 8) {
            /* establish ICMP echo reply */
            send_icmp_message(sr, packet, inf, 0, 0, len);
        }
    }
}

void process_arp(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, uint8_t *packet, struct sr_if *inf)
{
    switch (ntohs(arp_hdr->ar_op))
    {
    case arp_op_request:
    {
        printf("Received an ARP request\n");
        /* Construct ARP reply */
        unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *arp_reply = malloc(len);

        /* Set Ethernet Header */
        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)arp_reply;
        memcpy(reply_eth_hdr->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
        reply_eth_hdr->ether_type = htons(ethertype_arp);

        /* Set ARP Header */
        sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
        reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
        reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
        reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
        reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
        reply_arp_hdr->ar_op = htons(arp_op_reply);

        /* set sender MAC to be interface's MAC and set sender IP to be interface's IP*/
        memcpy(reply_arp_hdr->ar_sha, inf->addr, ETHER_ADDR_LEN);
        reply_arp_hdr->ar_sip = inf->ip;
        /* set target MAC to be the packet's sender MAC and set target IP to be the packet's sender IP*/
        memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

        printf("------------ ARP Reply ------------------\n");
        print_hdr_eth(arp_reply);
        print_hdr_arp(arp_reply + sizeof(sr_ethernet_hdr_t));
        printf("-----------------------------------------\n");

        sr_send_packet(sr, arp_reply, len, inf->name);
        free(arp_reply);
        break;
    }
    case arp_op_reply:
    {
        printf("Received an ARP reply.\n");
        /* Look up request queue */
        struct sr_arpreq *queued = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (queued)
        {
            struct sr_packet *queued_pkts = queued->packets;
            /* Send outstanding packets */
            while (queued_pkts)
            {
                struct sr_if *inf = sr_get_interface(sr, queued_pkts->iface);
                if (inf)
                {
                    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(queued_pkts->buf);
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
                    sr_send_packet(sr, queued_pkts->buf, queued_pkts->len, queued_pkts->iface);
                }
                queued_pkts = queued_pkts->next;
            }
            sr_arpreq_destroy(&sr->cache, queued);
        }
        break;
    }
    }
}


void send_icmp_message(struct sr_instance *sr, uint8_t *packet, struct sr_if *inf, uint8_t icmp_type, uint8_t icmp_code, unsigned int len)
{
    uint8_t *icmp_packet;
    unsigned int icmp_packet_len;
    if (icmp_type == 0)
    { /* Echo Reply */
        icmp_packet_len = len;
    }
    else
    {
        icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    }
    icmp_packet = malloc(icmp_packet_len);
    memcpy(icmp_packet, packet, icmp_packet_len);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, inf->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));

    /* Choose which interface to send it out on */
    if ((icmp_type == 0 && icmp_code == 0) || (icmp_type == 3 && icmp_code == 3))
    { /* If echo reply or port unreachable, it was meant for a router interface, so use the source destination */
        ip_hdr->ip_src = ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_dst;
    }
    else
    { /* Otherwise, use any ip from the router itself */
        ip_hdr->ip_src = inf->ip;
    }
    ip_hdr->ip_dst = ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_src;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_p = ip_protocol_icmp;
    if (icmp_type == 3)
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Modify ICMP header */
    if (icmp_type == 0 && icmp_code == 0) /* Echo Reply */
    {
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = icmp_type;
        icmp_hdr->icmp_code = icmp_code;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    }
    else
    {
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = icmp_type;
        icmp_hdr->icmp_code = icmp_code;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->next_mtu = 0;
        icmp_hdr->unused = 0;
        /* Copy the internet header into the data */
        memcpy(icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
        /* Copy the first 8 bytes of original datagram's data into the data */
        memcpy(icmp_hdr->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    }

    printf("----------- Send ICMP Message ------------\n");
    print_hdr_eth(icmp_packet);
    print_hdr_ip(icmp_packet + sizeof(sr_ethernet_hdr_t));
    print_hdr_icmp(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    printf("------------------------------------------\n");

    forward_ip(sr, ip_hdr, eth_hdr, icmp_packet, icmp_packet_len, inf);

    free(icmp_packet);
}

void forward_ip(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr, sr_ethernet_hdr_t *eth_hdr, uint8_t *packet, unsigned int len, struct sr_if *src_inf)
{
    /* Sanity Check: Minimum Length & Checksum*/

    /* Decrement TTL by 1 */
    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0)
    {
        /* Send ICMP Message Time Exceeded */
        printf("ICMP Message Time Exceeded.\n");
        send_icmp_message(sr, packet, src_inf, 11, 0, len);
        return;
    }

    /* Recompute checksum and add back in */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Check the routing table and compare the values to the destination IP address */
    struct sr_rt *cur_node = sr->routing_table;
    uint32_t matching_mask = 0;
    uint32_t matching_address;
    char inf[sr_IFACE_NAMELEN];

    while (cur_node)
    {
        /* Compare the packet destination and the destination in the routing table node, record how many bits match */
        printf("Checking Longest Prefix...\n");
        check_longest_prefix(cur_node, ip_hdr->ip_dst, &matching_mask, &matching_address, inf);
        cur_node = cur_node->next;
    }
    if (matching_address)
    {
        printf("Longest Prefix Matched!\n");
        /*
		* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP
		* If it's there, send it
		* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), and add the packet to the queue of packets waiting on this ARP request.
		*/
        struct sr_arpentry *matching_entry = sr_arpcache_lookup(&sr->cache, matching_address);
        /* Update the destination and source information for this package */
        if (matching_entry)
        {
            printf("There is a macthing entry.\n");
            memcpy(eth_hdr->ether_dhost, matching_entry->mac, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, sr_get_interface(sr, inf)->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, inf);
            free(matching_entry);
        }
        else
        {
            /* There was no entry in the ARP cache */
            printf("There was no entry in the ARP cache.\n");
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, matching_address, packet, len, inf);
            handle_arpreq(req, sr);
        }
    }
    else
    {
        /* Send ICMP Net unreachable */
        printf("ICMP Net Unreachable.\n");
        send_icmp_message(sr, packet, src_inf, 3, 0, len);
    }
    /* If we get here, then matching_address was null, then we drop the packet and send an error */
}

void check_longest_prefix(struct sr_rt *cur_node, uint32_t packet_dest, uint32_t *matching_mask, uint32_t *matching_address, char *inf)
{
    /* Mask the packet's destination address to get the prefix */
    int masked_dest = packet_dest & cur_node->mask.s_addr;
    /* If the prefix matches the entry's destination as well, it's a match */
    /* If doesn't work try: if (masked_dest == cur_node->dest.s_addr & cur_node->mask.s_addr) instead */
    if (masked_dest == (cur_node->dest.s_addr & cur_node->mask.s_addr))
    {
        /* If this is true then we know that this match is our best match (since the number of bits compared was higher)
         Save the data for comparison later */
        if (cur_node->mask.s_addr > *matching_mask)
        {
            *matching_mask = cur_node->mask.s_addr;
            *matching_address = cur_node->gw.s_addr;
            strncpy(inf, cur_node->interface, sr_IFACE_NAMELEN);
        }
        /* If it's false then it's not our best match, just ignore it */
    }
    /* If the prefix doesn't match then we do nothing */
}


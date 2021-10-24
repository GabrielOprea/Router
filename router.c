#include <queue.h>
#include "skel.h"
#include <math.h>

#define IP_LEN 32
#define BYTE 8

//Structure representing a single entry in the routing table
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/* Structure representing a trie using for performing longest prefix match in
constant time */
typedef struct trie {
	/* The routing table entry corresponding to the node. If the node is not
	a leaf, then this is set to NULL */
	struct route_table_entry* route;

	//Pointers to left and right subtrees
	struct trie* left;
	struct trie* right;
} TCell, *TTrie;

//Structure representing a single entry in the arp table
struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

int interfaces[ROUTER_NUM_INTERFACES];
struct arp_entry *arp_table;
int arp_table_len;

TTrie route_table_tree;
struct route_table_entry* rtable;
int rtable_size;


uint16_t ip_checksum(void* vdata,size_t length);

/*Function that counts the number of bits set to 1 from a mask. That is,
the lenght of the mask */
int count_mask_bits(uint32_t mask) {

	int set_bits = 0;
	for(int i = 0; i < IP_LEN; i++) {
		int crt_bit = (mask & (1 << i))== 0 ? 0 : 1;
		if(crt_bit == 1) set_bits++;
	}

	return set_bits;
}

//Alocates memory for a cell in the Trie
TTrie alocCell() {
	TTrie cell = calloc(1, sizeof(TTrie));
	if(!cell) return NULL;

	cell->route = NULL;
	cell->left = NULL;
	cell->right = NULL;

	return cell;
}

/* Converts the initially read routing table from an array representation to a
Trie one */
void table_to_trie() {
	//Alocating memory for the root, which is an empty node
	route_table_tree = calloc(1, sizeof(TCell));
	if(!route_table_tree) return;
	TTrie p;

	//Building rtable_size leaf nodes
	for(int i = 0; i < rtable_size; i++) {
		p = route_table_tree;

		//The lenght of the path for an entry is the length of the mask
		int mask_len = count_mask_bits(rtable[i].mask);

		//Build the path from the root node using the bits from the prefix
		for(int j = 0; j < mask_len; j++) {
			//extract the current bit
			int crt_bit = (rtable[i].prefix & (1 << j)) == 0 ? 0 : 1;

			//If the bit is set, the path is to the right
			if(crt_bit) {

				/*If the node is already allocated, go to the right, else
				build a new node */
				if(p->right) {
					p = p->right;
				}
				else {
					p->right = alocCell();
					p = p->right;
				}
			}

			//Go to the left
			else {
				if(p->left) {
					p = p->left;
				}
				else {
					p->left = alocCell();
					p = p->left;
				}
			}
		}
		/*After a leaf node is reached, set its route table entry to the
		corresponding one */
		p->route = rtable + i;
	}
}

/*Function that iterates through the Trie in search of the leaf node
corresponding to the path given by dest_ip */
struct route_table_entry *get_best_route(__u32 dest_ip) {
	
	struct route_table_entry* best_route = NULL;
	TTrie p = route_table_tree;
	//Search at most 32 nodes
	for(int i = 0; i < IP_LEN; i++) {
		//Extract the current bit from dest_ip
		int crt_bit = (dest_ip & (1 << i)) == 0 ? 0 : 1;
		if(!p) break;

		//If a valid route is found, update the result
		if(p->route != NULL) best_route = p->route;
		
		//Move the pointer
		if(crt_bit == 0) {
			p = p->left;
		}
		else p = p->right;
	}

	/* The result will contain the entry for the longest path or NULL
	if no path exists */
	return best_route;
}

//Auxiliary function that converts an array of characters to a unsigned int
uint32_t IP_to_int(char ip[36]) {

		char* aux = strtok(ip, ".");
		uint32_t part_4 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_3 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_2 = atoi(aux);

		aux = strtok(NULL, ".");
		uint32_t part_1 = atoi(aux);

		uint32_t result = (part_1 << (3 * BYTE)) | (part_2 << (2 * BYTE)) | (part_3 << BYTE) | (part_4);
		return result;
}

//Parser for the routing table
void read_rtable(char* filename) {

	FILE* in = fopen(filename, "r");

	//Use a new file descriptor to find the number of lines to be allocated
	FILE* fp = fopen(filename, "r");
	int lines = 0;
	char c;

	for(c = getc(fp); c != EOF; c = getc(fp)) {
		if(c == '\n') {
			lines++;
		}
	}

	fclose(fp);

	rtable = calloc(lines, sizeof(struct route_table_entry));
	if(!rtable) return; 

	rtable_size = lines;

	//Iterate through the lines
	int crt_lin = 0;
	while(crt_lin < lines) {
		char str_prefix[36];
		char str_next_hop[36];
		char str_mask[36];
		int interface;

		//Read the entries for each line
		fscanf(in, "%s %s %s %d", str_prefix, str_next_hop, str_mask, &interface);

		//Convert them to uint
		uint32_t prefix = IP_to_int(str_prefix);
		uint32_t next_hop = IP_to_int(str_next_hop);
		uint32_t mask = IP_to_int(str_mask);

		struct route_table_entry* crt_entry = calloc(1, sizeof(struct route_table_entry));
		if(!crt_entry) return;

		crt_entry->prefix = prefix;
		crt_entry->next_hop = next_hop;
		crt_entry->mask = mask;
		crt_entry->interface = interface;

		//Add the read entry in the routing table
		rtable[crt_lin] = *crt_entry;

		crt_lin++;
	}

	//Based on this array representation, build a Trie one for faster lookup
	table_to_trie();
}


/* Returns a pointer to the best matching ARP entry
or null if it does not exist. */
struct arp_entry *get_arp_entry(__u32 ip) {

    for (int i = 0; i < arp_table_len; i++) {
    	if (arp_table[i].ip == ip){
    		return arp_table + i;
    	}
    }

    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	queue q = queue_create();
	queue q_aux = queue_create();

	init(argc - 2, argv + 2);

	//Read the routing table and allocate memory for the arp table
	read_rtable(argv[1]);


	arp_table = calloc(100, sizeof(struct arp_entry));
	if(!arp_table) {
		perror("Allocation failed!");
		exit(1);
	}
	arp_table_len = 0;

	while (1) {
		rc = get_packet(&m);

		DIE(rc < 0, "get_message");

		//Extract all the relevant header from the payload
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		
		struct arp_header* arp_hdr = parse_arp(m.payload);
		struct icmphdr* icmp_hdr = parse_icmp(m.payload);

		//Checking for IP packets
		if(htons(eth_hdr->ether_type) == ETHERTYPE_IP) {

			//Checking for ICMP packets
			if(icmp_hdr != NULL) {

				int id = icmp_hdr->un.echo.id;
				int seq = icmp_hdr->un.echo.sequence;

				//Check for an ECHO Request
				if(icmp_hdr->type == 8 && icmp_hdr->code == 0 && ip_hdr->daddr == IP_to_int(get_interface_ip(m.interface))) {

					//Send an ECHO Reply
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost,
					eth_hdr->ether_dhost, 0, 0, (get_best_route(ip_hdr->saddr))->interface, id, seq);
					continue;
				}
			}

			//Send an ICMP Timeout message for bad ttl
			if(ip_hdr->ttl <= 1) {

				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost,
				eth_hdr->ether_dhost, 11, 0, (get_best_route(ip_hdr->saddr))->interface);

				continue;
			}

			unsigned short old_check = ip_hdr->check;
			ip_hdr->check = 0;
			unsigned short new_check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			if(old_check != new_check) {
				continue; //drop packet for bad checksum
			}

			ip_hdr->check = new_check;

			struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);

			//Send ICMP error for destination not found
			if(!best_route) {

				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost,
				eth_hdr->ether_dhost, 3, 0, (get_best_route(ip_hdr->saddr))->interface);

				continue;
			}

			//BONUS: Implemented checksum via incremental update
			uint16_t m_part; //16 bit field starting from ttl
			memcpy(&m_part, &(ip_hdr->ttl), sizeof(uint16_t));
			ip_hdr->ttl-= 1;

			uint16_t m_new_part; //new 16 bit field starting from ttl
			memcpy(&m_new_part, &(ip_hdr->ttl), sizeof(uint16_t));


			uint16_t old_checksum = ip_hdr->check;
			uint32_t new_checksum = ~old_checksum + ~m_part + m_new_part;
			new_checksum = (new_checksum >> 16) + (new_checksum & 0xFFFF);
			new_checksum += (new_checksum >> 16);
			uint16_t new_short_checksum = new_checksum;

			ip_hdr->check = ~(new_short_checksum) - 1;

			//Drop packet for bad ttl
			if(ip_hdr->ttl < 1) {
				continue;
			}

			//Search the matching arp entry
			struct arp_entry* matching_arp = get_arp_entry(best_route->next_hop);
			if(!matching_arp) {
				
				//If not found, send an arp request
				uint8_t* broadcast = calloc(6, sizeof(broadcast));
				for(int i = 0; i < 6; i++) broadcast[i] = 255;

				uint32_t iface_ip = IP_to_int(get_interface_ip(best_route->interface));

				struct ether_header* eth_hdr_req = (struct ether_header*) calloc(1, sizeof(struct ether_header));
				if(!eth_hdr_req) {
					perror("Memory allocation failed!");
					exit(1);
				}

				memcpy(eth_hdr_req->ether_dhost, broadcast, ETH_ALEN);
				get_interface_mac(best_route->interface, eth_hdr_req->ether_shost);
				eth_hdr_req->ether_type = ntohs(ETHERTYPE_ARP);

				packet to_enqueue = m;
				to_enqueue.interface = best_route->interface;

				//Enqueue the current packet and send an arp request
				queue_enq(q, &to_enqueue);
				send_arp(ip_hdr->daddr, iface_ip, eth_hdr_req, best_route->interface, ntohs(ARPOP_REQUEST));

				continue;
			}
			else {

				/*Update the ethernet header and set the packet normally,
				on the interface of the best route */
				memcpy(eth_hdr->ether_dhost, matching_arp->mac, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(best_route->interface,eth_hdr->ether_shost);
				send_packet(best_route->interface, &m);
			}
		}

		//Check for ARP packet
		else if(htons(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			if((htons(arp_hdr->op) == ARPOP_REQUEST) || (ntohs(arp_hdr->op) == ARPOP_REQUEST)) {

				//For a request, send an ARP reply

				uint32_t interface_ip = arp_hdr->tpa;

				struct ether_header* eth_hdr_reply = (struct ether_header*) calloc(1, sizeof(struct ether_header));
				if(!eth_hdr_reply) {
					perror("Memory allocation failed!");
					exit(1);
				}

				memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
				get_interface_mac(m.interface,eth_hdr_reply->ether_shost);
				eth_hdr_reply->ether_type = ntohs(ETHERTYPE_ARP);
				
				send_arp(arp_hdr->spa, interface_ip, eth_hdr_reply, m.interface, ntohs(ARPOP_REPLY));
			
				continue;
			}
			if(ntohs(arp_hdr->op) == ARPOP_REPLY) {

				/* For a reply, update the arp table, then send the packets in
				the queue */

				if(get_arp_entry(arp_hdr->spa) == NULL) {
					arp_table[arp_table_len].ip = arp_hdr->spa;
					memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, ETH_ALEN * sizeof(uint8_t));
					arp_table_len++;
				}
				if(get_arp_entry(arp_hdr->tpa) == NULL) {
					arp_table[arp_table_len].ip = arp_hdr->tpa;
					memcpy(arp_table[arp_table_len].mac, arp_hdr->tha, ETH_ALEN * sizeof(uint8_t));
					arp_table_len++;
				}

				while(!queue_empty(q)) {
					
					packet extracted = *(packet*) queue_deq(q);
					struct ether_header * eth_hdr = (struct ether_header*) extracted.payload;
					struct iphdr* ip_hdr = (struct iphdr*) (extracted.payload + sizeof(struct ether_header));

					if(arp_hdr->spa != ip_hdr->daddr) {
						queue_enq(q_aux, &extracted);
					}
					else {
						memcpy(eth_hdr->ether_dhost, arp_hdr->sha, ETH_ALEN);

						send_packet(extracted.interface, &extracted);
					}
				}

				while(!queue_empty(q_aux)) {
					packet extracted = *(packet*) queue_deq(q_aux);
					queue_enq(q, &extracted);
				}

				continue;
			}

		}
	}
}
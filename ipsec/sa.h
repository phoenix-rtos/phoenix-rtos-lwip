/*
 * Phoenix-RTOS --- LwIP port
 *
 * Copyright 2016 Phoenix Systems
 * Author: Jacek Popko, Kuba Sejdak, Michal Miroslaw, Marek Bialowas
 *
 * %LICENSE%
 */

#ifndef __SA_H__
#define __SA_H__

#include "ipsec.h"
#include "list.h"
#include "util.h"

#include "lwip/def.h"

#include <sys/threads.h>
#include <netinet/udp.h>


#define IPSEC_NR_NETIFS (1) /**< Defines the number of network interfaces. This is used to reserve space for db_netif_struct's */

typedef struct sad_entry_s {
	LIST_ENTRY(sad_entry_s)
	list; /** list linkage */
	/* this are the index fields */
	ip_addr_t addr; /**< IP destination address */
	u32_t spi;      /**< Security Parameter Index */
	u8_t proto;     /**< IPsec protocol */
	u8_t mode;      /**< tunnel or transport mode */
	/* this fields are used to maintain the current connection */
	u16_t path_mtu;  /**< mean transmission unit */
	u32_t seqnum;    /**< the sequence number used to implement the anti-reply mechanism (RFC 2402, 3.3.2: initialize with 0) */
	u8_t replay_win; /**< reply windows size */
	/* NAT-T info */
	u8_t natt_mode;
	u16_t natt_sport, natt_dport;
	/* this fields are used for the cryptography */
	u8_t enc_alg;                        /**< encryption algorithm */
	u8_t enckey_len;                     /**< encryption key length */
	u8_t enckey[IPSEC_MAX_ENCKEY_LEN];   /**< encryption key */
	u8_t auth_alg;                       /**< authentication algorithm */
	u8_t authkey[IPSEC_MAX_AUTHKEY_LEN]; /**< authentication key */
	u8_t iv[16];                         /**< initialization vector for CBC mode */
	pthread_t initiator;                 /**< pointer to thread which created larval SA */
	struct {
		u32_t curr_add_time;
		u32_t curr_use_time;
		u32_t soft_add_expires_seconds;
		u32_t soft_use_expires_seconds;
		u32_t hard_add_expires_seconds;
		u32_t hard_use_expires_seconds;
	} lifetime; /**< lifetime of the SA (must be dropped if HARD lifetime runs out, EXPIRY notification has to be sent in case of SOFT limit expire) */
} sad_entry_t;

typedef struct spd_entry_s {
	LIST_ENTRY(spd_entry_s)
	list;              /** list linkage */
	u32_t src;         /**< IP source address */
	u32_t src_mask;    /**< net mask for source address */
	u32_t dest;        /**< IP destination address */
	u32_t dest_mask;   /**< net mask for the destination address */
	u32_t tunnel_dest; /**< outer-IP destination address in tunnel mode */
	u16_t src_port;    /**< source port number */
	u16_t dest_port;   /**< destination port number */
	u8_t protocol;     /**< the transport layer protocol */
	u8_t policy;       /**< defines how this packet must be processed */
} spd_entry_t;

/** \struct spd_table_struct
 * This structure holds pointers which together define the Security Policy Database
 */
typedef struct spd_table_s {
	spd_entry_t *first;
	handle_t mutex;
} spd_table;

typedef struct sad_table_s {
	sad_entry_t *first;
	handle_t mutex;
} sad_table;

typedef struct db_set_netif_s {
	spd_table inbound_spd;  /**< inbound SPD */
	spd_table outbound_spd; /**< outbound SPD */
	sad_table inbound_sad;  /**< inbound SAD */
	sad_table outbound_sad; /**< outbound SAD */
} db_set_netif;


db_set_netif *ipsec_spd_load_dbs(spd_entry_t *inbound_spd_data, spd_entry_t *outbound_spd_data, sad_entry_t *inbound_sad_data, sad_entry_t *outbound_sad_data);

void ipsec_db_term(db_set_netif *dbs);

void ipsec_db_init(db_set_netif *dbs);

/**
 * Adds a Security Policy to an SPD table.
 *
 * The SPD entries are added to a statically allocated array of SPD structs. The size
 * is defined by IPSEC_MAX_SPD_ENRIES, so there cannot be added more entries added as this
 * constant.
 * The order of the entries within the table is not the same as the order within the array.
 * The "table functionality" is implemented in a linked-list, so one must follow the links of
 * the structure to get to the next entry.
 *
 * Implementation
 * -# This function first gets an empty entry out of the table passed by ipsec_spd_load_dbs().
 * -# If a free place was found, then the function arguments are copied to the appropriate place.
 * -# Then the linked-list is re-linked.
 *
 * @param src		IP source address
 * @param src_net	Netmask for the source address
 * @param dst		IP destination address
 * @param dst_net	Netmask for the destination address
 * @param proto		Transport protocol
 * @param src_port	Source Port
 * @param dst_port	Destination Port
 * @param policy	The policy defining how the packet matching the entry must be processed
 * @param table		Pointer to the SPD table
 * @return A pointer to the added entry when adding was successful
 * @return NULL when the entry could not have been added (no free entry or duplicate)
 * @todo right now there is no special order implemented, maybe this is needed
 */

spd_entry_t *ipsec_spd_add(u32_t src, u32_t src_net, u32_t dst, u32_t dst_net, u8_t proto, u16_t src_port,
	u16_t dst_port, u8_t policy, u32_t tunnel_dest, spd_table *table, int sort_src_first);

void ipsec_spd_del(spd_entry_t *entry, spd_table *table);
int ipsec_spd_del_maybe(spd_entry_t *ptr, spd_table *table);

ipsec_status ipsec_spd_add_sa(spd_entry_t *entry, sad_entry_t *sa);


/**
 * Returns an pointer to an SPD entry which matches the packet.
 *
 * Inbound packets must be checked against the inbound SPD and outbound
 * packets must be checked against the outbound SPD.
 *
 * Implementation
 *
 * This function checks all the selector fields of the SPD table. The port numbers
 * are only checked if the protocol is TCP or UDP.
 * An entry which has a value of 0 is the same as the '*' which means everything.
 *
 * @param	payload	Pointer to an IP packet which is checked
 * @param 	table	Pointer to the SPD inbound/outbound table
 * @param 	flags	Match address flag
 * @return 	Pointer to the matching SPD entry
 * @return 	NULL if no entry matched
 * @todo port checking should be implemnted also
 */
spd_entry_t *ipsec_spd_lookup(void *payload, spd_table *table, unsigned flags);

#define IPSEC_MATCH_BOTH 0
#define IPSEC_MATCH_DST  1
#define IPSEC_MATCH_SRC  2

/**
 * Adds an Security Association to an SA table.
 *
 * The SA entries are added to a statically allocated array of SAD structs. The size
 * is defined by IPSEC_MAX_SAD_ENTRIES, so there cannot be added more entries added as this
 * constant.
 * The order of the entries within the table is not the same as the order within the array.
 * The "table functionality" is implemented in a linked-list, so one must follow the links of
 * the structure to get to the next entry.
 *
 * Implementation
 * -# This function first gets an empty entry out of the table passed by ipsec_spd_load_dbs().
 * -# If a free place was found, then the function arguments are copied to the appropriate place.
 * -# Then the linked-list is re-linked.
 *
 * @param entry		pointer to the SA structure which will be copied into the table
 * @param table		pointer to the table where the SA is added
 * @return A pointer to the added entry when adding was successful
 * @return NULL when the entry could not have been added (no free entry or duplicate)
 * @todo right now there is no special order implemented, maybe this is needed
 */
sad_entry_t *ipsec_sad_add(const sad_entry_t *entry, sad_table *table);

/**
 * Deletes an Security Association from an SA table.
 *
 * This function is simple. If the pointer is within the range of the table, then
 * the entry is cleared. If the pointer does not match, nothing happens.
 *
 * @param entry Pointer to the SA entry which needs to be deleted
 * @param table Pointer to the SA table
 *
 * @return IPSEC_STATUS_SUCCESS	entry was deleted properly
 * @return IPSEC_STATUS_FAILURE entry could not be deleted because not found, or invalid pointer
 * @todo right now there is no special order implemented, maybe this is needed
 */

void ipsec_sad_del(sad_entry_t *entry, sad_table *table);
void ipsec_sad_del_spi(u32_t spi, sad_table *table);


/**
 * Gives back a pointer to a SA matching the SA selectors.
 *
 * For incoming packets the IPsec packet must be checked against the inbound SAD and
 * for outgoing packets the packet must be checked against the outbound SAD.
 *
 * Implementation
 * It simply loops over all entries and returns the first match.
 *
 * @param dest	destination IP address
 * @param proto	IPsec protocol
 * @param spi	Security Parameters Index
 * @param table	pointer to the SAD table
 * @return pointer to the SA entry if one matched
 * @return NULL if no matching entry was found
 */
sad_entry_t *ipsec_sad_lookup(ip4_addr_p_t dest, u8_t proto, u32_t spi, sad_table *table);
sad_entry_t *ipsec_sad_lookup_natt(struct ip_hdr *ip, sad_table *table);

/* returns SOFT/HARD-timeouted entry if any in given table */
sad_entry_t *ipsec_sad_check_timeouts(sad_table *table, int *is_soft);

u32_t ipsec_sad_get_spi(void *payload);

ipsec_status ipsec_spd_flush(spd_table *table, spd_entry_t *def_entry);
void ipsec_spd_dump_log(spd_table *table, const char *pfx);

void ipsec_sad_flush(sad_table *table);
void ipsec_sad_dump_log(sad_table *table, const char *pfx);

#endif

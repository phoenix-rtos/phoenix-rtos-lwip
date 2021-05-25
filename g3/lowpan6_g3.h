/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - 6LoWPAN netif
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

/*
 * This is based on the original lowpan6 implmementation in lwip.
 *
 * Copyright (c) 2015 Inico Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

/**
 * @defgroup sixlowpan 6LoWPAN (RFC4944)
 * @ingroup netifs
 * G3-PLC 6LowPAN netif implementation
 */

#ifndef LWIP_HDR_LOWPAN6_G3_H
#define LWIP_HDR_LOWPAN6_G3_H

#include "g3_opts.h"

#if LWIP_IPV6

#include "lowpan6_common.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"

#include "g3_adp.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 1 second period for reassembly */
#define LOWPAN6_TMR_INTERVAL 1000

#define LOWPAN6_MSDU_MAX        400

/* Layer parameter to pbuf_alloc. Used when allocating
 * pbufs by LBP protocol. Leaves space for
 * possible mesh header.
 */
#define PBUF_G3_MESH 5

#define LOWPAN6_BROADCAST_SHORT_ADDR  0xFFFF

/* Returns address in network order ready to serialize */
#define lowpan6_link_addr_to_u16(link_addr) (lwip_htons(((link_addr)->addr[0] << 8) | ((link_addr)->addr[1])))

/* Returns address in machine order ready to print */
#define lowpan6_link_addr_to_u64(addr) ((u64_t)lwip_ntohl(((u32_t *)(addr))[0]) << 32 | lwip_ntohl(((u32_t *)(addr))[1]))

/* Assumes short_addr is in network order */
#define lowpan6_link_addr_set_u16(link_addr, short_addr) do{(link_addr)->addr_len = 2; \
                                                            (link_addr)->addr[0] = (lwip_ntohs(short_addr)) >> 8; \
                                                            (link_addr)->addr[1] = (lwip_ntohs(short_addr)) & 0xFF;}while(0)

#define lowpan6_link_addr_cmp(a, b) (((a)->addr_len == (b)->addr_len) && \
                                     (!memcmp((a)->addr, (b)->addr, (a)->addr_len)))

enum lowpan6_g3_device_type {
  LOWPAN6_G3_DEVTYPE_DEVICE = 0,
  LOWPAN6_G3_DEVTYPE_COORD = 1,
  LOWPAN6_G3_DEVTYPE_NOT_DEFINED = 2
};

enum lowpan6_g3_pan_type {
  LOWPAN6_G3_PAN_SECURED = 0,
  LOWPAN6_G3_PAN_CLOSED,
  LOWPAN6_G3_PAN_OPEN
};

/* 6LoWPAN Header Dispatch values */
enum lowpan6_g3_header_dispatch {
  LOWPAN6_HEADER_IP6 = 0x41,   /* 01 000001 - Uncompressed IPv6 Addresses */
  LOWPAN6_HEADER_HC1 = 0x42,   /* 01 000010 - LOWPAN_HC1 Compressed IPv6 */
  LOWPAN6_HEADER_BC0 = 0x50,   /* 01 010000 - LOWPAN_BC0 broadcast */
  LOWPAN6_HEADER_ESC = 0x40,   /* 01 000000 - Additional Dispatch byte follows, updated according to RFC 6282 */
  LOWPAN6_HEADER_MESH = 0x80,  /* 10 xxxxxx - Mesh header */
  LOWPAN6_HEADER_FRAG1 = 0xc0, /* 11 000xxxx - Fragmentation header (first) */
  LOWPAN6_HEADER_FRAGN = 0xe0  /* 11 100xxx - Fragmentation header (subsequent) */
};

/* 6LoWPAN Command ID */
enum lowpan6_g3_cmd {
  LOWPAN6_CMD_LOADNG = 0x01,
  LOWPAN6_CMD_LBP = 0x02,
};

enum lowpan6_g3_role {
  LOWPAN6_G3_ROLE_NON_LBA = 0,
  LOWPAN6_G3_ROLE_LBA = 1,
};

struct lowpan6_g3_routing_entry {
  u16_t dest_addr;
  u16_t next_addr;
  u16_t metric;
  u8_t hop_count: 4;
  u8_t weak_link_count: 4;
  u16_t valid_time;
  u8_t metric_type;
  u16_t seq_num;
  u8_t is_bidirectional;
  u16_t local_iface_addr;
};

struct lowpan6_g3_broadcast_log_entry {
  u16_t src_addr;
  u8_t seq_number;
  u16_t valid_time; /* minutes */
};

struct lowpan6_g3_blacklist_entry {
  u16_t address;
  u16_t valid_time; /* minutes */
};

typedef struct {
  u8_t key[LOWPAN6_G3_GMK_LEN];
  u8_t is_set;
} gmk_key_t;

/** This struct keeps track of per-netif state */
typedef struct {
  /** fragment reassembly list */
  struct lowpan6_reass_helper *reass_list;
#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
  /** address context for compression */
  struct lowpan6_context context_information_table[LWIP_6LOWPAN_NUM_CONTEXTS];
#endif
  /** Datagram Tag for fragmentation */
  u16_t tx_datagram_tag;

  u8_t bc0_seq_num;
  u8_t ihc_enable;

  struct lowpan6_link_addr extended_mac_addr;

  u16_t pan_id;
  u8_t pan_type;
  u8_t role_of_device;
  struct lowpan6_link_addr short_mac_addr;
  u8_t short_addr_distribution_mechanism;
  struct lowpan6_link_addr lba_address;
  u8_t state;
  u8_t is_rekeying;
  u8_t connected;
  u16_t short_address; /* in machine order */
  gmk_key_t gmk[LOWPAN6_G3_N_GMK_KEYS];
  u16_t join_timeout;
  u8_t bandplan;
  u8_t rekey_gmk;

  u8_t security_level;
  struct lowpan6_link_addr coord_short_address;
  u8_t max_hops;
  u8_t device_type;
  u8_t sniffer_mode;
  u8_t active_key_index;
  u8_t default_coord_route_enable;
  u8_t disable_default_routing;

  /* Timeouts */
  u8_t net_traversal_time; /* seconds */
  u16_t routing_table_ttl; /* minutes */
  u16_t blacklist_table_ttl; /* minutes */
  u16_t broadcast_log_table_ttl; /* minutes */
  u16_t max_join_wait_time; /* seconds */
  u8_t rreq_wait; /* seconds */
  u8_t rrep_wait; /* seconds */
  u8_t path_discovery_time; /* seconds */
  u8_t rlc_time; /* seconds - implementation specific */
  u8_t seconds;

  /* Tables */
  struct lowpan6_g3_broadcast_log_entry broadcast_log_table[LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE];
  struct lowpan6_g3_routing_entry routing_table[LOWPAN6_G3_ROUTING_TABLE_SIZE];
  struct lowpan6_g3_blacklist_entry blacklist_table[LOWPAN6_G3_BLACKLIST_TABLE_SIZE];
  u16_t group_table[LOWPAN6_G3_GROUP_TABLE_SIZE];
  u16_t destination_address_set[LOWPAN6_G3_DEST_ADDRESS_SET_SIZE];

  /* Link cost function factors */
  u8_t kr, km, kc, kh, krt, kq;

  /* LoadNG */
  u8_t metric_type;
  u8_t low_lqi_value;
  u8_t high_lqi_value;
  u8_t rreq_retries;
  u8_t weak_lqi_value;
  u8_t enable_rlc;
  u8_t add_rev_link_cost;
  u8_t unicast_rreq_gen_enable;
  unsigned int n_routing_entries;
  u16_t loadng_sequnce_number;
  u8_t max_tones; /* This should be taken from PHY layer */
} lowpan6_g3_data_t;

void lowpan6_g3_tmr(void *arg);
err_t lowpan6_g3_output(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr);
err_t lowpan6_g3_encapsulate(struct netif *netif, struct pbuf *p, const struct lowpan6_link_addr *src,
                             const struct lowpan6_link_addr *dst, const struct lowpan6_link_addr *final_dest);
err_t lowpan6_g3_input(struct pbuf *p, struct netif *netif, struct lowpan6_link_addr *src, struct lowpan6_link_addr *dest, struct g3_mcps_data_indication *indication);
err_t lowpan6_g3_if_init(struct netif *netif);
err_t lowpan6_g3_status_handle(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dest, u8_t status);
unsigned int lowpan6_g3_add_mesh_header(u8_t *buffer, u8_t hops_left, const struct lowpan6_link_addr *originator,
                                        const struct lowpan6_link_addr *final_dest);

int lowpan6_g3_group_table_add(u16_t addr);
struct lowpan6_g3_blacklist_entry *lowpan6_g3_blacklist_table_add(u16_t addr);
struct lowpan6_g3_blacklist_entry *lowpan6_g3_blacklist_table_lookup(u16_t addr);
struct lowpan6_g3_routing_entry *lowpan6_g3_routing_table_lookup(u16_t dst, u8_t bidirectional_only);
struct lowpan6_g3_routing_entry *lowpan6_g3_routing_table_add(u16_t dst, u16_t next, u16_t metric, u16_t hop_count);
err_t lowpan6_g3_routing_table_route(struct lowpan6_link_addr *dst, struct lowpan6_link_addr *next);
void lowpan6_g3_routing_table_delete(struct lowpan6_g3_routing_entry *entry);

/* Setter functions */
err_t lowpan6_g3_set_ext_addr(struct netif *netif, const u8_t *addr);
err_t lowpan6_g3_set_pan_id(struct netif *netif, u16_t pan_id);
err_t lowpan6_g3_set_short_addr(struct netif *netif, u8_t addr_high, u8_t addr_low);
err_t lowpan6_g3_set_gmk(struct netif *netif, const u8_t *gmk, u8_t id);
err_t lowpan6_g3_set_device_role(struct netif *netif, u8_t role);

#if LWIP_G3_ADP_TEST
void lowpan6_g3_set_coord_address(u8_t addr_high, u8_t addr_low);
void lowpan6_g3_set_active_key_index(u8_t idx);
err_t lowpan6_g3_set_context(u8_t idx, const u32_t *context, u16_t context_length);
void lowpan6_g3_ihc_enable(u8_t enable);
void lowpan6_g3_datagram_tag_set(u16_t datagram_tag);
void lowpan6_g3_set_bc_seq_num(u8_t seq_num);
void lowpan6_g3_set_max_hops(u8_t max_hops);
void lowpan6_g3_set_security_level(u8_t level);
void lowpan6_g3_set_metric_type(u8_t metric_type);
void lowpan6_g3_set_enable_rlc(u8_t enable);
void lowpan6_g3_set_add_rev_link_cost(u8_t val);
void lowpan6_g3_set_metric_factor_set(u8_t kr, u8_t km, u8_t kc, u8_t kq, u8_t kh, u8_t krt);
void lowpan6_g3_set_unicast_rreq_gen_enable(u8_t enable);
void lowpan6_g3_set_add_rev_link_cost(u8_t val);
void lowpan6_g3_set_weak_lqi_value(u8_t val);
void lowpan6_g3_set_device_type(u8_t dev_type);
#endif /* LWIP_G3_ADP_TEST */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV6 */

#endif /* LWIP_HDR_LOWPAN6_G3_H */

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
 * This is based on the original lowpan6 implementation in lwip.
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

#include "lowpan6_g3.h"
#include "loadng_g3.h"
#include "lbp_g3.h"

#if LWIP_IPV6

#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/nd6.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/tcpip.h"
#include "lwip/snmp.h"

#include "ps_eap_psk_g3plc.h"
#include <string.h>

#define LOWPAN6_BROADCAST_ADDR  0x8001
#define lowpan6_g3_contains_lbp(buf) ((buf)[0] == LOWPAN6_HEADER_ESC && (buf)[1] == LOWPAN6_CMD_LBP)

enum lowpan6_header_size {
  LOWPAN6_HEADER_SZ_IP6 = 1,
  LOWPAN6_HEADER_SZ_FRAG1 = 4,
  LOWPAN6_HEADER_SZ_FRAGN = 5,
  LOWPAN6_HEADER_SZ_ESC = 2
};

/** This is a helper struct for reassembly of fragments
 * (For G3 MAC layer max MSDU is 400 bytes)
 */
struct lowpan6_reass_helper {
  struct lowpan6_reass_helper *next_packet;
  struct pbuf *reass;
  struct pbuf *frags;
  u8_t timer;
  struct lowpan6_link_addr sender_addr;
  u16_t datagram_size;
  u16_t datagram_tag;
};

struct lowpan6_g3_mesh_hdr {
  uint8_t hops_left;
  struct lowpan6_link_addr originator;
  struct lowpan6_link_addr final_dest;
};

/* Maximum frame size is 127 bytes minus CRC size */
#define LOWPAN6_MAX_PAYLOAD (127 - 2)

/** Currently, this state is global, since there's only one 6LoWPAN netif */
static lowpan6_g3_data_t lowpan6_data = {
    .short_mac_addr = {2, {0xFF, 0xFF} },
    .extended_mac_addr = {8, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    .coord_short_address = {2, { 0x00, 0x00 } },
    .max_tones = 36, /* TODO: it should be taken from PHY */
    .security_level = 0x05,
    .broadcast_log_table_ttl = 2,
    .low_lqi_value = 0,
    .high_lqi_value = 255,
    .metric_type = LOADNG_G3_METRIC_COMPOSITE,
    .rrep_wait = 4,
    .rlc_time = 4, /* Implementation specific */
    .rreq_wait = 30,
    .rreq_retries = 0,
    .role_of_device = LOWPAN6_G3_ROLE_NON_LBA,
    .unicast_rreq_gen_enable = 1,
    .max_hops = 8,
    .device_type = LOWPAN6_G3_DEVTYPE_NOT_DEFINED,
    .net_traversal_time = 20,
    .routing_table_ttl = 360,
    .kq = 10, .kh = 4,
    .weak_lqi_value = 52,
    .blacklist_table_ttl = 10,
    .max_join_wait_time = 20,
    .path_discovery_time = 40,
    .bandplan = ps_eap_band_id__g3_cenelec_a
};

#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
#define LWIP_6LOWPAN_CONTEXTS(netif) ((((lowpan6_g3_data_t *)(netif)->state))->context_information_table)
#else
#define LWIP_6LOWPAN_CONTEXTS(netif) NULL
#endif

static const struct lowpan6_link_addr ieee_802154_broadcast = {2, {0xff, 0xff}};

static err_t adpd_data_indication(struct pbuf *p, struct netif *netif)
{
#if LWIP_G3_ADP_TEST
  unsigned i;

  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("\033[1;33m"));
  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("ADPD-DATA.indication:\n"));
  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("\033[0;36m"));
  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("len: %d\n", p->len));

  for (i = 0; i < p->len; i++) {
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("%02X ", ((uint8_t *)p->payload)[i]));
  }

  if (p->next != NULL) {
    for (i = 0; i < p->next->len; i++) {
      LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("%02X ", ((uint8_t *)p->next->payload)[i]));
    }
  }

  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("\033[0m\n"));
#endif

  return ip6_input(p, netif);
}

/* Table functions - data structures used might be optimized
 * in the future. Now they are static arrays.
 */
struct lowpan6_g3_routing_entry *
lowpan6_g3_routing_table_add(u16_t dst, u16_t next, u16_t metric, u16_t hop_count)
{
  unsigned i;

  /* Find first empty/invalid entry */
  for (i = 0; i < LOWPAN6_G3_ROUTING_TABLE_SIZE; i++) {
    if (lowpan6_data.routing_table[i].valid_time == 0) {
      lowpan6_data.routing_table[i].dest_addr = dst;
      lowpan6_data.routing_table[i].next_addr = next;
      lowpan6_data.routing_table[i].metric = metric;
      lowpan6_data.routing_table[i].hop_count = hop_count;
      lowpan6_data.routing_table[i].metric_type = lowpan6_data.metric_type;
      lowpan6_data.routing_table[i].valid_time = lowpan6_data.routing_table_ttl;
      lowpan6_data.routing_table[i].seq_num = 0xFFFF;
      lowpan6_data.routing_table[i].is_bidirectional = 1;
      lowpan6_data.n_routing_entries++;
      return &lowpan6_data.routing_table[i];
    }
  }

  return NULL;
}

/**
 * Function used for routing table management.
 */
struct lowpan6_g3_routing_entry *
lowpan6_g3_routing_table_lookup(u16_t dst, u8_t bidirectional_only)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_ROUTING_TABLE_SIZE; i++) {
    if (lowpan6_data.routing_table[i].valid_time > 0 &&
        lowpan6_data.routing_table[i].dest_addr == dst &&
        (!bidirectional_only || lowpan6_data.routing_table[i].is_bidirectional))
      return &lowpan6_data.routing_table[i];
  }

  return NULL;
}

/**
 * Function used for table lookup when routing packets.
 * Returns ERR_OK if a route is found and sets 'next' pointer
 * to the next hop address.
 */
err_t
lowpan6_g3_routing_table_route(struct lowpan6_link_addr *dst, struct lowpan6_link_addr *next)
{
  struct lowpan6_g3_routing_entry *entry;

  if ((entry = lowpan6_g3_routing_table_lookup(lowpan6_link_addr_to_u16(dst), 1)) == NULL) {
    return ERR_VAL;
  }

  lowpan6_link_addr_set_u16(next, entry->next_addr);

  return ERR_OK;
}

void
lowpan6_g3_routing_table_delete(struct lowpan6_g3_routing_entry *entry)
{
  if (entry == NULL)
    return;
  entry->valid_time = 0;
  lowpan6_data.n_routing_entries--;
}

static int
lowpan6_g3_broadcast_log_table_add(u16_t src_addr, u8_t seq_num)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE; i++) {
    if (lowpan6_data.broadcast_log_table[i].valid_time == 0) {
      lowpan6_data.broadcast_log_table[i].src_addr = src_addr;
      lowpan6_data.broadcast_log_table[i].seq_number = seq_num;
      lowpan6_data.broadcast_log_table[i].valid_time = lowpan6_data.broadcast_log_table_ttl;

      return i;
    }
  }

  return -1;
}

static struct lowpan6_g3_broadcast_log_entry *
lowpan6_g3_broadcast_log_table_lookup(u16_t src_addr, u8_t seq_num)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE; i++) {
    if (lowpan6_data.broadcast_log_table[i].valid_time > 0 &&
        lowpan6_data.broadcast_log_table[i].src_addr == src_addr &&
        lowpan6_data.broadcast_log_table[i].seq_number == seq_num)
          return &lowpan6_data.broadcast_log_table[i];
  }

  return NULL;
}

int
lowpan6_g3_group_table_add(u16_t addr)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_GROUP_TABLE_SIZE; i++) {
    if (lowpan6_data.group_table[i] == 0) {
      lowpan6_data.group_table[i] = addr;
      return i;
    }
  }

  return -1;
}

static u16_t *
lowpan6_g3_group_table_lookup(u16_t addr)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_GROUP_TABLE_SIZE; i++) {
    if (lowpan6_data.group_table[i] == addr) {
      return &lowpan6_data.group_table[i];
    }
  }

  /* Not found */
  return NULL;
}

struct lowpan6_g3_blacklist_entry *
lowpan6_g3_blacklist_table_add(u16_t addr)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_BLACKLIST_TABLE_SIZE; i++) {
    if (lowpan6_data.blacklist_table[i].valid_time == 0) {
      lowpan6_data.blacklist_table[i].address = addr;
      lowpan6_data.blacklist_table[i].valid_time = lowpan6_data.blacklist_table_ttl;

      return &lowpan6_data.blacklist_table[i];
    }
  }

  return NULL;
}

struct lowpan6_g3_blacklist_entry *
lowpan6_g3_blacklist_table_lookup(u16_t addr)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_BLACKLIST_TABLE_SIZE; i++) {
    if (lowpan6_data.blacklist_table[i].valid_time > 0 &&
        lowpan6_data.blacklist_table[i].address == addr) {
      return &lowpan6_data.blacklist_table[i];
    }
  }

  return NULL;
}

static void
lowpan6_g3_blacklist_table_remove(struct lowpan6_g3_blacklist_entry *entry)
{
  entry->valid_time = 0;
}

/* Iterate through all the tables in order to
 * update their valid time. It shall be called
 * every minute.
 */
static void
lowpan6_g3_update_tables(lowpan6_g3_data_t *ctx)
{
  unsigned i;

  for (i = 0; i < LOWPAN6_G3_ROUTING_TABLE_SIZE; i++) {
    if (ctx->routing_table[i].valid_time > 0) {
      if (--ctx->routing_table[i].valid_time == 0) {
        ctx->n_routing_entries--;
      }
    }
  }

  for (i = 0; i < LOWPAN6_G3_BLACKLIST_TABLE_SIZE; i++) {
    if (ctx->blacklist_table[i].valid_time > 0) {
      ctx->blacklist_table[i].valid_time--;
    }
  }

  for (i = 0; i < LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE; i++) {
    if (lowpan6_data.broadcast_log_table[i].valid_time > 0) {
      lowpan6_data.broadcast_log_table[i].valid_time--;
    }
  }

  for (i = 0; i < LWIP_6LOWPAN_NUM_CONTEXTS; i++) {
    if (lowpan6_data.context_information_table[i].valid_lifetime > 0) {
      lowpan6_data.context_information_table[i].valid_lifetime--;
    }
  }
}

/* Fragmentation specific functions: */
static void
free_reass_datagram(struct lowpan6_reass_helper *lrh)
{
  if (lrh->reass) {
    pbuf_free(lrh->reass);
  }
  if (lrh->frags) {
    pbuf_free(lrh->frags);
  }
  mem_free(lrh);
}

/**
 * Removes a datagram from the reassembly queue.
 **/
static void
dequeue_datagram(struct lowpan6_reass_helper *lrh, struct lowpan6_reass_helper *prev)
{
  if (lowpan6_data.reass_list == lrh) {
    lowpan6_data.reass_list = lowpan6_data.reass_list->next_packet;
  } else {
    /* it wasn't the first, so it must have a valid 'prev' */
    LWIP_ASSERT("sanity check linked list", prev != NULL);
    prev->next_packet = lrh->next_packet;
  }
}

/**
 * Periodic timer for 6LoWPAN functions:
 *
 * - Remove incomplete/old packets
 */
void
lowpan6_g3_tmr(void *arg)
{
  struct lowpan6_reass_helper *lrh, *lrh_next, *lrh_prev = NULL;
  struct netif *netif = (struct netif *)arg;
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *)netif->state;

  lrh = lowpan6_data.reass_list;
  while (lrh != NULL) {
    lrh_next = lrh->next_packet;
    if ((--lrh->timer) == 0) {
      dequeue_datagram(lrh, lrh_prev);
      free_reass_datagram(lrh);
    } else {
      lrh_prev = lrh;
    }
    lrh = lrh_next;
  }

  ctx->seconds += LOWPAN6_TMR_INTERVAL / 1000;
  lbp_g3_tmr(arg);

  if (ctx->seconds >= 60) {
    ctx->seconds = 0;
    lowpan6_g3_update_tables(ctx);
  }
}

/*
 * Returns mesh header length
 */
unsigned int
lowpan6_g3_add_mesh_header(u8_t *buffer, u8_t hops_left, const struct lowpan6_link_addr *originator,
                           const struct lowpan6_link_addr *final_dest)
{
  LWIP_ASSERT("buffer != NULL", buffer != NULL);
  LWIP_ASSERT("originator != NULL", originator != NULL);
  LWIP_ASSERT("final_dest != NULL", final_dest != NULL);

  buffer[0] = LOWPAN6_HEADER_MESH |
              ((originator->addr_len == 2) << 5) |
              ((final_dest->addr_len == 2) << 4) |
              ((hops_left & 0xF));

  MEMCPY(buffer + 1, originator->addr, originator->addr_len);
  MEMCPY(buffer + 1 + originator->addr_len, final_dest->addr, final_dest->addr_len);

  return originator->addr_len + final_dest->addr_len + 1;
}

/**
 * Parses LoWPAN6 mesh header. Returns ERR_VAL on failure or number of bytes parsed on
 * success.
 */
static int
lowpan6_parse_mesh_header(const u8_t *buffer, u16_t buffer_len, struct lowpan6_g3_mesh_hdr *hdr)
{
  if (!buffer || buffer_len < 1) {
    return ERR_VAL;
  }

  if (buffer[0] & (1 << 5)) {
    hdr->originator.addr_len = 2;
  } else {
    hdr->originator.addr_len = 8;
  }

  if (buffer[0] & (1 << 4)) {
    hdr->final_dest.addr_len = 2;
  } else {
    hdr->final_dest.addr_len = 8;
  }

  hdr->hops_left = buffer[0] & 0xF;

  if (buffer_len < hdr->originator.addr_len + hdr->final_dest.addr_len + 1) {
    return ERR_VAL;
  }

  MEMCPY(hdr->originator.addr, buffer + 1, hdr->originator.addr_len);
  MEMCPY(hdr->final_dest.addr, buffer + 1 + hdr->originator.addr_len, hdr->final_dest.addr_len);

  return hdr->originator.addr_len + hdr->final_dest.addr_len + 1;
}


static int
lowpan6_g3_parse_bc0_header(const u8_t *buffer, u16_t buffer_len, u8_t *seq_num)
{
  if (!buffer || !seq_num || buffer_len < 2)
    return ERR_VAL;

  if (buffer[0] != LOWPAN6_HEADER_BC0)
    return ERR_VAL;

  *seq_num = buffer[1];

  return 2;
}

static int
lowpan6_g3_add_bc0_header(u8_t *buffer)
{
  buffer[0] = LOWPAN6_HEADER_BC0;
  buffer[1] = lowpan6_data.bc0_seq_num++;

  return 2;
}

/*
 * Encapsulates data into LoWPAN6 frames by generating
 * appropriate header if needed: mesh, broadcast, fragment, IPv6 (Compressed/Uncompressed)
 */
err_t
lowpan6_g3_encapsulate(struct netif *netif, struct pbuf *p, const struct lowpan6_link_addr *src,
                       const struct lowpan6_link_addr *dst, const struct lowpan6_link_addr *final_dest)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *p_frag;
  u16_t frag_len, remaining_len, max_data_len;
  u8_t *buffer;
  u8_t lowpan6_header_len = 0;
  u8_t hidden_header_len = 0;
  u16_t datagram_offset;
  err_t err = ERR_IF;
  u16_t header_len = 0;

  /* We'll use a dedicated pbuf for building 6LoWPAN fragments. */
  p_frag = pbuf_alloc(PBUF_RAW, LOWPAN6_MSDU_MAX, PBUF_RAM);
  if (p_frag == NULL) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    return ERR_MEM;
  }

  LWIP_ASSERT("this needs a pbuf in one piece", p_frag->len == p_frag->tot_len);
  buffer = (u8_t *)p_frag->payload;

  /* We need a mesh header */
  if (!lowpan6_link_addr_cmp(dst, final_dest)) {
    header_len += lowpan6_g3_add_mesh_header(buffer, ctx->max_hops,
                                             &ctx->short_mac_addr, final_dest);

    if (lowpan6_link_addr_cmp(dst, &ieee_802154_broadcast)) {
      header_len += lowpan6_g3_add_bc0_header(buffer + header_len);
    }
  }

  if (ctx->ihc_enable) {
    /* Perform 6LoWPAN IPv6 header compression according to RFC 6282 */
    /* do the header compression (this does NOT copy any non-compressed data) */
    err = lowpan6_compress_headers(netif, (u8_t *)p->payload, p->len,
      buffer + header_len, p_frag->len, &lowpan6_header_len,
      &hidden_header_len, LWIP_6LOWPAN_CONTEXTS(netif), src, dst);
    if (err != ERR_OK) {
      MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
      pbuf_free(p_frag);
      return err;
    }
    pbuf_remove_header(p, hidden_header_len);
  } else {
    /* Send uncompressed IPv6 header with appropriate dispatch byte. */
    lowpan6_header_len = 1;
    buffer[header_len] = LOWPAN6_HEADER_IP6;
  }

  /* Calculate remaining packet length */
  remaining_len = p->tot_len;

  if (remaining_len > 0x7FF) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    /* datagram_size must fit into 11 bit */
    pbuf_free(p_frag);
    return ERR_VAL;
  }

  /* Fragment, or 1 packet? */
  max_data_len = LOWPAN6_MSDU_MAX - header_len - lowpan6_header_len;
  if (remaining_len > max_data_len) {
    u16_t data_len;

    memmove(&buffer[header_len + 4], &buffer[header_len], lowpan6_header_len);
    /* Now we need to fragment the packet. FRAG1 header first */
    buffer[header_len] = LOWPAN6_HEADER_FRAG1 | (((p->tot_len + hidden_header_len) >> 8) & 0x7);
    buffer[header_len + 1] = (p->tot_len + hidden_header_len) & 0xff;
    buffer[header_len + 2] = (ctx->tx_datagram_tag >> 8) & 0xff;
    buffer[header_len + 3] = ctx->tx_datagram_tag & 0xff;

    /* Fragment follows. All data fragments except for last one
     * shall be multiple of 8.
     */
    data_len = (max_data_len - LOWPAN6_HEADER_SZ_FRAG1) & 0xfff8;
    frag_len = data_len + lowpan6_header_len;

    pbuf_copy_partial(p, buffer + header_len + lowpan6_header_len + LOWPAN6_HEADER_SZ_FRAG1, frag_len - lowpan6_header_len, 0);
    remaining_len -= frag_len - lowpan6_header_len;
    /* datagram offset holds the offset before compression */
    datagram_offset = frag_len - lowpan6_header_len + hidden_header_len;
    LWIP_ASSERT("datagram offset must be a multiple of 8", (datagram_offset & 7) == 0);

    /* Calculate frame length */
    p_frag->len = p_frag->tot_len = header_len + LOWPAN6_HEADER_SZ_FRAG1 + frag_len;

    /* send the packet */
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));

    err = g3_mcps_data_request(p_frag, &ctx->short_mac_addr, dst, ctx->security_level,
                               ctx->pan_id, 0, ctx->active_key_index);

    while ((remaining_len > 0) && (err == ERR_OK)) {
      if (lowpan6_link_addr_cmp(dst, &ieee_802154_broadcast)) {
        /* In case of broadcast/multicast we need to increment sequence number */
        buffer[6] = ctx->bc0_seq_num++;
      }
      buffer[header_len] |= LOWPAN6_HEADER_FRAGN; /* Change FRAG1 to FRAGN */

      LWIP_ASSERT("datagram offset must be a multiple of 8", (datagram_offset & 7) == 0);
      buffer[header_len + 4] = (u8_t)(datagram_offset >> 3); /* datagram offset in FRAGN header (datagram_offset is max. 11 bit) */

      frag_len = (LOWPAN6_MSDU_MAX - LOWPAN6_HEADER_SZ_FRAGN - header_len) & 0xfff8;
      /* Last fragment? */
      if (frag_len > remaining_len) {
        frag_len = remaining_len;
      }

      pbuf_copy_partial(p, buffer + header_len + LOWPAN6_HEADER_SZ_FRAGN, frag_len, p->tot_len - remaining_len);
      remaining_len -= frag_len;
      datagram_offset += frag_len;

      /* Calculate frame length */
      p_frag->len = p_frag->tot_len = frag_len + header_len + LOWPAN6_HEADER_SZ_FRAGN;

      /* send the packet */
      MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
      LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));
      err = g3_mcps_data_request(p_frag, &ctx->short_mac_addr, dst, ctx->security_level,
                               ctx->pan_id, 0, ctx->active_key_index);
    }

    ctx->tx_datagram_tag++;

  } else {
    /* It fits in one frame. */
    frag_len = remaining_len;

    /* Copy IPv6 packet */
    pbuf_copy_partial(p, buffer + header_len + lowpan6_header_len, frag_len, 0);
    remaining_len = 0;

    /* Calculate frame length */
    p_frag->len = p_frag->tot_len = frag_len + header_len + lowpan6_header_len;
    LWIP_ASSERT("p_frag->len <= LOWPAN6_MSDU_MAX", p_frag->len <= LOWPAN6_MSDU_MAX);

    /* send the packet */
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));
    err = g3_mcps_data_request(p_frag, &ctx->short_mac_addr, dst, ctx->security_level,
                               ctx->pan_id, 0, ctx->active_key_index);
  }

  pbuf_free(p_frag);

  return err;
}

/**
 * @ingroup sixlowpan
 * Set context
 */
err_t
lowpan6_g3_set_context(u8_t idx, const u32_t *context, u16_t context_length)
{
#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
  if (idx >= LWIP_6LOWPAN_NUM_CONTEXTS) {
    return ERR_ARG;
  }

  lowpan6_data.context_information_table[idx].cid = idx;
  lowpan6_data.context_information_table[idx].context_length = context_length;
  lowpan6_data.context_information_table[idx].c = 1;
  lowpan6_data.context_information_table[idx].valid_lifetime = 360;
  MEMCPY(lowpan6_data.context_information_table[idx].context, context, 16);

  return ERR_OK;
#else
  LWIP_UNUSED_ARG(idx);
  LWIP_UNUSED_ARG(context);
  LWIP_UNUSED_ARG(context_length);
  return ERR_ARG;
#endif
}

#if LWIP_6LOWPAN_INFER_SHORT_ADDRESS
/**
 * @ingroup sixlowpan
 * Set short address
 */
err_t
lowpan6_set_short_addr(u8_t addr_high, u8_t addr_low)
{
  lowpan6_data.short_mac_addr.addr[0] = addr_high;
  lowpan6_data.short_mac_addr.addr[1] = addr_low;

  return ERR_OK;
}
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */

/**
 * @ingroup sixlowpan
 * Resolves IPv6 address to link layer address, performs mesh routing if necessary,
 * fragment packet, compresses IPv6 headers if configured. Sends 6LoWPAN frames
 * to MAC layer.
 *
 * @param netif The LwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ip6addr The IP address of the packet destination.
 *
 * @return err_t
 */
err_t
lowpan6_g3_output(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr next, final_dest;
  ip6_addr_t ip6_src;
  struct ip6_hdr *ip6_hdr;

  /* Don't send packets, if a device short address is not set */
  if (lowpan6_link_addr_cmp(&ctx->short_mac_addr, &ieee_802154_broadcast)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    return ERR_USE;
  }

  ip6_hdr = (struct ip6_hdr *)q->payload;
  ip6_addr_copy_from_packed(ip6_src, ip6_hdr->src);
  ip6_addr_assign_zone(&ip6_src, IP6_UNICAST, netif);

  if (ip6_addr_ismulticast(ip6addr)) {
    MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
    /* Map multicast address: RFC 4944, ch. 9 */
    lowpan6_link_addr_set_u16(&final_dest, lwip_htons(0x8000 | (lwip_ntohl(ip6addr->addr[3]) & 0x1fff)));
    lowpan6_link_addr_set_u16(&next, LOWPAN6_BROADCAST_SHORT_ADDR);
  } else {
    /* Try to derive a MAC short address from IPv6 dest address */
    lowpan6_link_addr_set_u16(&final_dest, lwip_htons(lwip_ntohl(ip6_hdr->dest.addr[3]) & 0xFFFF));

    /* If not possible use PAN-coordinator address as default gateway */
    if ((!ip6_addr_netcmp_zoneless(&ip6_hdr->src, &ip6_hdr->dest)) ||
        (lowpan6_get_address_mode(ip6addr, &final_dest) != 3)) {
      /* TODO: handle network prefixes */
      final_dest = ctx->coord_short_address;
    }

    MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);

    /* By default, we send it straight to the receiver */
    next = final_dest;
    if (!ctx->disable_default_routing) {
      struct g3_mac_nb_entry nb_entry;

      if (lowpan6_g3_routing_table_route(&final_dest, &next) != ERR_OK) {
        /* Routing entry not found */
        if (g3_mac_nb_table_lookup_sync(&final_dest, &nb_entry) < 0) {
          return loadng_g3_route_disc(netif, q, &ctx->short_mac_addr,
                                        &final_dest, 0, ctx->max_hops);
        }
      }
    }
  }

  return lowpan6_g3_encapsulate(netif, q, &ctx->short_mac_addr, &next, &final_dest);
}

/**
 * @ingroup sixlowpan
 * This function is called by the lower layer, when MCPS-DATA.confirm is received.
 * Currently we need to handle only three statuses: NO_ACK, TRANSMISSION_EXPIRES and SUCCESS.
 */
err_t
lowpan6_g3_status_handle(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dest, u8_t status)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr *originator, *final_dest;
  struct lowpan6_g3_mesh_hdr mesh_hdr;
  u8_t *buf;
  u8_t max_hops;
  u8_t is_route_repair;

  /* We only handle short addresses at the moment. TODO: handle LBP */
  if (dest->addr_len != 2)
    return ERR_OK;

  buf = (u8_t *) p->payload;

  if (buf[0] == LOWPAN6_HEADER_ESC && buf[1] == LOWPAN6_CMD_LOADNG) {
    return loadng_g3_status_handle(netif, p, dest, status);
  } else if (buf[0] == LOWPAN6_HEADER_ESC && buf[1] == LOWPAN6_CMD_LBP) {

  }
  /* Basic parsing of a frame */
  if ((buf[0] & 0xc0) == LOWPAN6_HEADER_MESH) {
    if (lowpan6_parse_mesh_header(buf, p->len, &mesh_hdr) < 0)
      return ERR_VAL;

    pbuf_remove_header(p, 6);
    if (mesh_hdr.final_dest.addr_len != 2 || mesh_hdr.originator.addr_len != 2)
      return ERR_OK;

    originator = &mesh_hdr.originator;
    final_dest = &mesh_hdr.final_dest;
  } else {
    originator = &ctx->short_mac_addr;
    final_dest = dest;
  }

  is_route_repair = loadng_g3_route_repair_status(netif, final_dest);
  if (status == g3_mac_status_no_ack ||
      status == g3_mac_status_transaction_expires) {
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_status_handle: Sending data failed due to device %02X%02X being unreachable.\n",
                                     dest->addr[0], dest->addr[1]));
    if (!is_route_repair) {
      LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_status_handle: Starting the Route Repair procedure for: %02X%02X.\n",
                                       dest->addr[0], dest->addr[1]));
      if (lowpan6_link_addr_cmp(originator, &ctx->short_mac_addr))
        max_hops = ctx->max_hops;
      else
        max_hops = mesh_hdr.hops_left;

      /* TODO: don't do route repair on lbp status */
      loadng_g3_route_disc(netif, p, originator, final_dest, 1, max_hops);
    } else {
      LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_status_handle: Data transmission to: %02X%02X failed after the successful Route Repair. Dropping this frame.\n",
                                       dest->addr[0], dest->addr[1]));
    }
  } else if (status != g3_mac_status_success) {
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_status_handle: Sending data failed with status: %02X\n", status));
  }
  /* TODO: do we have to remove a device from blacklist? */

  return ERR_OK;
}

/**
 * @ingroup sixlowpan
 * NETIF input function: don't free the input pbuf when returning != ERR_OK!
 */
err_t
lowpan6_g3_input(struct pbuf *p, struct netif *netif, struct lowpan6_link_addr *src, struct lowpan6_link_addr *dest, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  const u8_t *puc;
  u8_t b, seq_num;
  unsigned pos = 0;
  int ret;
  s16_t i;
  u16_t datagram_size = 0;
  u16_t datagram_offset, datagram_tag;
  struct lowpan6_reass_helper *lrh, *lrh_next, *lrh_prev = NULL;
  struct lowpan6_g3_mesh_hdr mesh_header;
  struct lowpan6_g3_routing_entry *entry;
  struct lowpan6_link_addr next_hop, *originator = src;

  if (p == NULL) {
    return ERR_OK;
  }

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);

  puc = (u8_t *)p->payload;
  if (!lowpan6_g3_contains_lbp(puc) && indication->security_level < ctx->security_level) {
    goto lowpan6_input_discard;
  }

  if (p->len != p->tot_len) {
    /* for now, this needs a pbuf in one piece */
    goto lowpan6_input_discard;
  }

  /* Packet not for us. */
  if ((dest->addr_len == 2 &&
      !lowpan6_link_addr_cmp(dest, &ieee_802154_broadcast) &&
      !lowpan6_link_addr_cmp(dest, &ctx->short_mac_addr)) ||
      (dest->addr_len == 8 && !lowpan6_link_addr_cmp(dest, &ctx->extended_mac_addr))) {
      goto lowpan6_input_discard;
  }

  b = *puc;
  if ((b & 0xc0) == LOWPAN6_HEADER_MESH) {
    if ((ret = lowpan6_parse_mesh_header(puc, p->len, &mesh_header)) < 0)
      goto lowpan6_input_discard;

    pos += ret;
    originator = &mesh_header.originator;
    /* G3 supports only mesh routing of short addresses */
    if (mesh_header.originator.addr_len != 2 || mesh_header.final_dest.addr_len != 2)
      goto lowpan6_input_discard;

    if (mesh_header.hops_left == 0)
      goto lowpan6_input_discard;

    if (lowpan6_link_addr_cmp(dest, &ieee_802154_broadcast)) {
      /* Multicast case */
      if ((ret = lowpan6_g3_parse_bc0_header(puc + pos, p->len - pos, &seq_num)) < 0)
        goto lowpan6_input_discard;

      pos += ret;
      /* Neither broadcast frame nor destined to a group, to which we belong */
      if (lowpan6_link_addr_to_u16(&mesh_header.final_dest) != PP_HTONS(LOWPAN6_BROADCAST_ADDR) &&
          lowpan6_g3_group_table_lookup(lowpan6_link_addr_to_u16(&mesh_header.final_dest)) == NULL) {
          goto lowpan6_input_discard;
      }

      /* Have we seen this frame? */
      if (lowpan6_g3_broadcast_log_table_lookup(lowpan6_link_addr_to_u16(&mesh_header.originator), seq_num) != NULL ||
          memcmp(mesh_header.originator.addr, ctx->short_mac_addr.addr, 2) == 0) {
          goto lowpan6_input_discard;
      }

      /* Accept frame */
      lowpan6_g3_broadcast_log_table_add(lowpan6_link_addr_to_u16(&mesh_header.originator), seq_num);

      /* Check if we shall retransmit this frame */
      if (mesh_header.hops_left > 1) {
        /* Decrement HopsLeft */
        ((uint8_t *)p->payload)[0]--;
        g3_mcps_data_request(p, &ctx->short_mac_addr, &ieee_802154_broadcast,
                             ctx->security_level, ctx->pan_id, 0, ctx->active_key_index);
      }
    } else if (!lowpan6_link_addr_cmp(&mesh_header.final_dest, &ctx->short_mac_addr)) {
      /* Frame not for us */
      entry = lowpan6_g3_routing_table_lookup(lowpan6_link_addr_to_u16(&mesh_header.final_dest), 1);
      if (mesh_header.hops_left > 1) {
        ((uint8_t *)p->payload)[0]--;
        if (entry != NULL) {
          /* Forward the packet to the next hop */
          lowpan6_link_addr_set_u16(&next_hop, entry->next_addr);
          g3_mcps_data_request(p, &ctx->short_mac_addr, &next_hop,
                               ctx->security_level, ctx->pan_id, 0, ctx->active_key_index);
          goto lowpan6_input_discard;
        } else {
          /* An intermediate node does not have a route towards destination */
          loadng_g3_route_disc(netif, p, &mesh_header.originator,
                               &mesh_header.final_dest, 1, mesh_header.hops_left - 1);
          goto lowpan6_input_discard;
        }
      } else {
        if (entry != NULL) {
          lowpan6_g3_routing_table_delete(entry);
        }

        loadng_g3_rerr_issue(netif, &mesh_header.final_dest,
                             &mesh_header.originator, 0);
        goto lowpan6_input_discard;
      }
    }
    /* Packet destined to us */
    src = &mesh_header.originator;
    pbuf_remove_header(p, pos);
  }

  /* Frame destined to us, carry on processing */
  puc = (u8_t *)p->payload;
  b = *puc;
  if ((b & 0xf8) == 0xc0) {
    /* FRAG1 dispatch, add this packet to reassembly list. */
    datagram_size = ((u16_t)(puc[0] & 0x07) << 8) | (u16_t)puc[1];
    datagram_tag = ((u16_t)puc[2] << 8) | (u16_t)puc[3];

    /* check for duplicate */
    lrh = ctx->reass_list;
    while (lrh != NULL) {
      uint8_t discard = 0;
      lrh_next = lrh->next_packet;
      if ((lrh->sender_addr.addr_len == src->addr_len) &&
          (memcmp(lrh->sender_addr.addr, src->addr, src->addr_len) == 0)) {
        /* address match with packet in reassembly. */
        if ((datagram_tag == lrh->datagram_tag) && (datagram_size == lrh->datagram_size)) {
          /* duplicate fragment. */
          goto lowpan6_input_discard;
        } else {
          /* We are receiving the start of a new datagram. Discard old one (incomplete). */
          discard = 1;
        }
      }
      if (discard) {
        dequeue_datagram(lrh, lrh_prev);
        free_reass_datagram(lrh);
      } else {
        lrh_prev = lrh;
      }
      /* Check next datagram in queue. */
      lrh = lrh_next;
    }

    pbuf_remove_header(p, 4); /* hide frag1 dispatch */
    lrh = (struct lowpan6_reass_helper *) mem_malloc(sizeof(struct lowpan6_reass_helper));
    if (lrh == NULL) {
      goto lowpan6_input_discard;
    }

    lrh->sender_addr.addr_len = src->addr_len;

    for (i = 0; i < src->addr_len; i++) {
      lrh->sender_addr.addr[i] = src->addr[i];
    }

    lrh->datagram_size = datagram_size;
    lrh->datagram_tag = datagram_tag;
    lrh->frags = NULL;

    if (*(u8_t *)p->payload == 0x41) {
      /* This is a complete IPv6 packet, just skip dispatch byte. */
      pbuf_remove_header(p, 1); /* hide dispatch byte. */
      lrh->reass = p;
    } else if ((*(u8_t *)p->payload & 0xe0 ) == 0x60) {
      lrh->reass = lowpan6_decompress(p, datagram_size, LWIP_6LOWPAN_CONTEXTS(netif), ctx->pan_id, src, dest);
      if (lrh->reass == NULL) {
        /* decompression failed */
        mem_free(lrh);
        goto lowpan6_input_discard;
      }
    }
    /* TODO: handle the case where we already have FRAGN received */
    lrh->next_packet = ctx->reass_list;
    lrh->timer = 2;
    ctx->reass_list = lrh;
    return ERR_OK;
  } else if ((b & 0xf8) == 0xe0) {
    /* FRAGN dispatch, find packet being reassembled. */
    datagram_size = ((u16_t)(puc[0] & 0x07) << 8) | (u16_t)puc[1];
    datagram_tag = ((u16_t)puc[2] << 8) | (u16_t)puc[3];
    datagram_offset = (u16_t)puc[4] << 3;
    pbuf_remove_header(p, 4); /* hide frag1 dispatch but keep datagram offset for reassembly */
    for (lrh = ctx->reass_list; lrh != NULL; lrh_prev = lrh, lrh = lrh->next_packet) {
      if ((lrh->sender_addr.addr_len == src->addr_len) &&
          (memcmp(lrh->sender_addr.addr, src->addr, src->addr_len) == 0) &&
          (datagram_tag == lrh->datagram_tag) &&
          (datagram_size == lrh->datagram_size)) {
        break;
      }
    }
    if (lrh == NULL) {
      /* rogue fragment */
      goto lowpan6_input_discard;
    }
    /* Insert new pbuf into list of fragments. Each fragment is a pbuf,
       this only works for unchained pbufs. */
    LWIP_ASSERT("p->next == NULL", p->next == NULL);
    if (lrh->reass != NULL) {
      /* FRAG1 already received, check this offset against first len */
      if (datagram_offset < lrh->reass->len) {
        /* fragment overlap, discard old fragments */
        dequeue_datagram(lrh, lrh_prev);
        free_reass_datagram(lrh);
        goto lowpan6_input_discard;
      }
    }
    if (lrh->frags == NULL) {
      /* first FRAGN */
      lrh->frags = p;
    } else {
      /* find the correct place to insert */
      struct pbuf *q, *last;
      u16_t new_frag_len = p->len - 1; /* p->len includes datagram_offset byte */
      for (q = lrh->frags, last = NULL; q != NULL; last = q, q = q->next) {
        u16_t q_datagram_offset = ((u8_t *)q->payload)[0] << 3;
        u16_t q_frag_len = q->len - 1;
        if (datagram_offset < q_datagram_offset) {
          if (datagram_offset + new_frag_len > q_datagram_offset) {
            /* overlap, discard old fragments */
            dequeue_datagram(lrh, lrh_prev);
            free_reass_datagram(lrh);
            goto lowpan6_input_discard;
          }
          /* insert here */
          break;
        } else if (datagram_offset == q_datagram_offset) {
          if (q_frag_len != new_frag_len) {
            /* fragment mismatch, discard old fragments */
            dequeue_datagram(lrh, lrh_prev);
            free_reass_datagram(lrh);
            goto lowpan6_input_discard;
          }
          /* duplicate, ignore */
          pbuf_free(p);
          return ERR_OK;
        }
      }
      /* insert fragment */
      if (last == NULL) {
        lrh->frags = p;
      } else {
        last->next = p;
        p->next = q;
      }
    }
    /* check if all fragments were received */
    if (lrh->reass) {
      u16_t offset = lrh->reass->len;
      struct pbuf *q;
      for (q = lrh->frags; q != NULL; q = q->next) {
        u16_t q_datagram_offset = ((u8_t *)q->payload)[0] << 3;
        if (q_datagram_offset != offset) {
          /* not complete, wait for more fragments */
          return ERR_OK;
        }
        offset += q->len - 1;
      }
      if (offset == datagram_size) {
        /* all fragments received, combine pbufs */
        u16_t datagram_left = datagram_size - lrh->reass->len;
        for (q = lrh->frags; q != NULL; q = q->next) {
          /* hide datagram_offset byte now */
          pbuf_remove_header(q, 1);
          q->tot_len = datagram_left;
          datagram_left -= q->len;
        }
        LWIP_ASSERT("datagram_left == 0", datagram_left == 0);
        q = lrh->reass;
        q->tot_len = datagram_size;
        q->next = lrh->frags;
        lrh->frags = NULL;
        lrh->reass = NULL;
        dequeue_datagram(lrh, lrh_prev);
        mem_free(lrh);

        /* @todo: distinguish unicast/multicast */
        MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
        return adpd_data_indication(q, netif);
      }
    }
    /* pbuf enqueued, waiting for more fragments */
    return ERR_OK;
  } else {
    if (b == 0x41) {
      /* This is a complete IPv6 packet, just skip dispatch byte. */
      pbuf_remove_header(p, 1); /* hide dispatch byte. */
    } else if ((b & 0xe0 ) == 0x60) {
      /* IPv6 headers are compressed using IPHC. */
      p = lowpan6_decompress(p, datagram_size, LWIP_6LOWPAN_CONTEXTS(netif), ctx->pan_id, src, dest);
      if (p == NULL) {
        MIB2_STATS_NETIF_INC(netif, ifindiscards);
        return ERR_OK;
      }
    } else if (b == LOWPAN6_HEADER_ESC && puc[1] == LOWPAN6_CMD_LBP) {
      return lbp_g3_input(netif, p, originator);
    } else if (b == LOWPAN6_HEADER_ESC && puc[1] == LOWPAN6_CMD_LOADNG) {
      return loadng_g3_input(netif, p, src, indication);
    } else {
      goto lowpan6_input_discard;
    }
    /* @todo: distinguish unicast/multicast */
    MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
    return adpd_data_indication(p, netif);
  }
lowpan6_input_discard:
  MIB2_STATS_NETIF_INC(netif, ifindiscards);
  pbuf_free(p);
  /* always return ERR_OK here to prevent the caller freeing the pbuf */
  return ERR_OK;
}

static void
g3_lowpan_timer(void *arg)
{
  lowpan6_g3_tmr(arg);
  sys_timeout(LOWPAN6_TMR_INTERVAL, g3_lowpan_timer, arg);
}
/**
 * @ingroup sixlowpan
 */
err_t
lowpan6_g3_if_init(struct netif *netif)
{
  netif->name[0] = 'G';
  netif->name[1] = '3';
  netif->output_ip6 = lowpan6_g3_output;

  MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);

  /* maximum transfer unit */
  netif->mtu = 1280;

  /* broadcast capability */
  netif->flags = NETIF_FLAG_BROADCAST /* | NETIF_FLAG_LOWPAN6 */;
  netif->state = &lowpan6_data;

  if (g3_mac_reset() < 0) {
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_if_init: Can't reset the MAC\n"));
    return ERR_VAL;
  }

  /* Get Extended MAC address */
  if (g3_get_hwaddr(lowpan6_data.extended_mac_addr.addr) < 0) {
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_if_init: Can't get the MAC\n"));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG, ("lowpan6_g3_if_init: Device MAC addr %016llx\n",
                                   lowpan6_link_addr_to_u64(lowpan6_data.extended_mac_addr.addr)));

  /*
   * A device can become a PAN coordinator by calling
   * lbp_g3_lbs_pan_start()
   */
  lowpan6_data.device_type = LOWPAN6_G3_DEVTYPE_DEVICE;

  LOCK_TCPIP_CORE();
  sys_timeout(LOWPAN6_TMR_INTERVAL, g3_lowpan_timer, netif);
  UNLOCK_TCPIP_CORE();

  return ERR_OK;
}

/* Setter functions for accessing MAC */
err_t
lowpan6_g3_set_short_addr(struct netif *netif, u8_t addr_high, u8_t addr_low)
{
  lowpan6_data.short_mac_addr.addr[0] = addr_high;
  lowpan6_data.short_mac_addr.addr[1] = addr_low;

  return g3_set_shortaddr((u16_t)addr_high << 8 | addr_low);
}

err_t
lowpan6_g3_set_ext_addr(struct netif *netif, const u8_t *addr)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  MEMCPY(ctx->extended_mac_addr.addr, addr, 8);

  return g3_set_hwaddr(addr);
}

err_t
lowpan6_g3_set_gmk(struct netif *netif, const u8_t *gmk, u8_t id)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  if (id >= LOWPAN6_G3_N_GMK_KEYS) {
    return ERR_VAL;
  }

  if (g3_set_gmk(gmk, id) < 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lowpan6_g3_set_gmk: Can't set GMK key!\n"));
    return ERR_VAL;
  }

  MEMCPY(&ctx->gmk[id].key, gmk, 16);
  ctx->gmk[id].is_set = 1;

  return ERR_OK;
}

err_t
lowpan6_g3_set_device_role(struct netif *netif, u8_t role)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u16_t rc_val;

  ctx->role_of_device = role;
  if (role == LOWPAN6_G3_ROLE_LBA) {
    rc_val = 0x7FFF;
  } else {
    rc_val = 0xFFFF;
  }

  return g3_set_rc_coord(rc_val);
}

/**
 * @ingroup sixlowpan
 * Set PAN ID
 */
err_t
lowpan6_g3_set_pan_id(struct netif *netif, u16_t pan_id)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  ctx->pan_id = pan_id;

  return g3_pan_id_set(pan_id);
}

#if LWIP_G3_ADP_TEST
/* Helper setters needed for testing */
void lowpan6_g3_set_coord_address(u8_t addr_high, u8_t addr_low)
{
  lowpan6_data.coord_short_address.addr[0] = addr_high;
  lowpan6_data.coord_short_address.addr[1] = addr_low;
}

void
lowpan6_g3_ihc_enable(u8_t enable)
{
  lowpan6_data.ihc_enable = enable;
}

void
lowpan6_g3_datagram_tag_set(u16_t datagram_tag)
{
  lowpan6_data.tx_datagram_tag = datagram_tag;
}

void
lowpan6_g3_set_bc_seq_num(u8_t seq_num)
{
  lowpan6_data.bc0_seq_num = seq_num;
}

void
lowpan6_g3_set_max_hops(u8_t max_hops)
{
  lowpan6_data.max_hops = max_hops;
}

void
lowpan6_g3_set_metric_type(u8_t metric_type)
{
  lowpan6_data.metric_type = metric_type;
}

void
lowpan6_g3_set_unicast_rreq_gen_enable(u8_t enable)
{
  lowpan6_data.unicast_rreq_gen_enable = enable;
}

void
lowpan6_g3_set_enable_rlc(u8_t enable)
{
  lowpan6_data.enable_rlc = enable;
}

void
lowpan6_g3_set_add_rev_link_cost(u8_t val)
{
  lowpan6_data.add_rev_link_cost = val;
}

void
lowpan6_g3_set_metric_factor_set(u8_t kr, u8_t km, u8_t kc,
                                 u8_t kq, u8_t kh, u8_t krt)
{
  lowpan6_data.kq = kq;
  lowpan6_data.kh = kh;
  lowpan6_data.krt = krt;
  lowpan6_data.kc = kc;
  lowpan6_data.km = km;
  lowpan6_data.kr = kr;
}

void
lowpan6_g3_set_security_level(u8_t level)
{
  lowpan6_data.security_level = level;
}

void
lowpan6_g3_set_weak_lqi_value(u8_t val)
{
  lowpan6_data.weak_lqi_value = val;
}

void
lowpan6_g3_set_device_type(u8_t dev_type)
{
  lowpan6_data.device_type = dev_type;
}

void
lowpan6_g3_set_active_key_index(u8_t idx)
{
  lowpan6_data.active_key_index = idx;
}
#endif /* LWIP_G3_ADP_TEST */

#endif /* LWIP_IPV6 */

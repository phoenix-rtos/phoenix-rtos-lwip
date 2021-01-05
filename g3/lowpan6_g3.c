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

#include "lowpan6_g3.h"

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

#include <string.h>


/** This is a helper struct for reassembly of fragments
 * (IEEE 802.15.4 limits to 127 bytes)
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

/** This struct keeps track of per-netif state */
struct lowpan6_ieee802154_data {
  /** fragment reassembly list */
  struct lowpan6_reass_helper *reass_list;
#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
  /** address context for compression */
  struct lowpan6_context lowpan6_context[LWIP_6LOWPAN_NUM_CONTEXTS];
#endif
  /** Datagram Tag for fragmentation */
  u16_t tx_datagram_tag;
  /** local PAN ID for IEEE 802.15.4 header */
  u16_t ieee_802154_pan_id;
  /** Sequence Number for IEEE 802.15.4 transmission */
  u8_t tx_frame_seq_num;
};

/* Maximum frame size is 127 bytes minus CRC size */
#define LOWPAN6_MAX_PAYLOAD (127 - 2)

/** Currently, this state is global, since there's only one 6LoWPAN netif */
static struct lowpan6_ieee802154_data lowpan6_data;

#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
#define LWIP_6LOWPAN_CONTEXTS(netif) lowpan6_data.lowpan6_context
#else
#define LWIP_6LOWPAN_CONTEXTS(netif) NULL
#endif

static const struct lowpan6_link_addr ieee_802154_broadcast = {2, {0xff, 0xff}};

#if LWIP_6LOWPAN_INFER_SHORT_ADDRESS
static struct lowpan6_link_addr short_mac_addr = {2, {0, 0}};
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */

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
 * Periodic timer for 6LowPAN functions:
 *
 * - Remove incomplete/old packets
 */
void
lowpan6_tmr(void)
{
  struct lowpan6_reass_helper *lrh, *lrh_next, *lrh_prev = NULL;

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
}

/*
 * Encapsulates data into IEEE 802.15.4 frames.
 * Fragments an IPv6 datagram into 6LowPAN units, which fit into IEEE 802.15.4 frames.
 * If configured, will compress IPv6 and or UDP headers.
 * */
static err_t
lowpan6_frag(struct netif *netif, struct pbuf *p, const struct lowpan6_link_addr *src, const struct lowpan6_link_addr *dst)
{
  struct pbuf *p_frag;
  u16_t frag_len, remaining_len, max_data_len;
  u8_t *buffer;
  u8_t ieee_header_len;
  u8_t lowpan6_header_len;
  u8_t hidden_header_len;
  u16_t crc;
  u16_t datagram_offset;
  err_t err = ERR_IF;

  LWIP_ASSERT("lowpan6_frag: netif->linkoutput not set", netif->linkoutput != NULL);

  /* We'll use a dedicated pbuf for building 6LowPAN fragments. */
  p_frag = pbuf_alloc(PBUF_RAW, 127, PBUF_RAM);
  if (p_frag == NULL) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    return ERR_MEM;
  }
  LWIP_ASSERT("this needs a pbuf in one piece", p_frag->len == p_frag->tot_len);

#if LWIP_6LOWPAN_IPHC
  /* Perform 6LowPAN IPv6 header compression according to RFC 6282 */
  /* do the header compression (this does NOT copy any non-compressed data) */
  err = lowpan6_compress_headers(netif, (u8_t *)p->payload, p->len,
    &buffer[ieee_header_len], p_frag->len - ieee_header_len, &lowpan6_header_len,
    &hidden_header_len, LWIP_6LOWPAN_CONTEXTS(netif), src, dst);
  if (err != ERR_OK) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    pbuf_free(p_frag);
    return err;
  }
  pbuf_remove_header(p, hidden_header_len);

#else /* LWIP_6LOWPAN_IPHC */
  /* Send uncompressed IPv6 header with appropriate dispatch byte. */
  lowpan6_header_len = 1;
  buffer[ieee_header_len] = 0x41; /* IPv6 dispatch */
#endif /* LWIP_6LOWPAN_IPHC */

  /* Calculate remaining packet length */
  remaining_len = p->tot_len;

  if (remaining_len > 0x7FF) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    /* datagram_size must fit into 11 bit */
    pbuf_free(p_frag);
    return ERR_VAL;
  }

  /* Fragment, or 1 packet? */
  max_data_len = LOWPAN6_MAX_PAYLOAD - ieee_header_len - lowpan6_header_len;
  if (remaining_len > max_data_len) {
    u16_t data_len;
    /* We must move the 6LowPAN header to make room for the FRAG header. */
    memmove(&buffer[ieee_header_len + 4], &buffer[ieee_header_len], lowpan6_header_len);

    /* Now we need to fragment the packet. FRAG1 header first */
    buffer[ieee_header_len] = 0xc0 | (((p->tot_len + hidden_header_len) >> 8) & 0x7);
    buffer[ieee_header_len + 1] = (p->tot_len + hidden_header_len) & 0xff;

    lowpan6_data.tx_datagram_tag++;
    buffer[ieee_header_len + 2] = (lowpan6_data.tx_datagram_tag >> 8) & 0xff;
    buffer[ieee_header_len + 3] = lowpan6_data.tx_datagram_tag & 0xff;

    /* Fragment follows. */
    data_len = (max_data_len - 4) & 0xf8;
    frag_len = data_len + lowpan6_header_len;

    pbuf_copy_partial(p, buffer + ieee_header_len + lowpan6_header_len + 4, frag_len - lowpan6_header_len, 0);
    remaining_len -= frag_len - lowpan6_header_len;
    /* datagram offset holds the offset before compression */
    datagram_offset = frag_len - lowpan6_header_len + hidden_header_len;
    LWIP_ASSERT("datagram offset must be a multiple of 8", (datagram_offset & 7) == 0);

    /* Calculate frame length */
    p_frag->len = p_frag->tot_len = ieee_header_len + 4 + frag_len + 2; /* add 2 bytes for crc*/

    /* send the packet */
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));
    err = netif->linkoutput(netif, p_frag);

    while ((remaining_len > 0) && (err == ERR_OK)) {
      buffer[ieee_header_len] |= 0x20; /* Change FRAG1 to FRAGN */

      LWIP_ASSERT("datagram offset must be a multiple of 8", (datagram_offset & 7) == 0);
      buffer[ieee_header_len + 4] = (u8_t)(datagram_offset >> 3); /* datagram offset in FRAGN header (datagram_offset is max. 11 bit) */

      frag_len = (127 - ieee_header_len - 5 - 2) & 0xf8;
      if (frag_len > remaining_len) {
        frag_len = remaining_len;
      }

      pbuf_copy_partial(p, buffer + ieee_header_len + 5, frag_len, p->tot_len - remaining_len);
      remaining_len -= frag_len;
      datagram_offset += frag_len;

      /* Calculate frame length */
      p_frag->len = p_frag->tot_len = frag_len + 5 + ieee_header_len + 2;

      /* 2 bytes CRC */
      crc = LWIP_6LOWPAN_DO_CALC_CRC(p_frag->payload, p_frag->len - 2);
      pbuf_take_at(p_frag, &crc, 2, p_frag->len - 2);

      /* send the packet */
      MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
      LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));
      err = netif->linkoutput(netif, p_frag);
    }
  } else {
    /* It fits in one frame. */
    frag_len = remaining_len;

    /* Copy IPv6 packet */
    pbuf_copy_partial(p, buffer + ieee_header_len + lowpan6_header_len, frag_len, 0);
    remaining_len = 0;

    /* Calculate frame length */
    p_frag->len = p_frag->tot_len = frag_len + lowpan6_header_len + ieee_header_len + 2;
    LWIP_ASSERT("", p_frag->len <= 127);

    /* 2 bytes CRC */
    crc = LWIP_6LOWPAN_DO_CALC_CRC(p_frag->payload, p_frag->len - 2);
    pbuf_take_at(p_frag, &crc, 2, p_frag->len - 2);

    /* send the packet */
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p_frag->tot_len);
    LWIP_DEBUGF(LWIP_LOWPAN6_DEBUG | LWIP_DBG_TRACE, ("lowpan6_send: sending packet %p\n", (void *)p));
    err = netif->linkoutput(netif, p_frag);
  }

  pbuf_free(p_frag);

  return err;
}

/**
 * @ingroup sixlowpan
 * Set context
 */
err_t
lowpan6_set_context(u8_t idx, const u32_t *context, u16_t context_length)
{
#if LWIP_6LOWPAN_NUM_CONTEXTS > 0
  if (idx >= LWIP_6LOWPAN_NUM_CONTEXTS) {
    return ERR_ARG;
  }

  lowpan6_data.lowpan6_context[idx].cid = idx;
  lowpan6_data.lowpan6_context[idx].context_length = context_length;
  lowpan6_data.lowpan6_context[idx].c = 1;
  lowpan6_data.lowpan6_context[idx].valid_lifetime = -1; /* @todo: calculate valid lifetime */
  MEMCPY(lowpan6_data.lowpan6_context[idx].context, context, 16);

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
  short_mac_addr.addr[0] = addr_high;
  short_mac_addr.addr[1] = addr_low;

  return ERR_OK;
}
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */

/**
 * @ingroup sixlowpan
 * Resolve and fill-in IEEE 802.15.4 address header for outgoing IPv6 packet.
 *
 * Perform Header Compression and fragment if necessary.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ip6addr The IP address of the packet destination.
 *
 * @return err_t
 */
err_t
lowpan6_output(struct netif *netif, struct pbuf *q, const ip6_addr_t *ip6addr)
{
  err_t result;
  const u8_t *hwaddr;
  struct lowpan6_link_addr src, dest;
#if LWIP_6LOWPAN_INFER_SHORT_ADDRESS
  ip6_addr_t ip6_src;
  struct ip6_hdr *ip6_hdr;
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */

#if LWIP_6LOWPAN_INFER_SHORT_ADDRESS
  /* Check if we can compress source address (use aligned copy) */
  ip6_hdr = (struct ip6_hdr *)q->payload;
  ip6_addr_copy_from_packed(ip6_src, ip6_hdr->src);
  ip6_addr_assign_zone(&ip6_src, IP6_UNICAST, netif);
  if (lowpan6_get_address_mode(&ip6_src, &short_mac_addr) == 3) {
    src.addr_len = 2;
    src.addr[0] = short_mac_addr.addr[0];
    src.addr[1] = short_mac_addr.addr[1];
  } else
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */
  {
    result = lowpan6_hwaddr_to_addr(netif, &src);
    if (result != ERR_OK) {
      MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
      return result;
    }
  }

  /* multicast destination IP address? */
  if (ip6_addr_ismulticast(ip6addr)) {
    MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
    /* We need to send to the broadcast address.*/
    return lowpan6_frag(netif, q, &src, &ieee_802154_broadcast);
  }

  /* We have a unicast destination IP address */
  /* @todo anycast? */

#if LWIP_6LOWPAN_INFER_SHORT_ADDRESS
  if (src.addr_len == 2) {
    /* If source address was compressable to short_mac_addr, and dest has same subnet and
     * is also compressable to 2-bytes, assume we can infer dest as a short address too. */
    dest.addr_len = 2;
    dest.addr[0] = ((u8_t *)q->payload)[38];
    dest.addr[1] = ((u8_t *)q->payload)[39];
    if ((src.addr_len == 2) && (ip6_addr_netcmp_zoneless(&ip6_hdr->src, &ip6_hdr->dest)) &&
        (lowpan6_get_address_mode(ip6addr, &dest) == 3)) {
      MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
      return lowpan6_frag(netif, q, &src, &dest);
    }
  }
#endif /* LWIP_6LOWPAN_INFER_SHORT_ADDRESS */

  /* Ask ND6 what to do with the packet. */
  result = nd6_get_next_hop_addr_or_queue(netif, q, ip6addr, &hwaddr);
  if (result != ERR_OK) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    return result;
  }

  /* If no hardware address is returned, nd6 has queued the packet for later. */
  if (hwaddr == NULL) {
    return ERR_OK;
  }

  /* Send out the packet using the returned hardware address. */
  dest.addr_len = netif->hwaddr_len;
  /* XXX: Inferring the length of the source address from the destination address
   * is not correct for IEEE 802.15.4, but currently we don't get this information
   * from the neighbor cache */
  SMEMCPY(dest.addr, hwaddr, netif->hwaddr_len);
  MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
  return lowpan6_frag(netif, q, &src, &dest);
}
/**
 * @ingroup sixlowpan
 * NETIF input function: don't free the input pbuf when returning != ERR_OK!
 */
err_t
lowpan6_input(struct pbuf *p, struct netif *netif)
{
  u8_t *puc, b;
  s8_t i;
  struct lowpan6_link_addr src, dest;
  u16_t datagram_size = 0;
  u16_t datagram_offset, datagram_tag;
  struct lowpan6_reass_helper *lrh, *lrh_next, *lrh_prev = NULL;

  if (p == NULL) {
    return ERR_OK;
  }

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);

  if (p->len != p->tot_len) {
    /* for now, this needs a pbuf in one piece */
    goto lowpan6_input_discard;
  }

  if (lowpan6_parse_iee802154_header(p, &src, &dest) != ERR_OK) {
    goto lowpan6_input_discard;
  }

  /* Check dispatch. */
  puc = (u8_t *)p->payload;

  b = *puc;
  if ((b & 0xf8) == 0xc0) {
    /* FRAG1 dispatch. add this packet to reassembly list. */
    datagram_size = ((u16_t)(puc[0] & 0x07) << 8) | (u16_t)puc[1];
    datagram_tag = ((u16_t)puc[2] << 8) | (u16_t)puc[3];

    /* check for duplicate */
    lrh = lowpan6_data.reass_list;
    while (lrh != NULL) {
      uint8_t discard = 0;
      lrh_next = lrh->next_packet;
      if ((lrh->sender_addr.addr_len == src.addr_len) &&
          (memcmp(lrh->sender_addr.addr, src.addr, src.addr_len) == 0)) {
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

    lrh->sender_addr.addr_len = src.addr_len;
    for (i = 0; i < src.addr_len; i++) {
      lrh->sender_addr.addr[i] = src.addr[i];
    }
    lrh->datagram_size = datagram_size;
    lrh->datagram_tag = datagram_tag;
    lrh->frags = NULL;
    if (*(u8_t *)p->payload == 0x41) {
      /* This is a complete IPv6 packet, just skip dispatch byte. */
      pbuf_remove_header(p, 1); /* hide dispatch byte. */
      lrh->reass = p;
    } else if ((*(u8_t *)p->payload & 0xe0 ) == 0x60) {
      lrh->reass = lowpan6_decompress(p, datagram_size, LWIP_6LOWPAN_CONTEXTS(netif), 0, &src, &dest);
      if (lrh->reass == NULL) {
        /* decompression failed */
        mem_free(lrh);
        goto lowpan6_input_discard;
      }
    }
    /* TODO: handle the case where we already have FRAGN received */
    lrh->next_packet = lowpan6_data.reass_list;
    lrh->timer = 2;
    lowpan6_data.reass_list = lrh;

    return ERR_OK;
  } else if ((b & 0xf8) == 0xe0) {
    /* FRAGN dispatch, find packet being reassembled. */
    datagram_size = ((u16_t)(puc[0] & 0x07) << 8) | (u16_t)puc[1];
    datagram_tag = ((u16_t)puc[2] << 8) | (u16_t)puc[3];
    datagram_offset = (u16_t)puc[4] << 3;
    pbuf_remove_header(p, 4); /* hide frag1 dispatch but keep datagram offset for reassembly */

    for (lrh = lowpan6_data.reass_list; lrh != NULL; lrh_prev = lrh, lrh = lrh->next_packet) {
      if ((lrh->sender_addr.addr_len == src.addr_len) &&
          (memcmp(lrh->sender_addr.addr, src.addr, src.addr_len) == 0) &&
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
        return ip6_input(q, netif);
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
      p = lowpan6_decompress(p, datagram_size, LWIP_6LOWPAN_CONTEXTS(netif), 0, &src, &dest);
      if (p == NULL) {
        MIB2_STATS_NETIF_INC(netif, ifindiscards);
        return ERR_OK;
      }
    } else {
      goto lowpan6_input_discard;
    }

    /* @todo: distinguish unicast/multicast */
    MIB2_STATS_NETIF_INC(netif, ifinucastpkts);

    return ip6_input(p, netif);
  }
lowpan6_input_discard:
  MIB2_STATS_NETIF_INC(netif, ifindiscards);
  pbuf_free(p);
  /* always return ERR_OK here to prevent the caller freeing the pbuf */
  return ERR_OK;
}

/**
 * @ingroup sixlowpan
 */
err_t
lowpan6_if_init(struct netif *netif)
{
  netif->name[0] = 'L';
  netif->name[1] = '6';
  netif->output_ip6 = lowpan6_output;

  MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);

  /* maximum transfer unit */
  netif->mtu = 1280;

  /* broadcast capability */
  netif->flags = NETIF_FLAG_BROADCAST /* | NETIF_FLAG_LOWPAN6 */;

  return ERR_OK;
}

/**
 * @ingroup sixlowpan
 * Set PAN ID
 */
err_t
lowpan6_set_pan_id(u16_t pan_id)
{
  lowpan6_data.ieee_802154_pan_id = pan_id;

  return ERR_OK;
}

#if !NO_SYS
/**
 * @ingroup sixlowpan
 * Pass a received packet to tcpip_thread for input processing
 *
 * @param p the received packet, p->payload pointing to the
 *          IEEE 802.15.4 header.
 * @param inp the network interface on which the packet was received
 */
err_t
tcpip_6lowpan_input(struct pbuf *p, struct netif *inp)
{
  return tcpip_inpkt(p, inp, lowpan6_input);
}
#endif /* !NO_SYS */

#endif /* LWIP_IPV6 */
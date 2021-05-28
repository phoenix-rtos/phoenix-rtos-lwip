/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - LOADng routing protocol
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#include "loadng_g3.h"
#include "lwip/def.h"
#include "lwip/arch.h"
#include "lwip/sys.h"

#define LOADNG_G3_MAX_DIST          0xFFFF
#define LOADNG_G3_MAX_SEQ_NUM       65535
#define LOADNG_G3_MAX_HOP_COUNT     15

/* Common structure for RREQ and RREP messages */
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_route_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t originator);
  PACK_STRUCT_FIELD(u16_t sequence_number);
  PACK_STRUCT_FLD_8(u8_t metric_type:4);
  PACK_STRUCT_FLD_8(u8_t flags:4);
  PACK_STRUCT_FIELD(u16_t route_cost);
  PACK_STRUCT_FLD_8(u8_t hop_count:4);
  PACK_STRUCT_FLD_8(u8_t hop_limit:4);
  PACK_STRUCT_FLD_8(u8_t reserved:4);
  PACK_STRUCT_FLD_8(u8_t weak_link:4);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_rerr_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t originator);
  PACK_STRUCT_FLD_8(u8_t error_code);
  PACK_STRUCT_FIELD(u16_t unreachable_address);
  PACK_STRUCT_FLD_8(u8_t reserved:4);
  PACK_STRUCT_FLD_8(u8_t hop_limit:4);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_hop_field {
  PACK_STRUCT_FIELD(u16_t address);
  PACK_STRUCT_FLD_8(u8_t reserved);
  PACK_STRUCT_FLD_8(u8_t link_cost);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_preq_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t originator);
  PACK_STRUCT_FLD_8(u8_t path_metric_type);
  PACK_STRUCT_FIELD(u32_t reserved : 24);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_prep_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t expected_originator);
  PACK_STRUCT_FLD_8(u8_t path_metric_type);
  PACK_STRUCT_FLD_8(u8_t reserved);
  PACK_STRUCT_FIELD(u16_t originator);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_rlcreq_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t originator);
  PACK_STRUCT_FLD_8(u8_t metric_type:4);
  PACK_STRUCT_FLD_8(u8_t reserved:4);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN
struct loadng_g3_rlcrep_msg {
  PACK_STRUCT_FIELD(u16_t destination);
  PACK_STRUCT_FIELD(u16_t originator);
  PACK_STRUCT_FLD_8(u8_t reserved:4);
  PACK_STRUCT_FLD_8(u8_t metric_type:4);
  PACK_STRUCT_FLD_8(u8_t link_cost);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif

#define loadng_g3_pbuf_msg_cast(p, type) ((type) (p->payload + 3))
#define loadng_g3_seq_num_gt(s1, s2) ((s1 > s2 && s1 - s2 <= LOADNG_G3_MAX_SEQ_NUM / 2) || \
                                      (s2 > s1 && s2 - s1 > LOADNG_G3_MAX_SEQ_NUM / 2))

#define lowpan6_dev_short_addr(ctx) (lowpan6_link_addr_to_u16(&(ctx)->short_mac_addr))


static int
loadng_seq_num_gt(u16_t s1, u16_t s2)
{
  return (s1 > s2 && s1 - s2 <= LOADNG_G3_MAX_SEQ_NUM / 2) ||
         (s2 > s1 && s2 - s1 > LOADNG_G3_MAX_SEQ_NUM / 2);
}

enum loadng_g3_rreq_state {
  LOADNG_G3_RREQ_STATE_EMPTY = 0,
  LOADNG_G3_RREQ_STATE_WAITING,  /* RREQ waiting for a next time slot */
  LOADNG_G3_RREQ_STATE_PENDING, /* RREQ sent, waiting for RREP */
  LOADNG_G3_RREQ_STATE_RREPAIR_SUCCESS /* Route repair succeeded, waiting for MAC ack */
};

struct loadng_g3_q_entry {
  struct pbuf *p;
  struct loadng_g3_q_entry *next;
};

struct loadng_g3_rreq_entry {
  struct loadng_g3_q_entry *q; /* Packets enqueued waiting for this route request to finish */
  struct netif *netif;
  struct pbuf *msg;
  u16_t originator;
  u16_t dest_addr;
  u8_t valid_time;
  u8_t is_route_repair;
  u8_t n_retries;
  u8_t state;
};

enum loadng_g3_rrep_state {
  LOADNG_G3_RREP_STATE_EMPTY = 0,
  LOADNG_G3_RREP_STATE_WAITING, /* RREP scheduled, waiting rrep_wait time */
  LOADNG_G3_RREP_STATE_TRANSMITTED /* RREP transmitted, but needs to be cached for rrep_wait time */
};

struct loadng_g3_rrep_entry {
  struct netif *netif;
  struct pbuf *p;
  u16_t rreq_originator;
  u16_t rreq_seq_num;
  u8_t time;
  u8_t state;
};

struct loadng_g3_preq_entry {
  struct netif *netif;
  u16_t dst_addr;
  u8_t valid_time;
};

enum loadng_g3_rlc_state {
  LOADNG_G3_RLC_STATE_EMPTY = 0,
  LOADNG_G3_RLC_STATE_WAITING, /* RLCREQ scheduled, waiting for a next time slot */
  LOADNG_G3_RLC_STATE_PENDING /* RLCREQ transmitted, waiting for RLCREP response */
};

struct loadng_g3_rlc_entry {
  struct netif *netif;
  struct loadng_g3_q_entry *q;
  struct pbuf *rlc_msg;
  u16_t previous_hop;
  u8_t msg_type;
  u8_t lqi;
  u16_t fwd_link_cost;
  u8_t valid_time;
  u8_t state;
};

enum loadng_g3_msg_type {
  LOADNG_G3_MSG_TYPE_RREQ = 0,
  LOADNG_G3_MSG_TYPE_RREP = 1,
  LOADNG_G3_MSG_TYPE_RERR = 2,
  LOADNG_G3_MSG_TYPE_PREQ = 252,
  LOADNG_G3_MSG_TYPE_PREP = 253,
  LOADNG_G3_MSG_TYPE_RLCREQ = 254,
  LOADNG_G3_MSG_TYPE_RLCREP = 255
};

enum loadng_g3_route_flags {
  LOADNG_G3_RREQ_FL_RREPAIR = 0x8,
  LOADNG_G3_RREQ_FL_UNICAST = 0x4,
  LOADNG_G3_RREP_FL_ROUTE_REPAIR = 0x8
};

#if LOADNG_G3_DEBUG
static void loadng_g3_routing_entry_debug(struct lowpan6_g3_routing_entry *entry);
#else
#define lodng_g3_routing_entry_debug(p)
#endif

static struct loadng_g3_rreq_entry rreq_table[LOADNG_G3_RREQ_TABLE_SIZE];
static struct loadng_g3_rlc_entry rlc_table[LOADNG_G3_RLC_TABLE_SIZE];
static struct loadng_g3_rrep_entry rrep_table[LOADNG_G3_RREP_TABLE_SIZE];
static struct loadng_g3_preq_entry preq_table[LOADNG_G3_PREQ_TABLE_SIZE];

static u32_t last_rreq_time = 0;
static u32_t last_rlcreq_time = 0;

static struct pbuf *
loadng_g3_msg_init(u8_t msg_type)
{
  struct pbuf *p;
  u8_t msg_len;
  u8_t *buf;

  /* 2 bytes for LoWPAN6 escape 1 byte for msg_type */
  msg_len = 3;
  switch (msg_type) {
    case LOADNG_G3_MSG_TYPE_RREQ:
    case LOADNG_G3_MSG_TYPE_RREP:
      msg_len += sizeof(struct loadng_g3_route_msg);
      break;
    case LOADNG_G3_MSG_TYPE_RERR:
      msg_len += sizeof(struct loadng_g3_rerr_msg);
      break;
    case LOADNG_G3_MSG_TYPE_PREQ:
      msg_len += sizeof(struct loadng_g3_preq_msg);
      break;
    case LOADNG_G3_MSG_TYPE_PREP:
      msg_len += sizeof(struct loadng_g3_prep_msg);
      break;
    case LOADNG_G3_MSG_TYPE_RLCREQ:
      msg_len += sizeof(struct loadng_g3_rlcreq_msg);
      break;
    case LOADNG_G3_MSG_TYPE_RLCREP:
      msg_len += sizeof(struct loadng_g3_rlcrep_msg);
      break;
  }

  p = pbuf_alloc(PBUF_RAW, msg_len, PBUF_RAM);
  if (p == NULL)
    return NULL;

  buf = (u8_t *) p->payload;
  buf[0] = LOWPAN6_HEADER_ESC;
  buf[1] = LOWPAN6_CMD_LOADNG;
  buf[2] = msg_type;

  return p;
}

/**
 * Computes a directional link cost. Parameters to this function
 * might be taken from the MCPS-DATA.indication structure or
 * the MAC neighbour table.
 */
static u16_t
loadng_g3_link_cost_dir(struct netif *netif, u8_t mod_type, u8_t active_tones, u8_t lqi)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  const u8_t mod_km[5] = { 3, 3, 2, 1, 0 };
  const u8_t mod_kr = mod_type == 0; /* Check for Robust modulation type */
  u16_t kq_part, kc_part;

  if (mod_type >= sizeof(mod_km)) {
    return 0;
  }

  kq_part = (ctx->high_lqi_value > lqi) ? (ctx->high_lqi_value - lqi) : 0;
  kq_part = LWIP_MIN(1, kq_part / (ctx->high_lqi_value - ctx->low_lqi_value));

  kc_part = (ctx->max_tones - active_tones) / ctx->max_tones;

  return ctx->kr * mod_kr
         + ctx->km * mod_km[mod_type]
         + ctx->kc * kc_part
         + ctx->kq * kq_part;
}

/**
 * Given MAX(reverse_cost, forward_cost) compute overall
 * composite link cost.
 */
static u16_t
loadng_g3_link_cost_composite(struct netif *netif, u16_t max_dir)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  return max_dir + ((u16_t) ctx->krt * ctx->n_routing_entries / LOWPAN6_G3_ROUTING_TABLE_SIZE)
        + ctx->kh;
}

/**
 * This function is used to compute an overall link cost.
 * The forward cost is always computed based on the MCPS-DATA.indication,
 * while the reverse cost can be computed using a MAC neighbour entry given
 * as a parameter or approximated using the forward cost.
 */
static u16_t
loadng_g3_link_cost(struct netif *netif, struct g3_mcps_data_indication *indication, struct g3_mac_nb_entry *nb)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u16_t cost_fwd, cost_rev;

  cost_fwd = loadng_g3_link_cost_dir(netif, indication->modulation, indication->active_tones, indication->msdu_linkquality);

  /* Neighbour entry is valid */
  if (nb != NULL) {
    cost_rev = loadng_g3_link_cost_dir(netif, nb->mod_type, nb->active_tones, nb->lqi);
  } else {
    cost_rev = cost_fwd + ctx->add_rev_link_cost;
  }

  return loadng_g3_link_cost_composite(netif, LWIP_MAX(cost_fwd, cost_rev));
}

static err_t
loadng_g3_output(struct netif *netif, struct pbuf *p, u16_t short_dest);

/**
 * Send RREQ frame on unicast, if the unicast flag is set or broadcast otherwise.
 */
static err_t
loadng_g3_rreq_transmit(struct netif *netif, struct pbuf *p)
{
  struct loadng_g3_route_msg *rreq;
  struct lowpan6_g3_routing_entry *entry;

  rreq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);

  /* Check if it should be unicast or multicast */
  if ((rreq->flags & LOADNG_G3_RREQ_FL_UNICAST) &&
      (entry = lowpan6_g3_routing_table_lookup(rreq->destination, 1)) != NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_transmit: Sending a unicast RREQ msg to %04X destined to %04X\n",
                               lwip_ntohs(entry->next_addr), lwip_ntohs(rreq->destination)));
    return loadng_g3_output(netif, p, entry->next_addr);
  } else {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_transmit: Broadcasting RREQ msg destined to %04X\n",
                               lwip_ntohs(rreq->destination)));
    return loadng_g3_output(netif, p, LOWPAN6_BROADCAST_SHORT_ADDR);
  }
}

static err_t
loadng_g3_rrep_transmit(struct netif *netif, struct pbuf *p)
{
  struct loadng_g3_route_msg *rrep;
  struct lowpan6_g3_routing_entry *entry;

  rrep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);

  entry = lowpan6_g3_routing_table_lookup(rrep->destination, 0);
  if (entry == NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_transmit: Can't transmit RREP destined to %04X. No routing tuple found.\n",
                               lwip_ntohs(rrep->destination)));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_transmit: Transmitting RREP msg to %04X destined to %04X\n",
                             lwip_ntohs(entry->next_addr), lwip_ntohs(entry->dest_addr)));

  return loadng_g3_output(netif, p, entry->next_addr);
}

static err_t
loadng_g3_prep_transmit(struct netif *netif, struct pbuf *p)
{
  struct lowpan6_g3_routing_entry *entry;
  struct loadng_g3_prep_msg *prep;

  prep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_prep_msg *);
  entry = lowpan6_g3_routing_table_lookup(prep->destination, 1);
  if (entry == NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_prep_transmit: Can't find route to %04X. Discarding RREP\n",
                               lwip_ntohs(prep->destination)));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_prep_transmit: Transmitting PREP to %04X\n",
                               lwip_ntohs(prep->destination)));

  return loadng_g3_output(netif, p, entry->next_addr);
}

static err_t
loadng_g3_prep_generate(struct netif *netif, struct pbuf *p, u16_t preq_destination, u16_t preq_originator)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_prep_msg *prep;
  u8_t *buf;

  /* Don't allocate a new pbuf. Instead use the received
   * PREQ and modify it.
   */
  buf = (u8_t *) p->payload;
  buf[2] = LOADNG_G3_MSG_TYPE_PREP;
  prep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_prep_msg *);
  prep->originator = lowpan6_dev_short_addr(ctx);
  prep->destination = preq_originator;
  prep->expected_originator = preq_destination;
  /* Other fields remain the same as in the PREQ */

  return loadng_g3_prep_transmit(netif, p);
}

static err_t
loadng_g3_preq_transmit(struct netif *netif, struct pbuf *p)
{
  struct lowpan6_g3_routing_entry *entry;
  struct loadng_g3_preq_msg *preq;

  preq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_preq_msg *);

  entry = lowpan6_g3_routing_table_lookup(preq->destination, 1);
  if (entry == NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_preq_transmit: Can't find route to %04X. Replying with PREP\n",
                               lwip_ntohs(preq->destination)));
    return loadng_g3_prep_generate(netif, p, preq->destination, preq->originator);
  }

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_preq_transmit: Transmitting PREQ destined to: %04X through: %04X\n",
                               lwip_ntohs(preq->destination), lwip_ntohs(entry->next_addr)));

  return loadng_g3_output(netif, p, entry->next_addr);
}

static err_t
loadng_g3_rerr_transmit(struct netif *netif, struct pbuf *p)
{
  struct loadng_g3_rerr_msg *rerr;
  struct lowpan6_g3_routing_entry *entry;

  rerr = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_rerr_msg *);
  entry = lowpan6_g3_routing_table_lookup(rerr->destination, 1);
  if (entry == NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rerr_transmit: Can't transmit RERR msg. No routing entry for %04X\n",
                                lwip_ntohs(rerr->destination)));
    return ERR_VAL;
  }

  return loadng_g3_output(netif, p, entry->next_addr);
}

err_t
loadng_g3_rerr_issue(struct netif *netif, struct lowpan6_link_addr *unreachable_addr, struct lowpan6_link_addr *dest, u8_t error_code)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *p;
  struct loadng_g3_rerr_msg *rerr;
  err_t ret;

  p = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_RERR);
  if (p == NULL) {
    return ERR_MEM;
  }

  rerr = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_rerr_msg *);
  rerr->unreachable_address = lowpan6_link_addr_to_u16(unreachable_addr);
  rerr->originator = lowpan6_dev_short_addr(ctx);
  rerr->destination = lowpan6_link_addr_to_u16(dest);
  rerr->error_code = error_code;
  rerr->hop_limit = ctx->max_hops;
  rerr->reserved = 0;

  ret = loadng_g3_rerr_transmit(netif, p);
  pbuf_free(p);

  return ret;
}

/**
 * Start a Route Discovery procedure, e.g. when a destination address is unreachable.
 * @param netif network interface, which received the packet
 * @param p packet to be sent once the route is found
 * @param frame_originator it is necessary, if we are performing a route repair as an intermediate node
 * @param dst destination address
 * @param route_repair set to 1, this Route Discovery is a repair of an existing route
 * @param max_hops maximum number of hops for the requested route
 */
err_t
loadng_g3_route_disc(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *frame_originator,
                     struct lowpan6_link_addr *dst, u8_t route_repair, u8_t max_hops)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *rreq;
  struct loadng_g3_q_entry *entry, *n_entry = NULL;
  struct pbuf *q;
  u16_t src, dst_short, origin_short;
  u32_t now = sys_now();
  unsigned i;

  src = lowpan6_dev_short_addr(ctx);
  dst_short = lowpan6_link_addr_to_u16(dst);
  origin_short = lowpan6_link_addr_to_u16(frame_originator);

  if (p != NULL) {
    n_entry = mem_malloc(sizeof(struct loadng_g3_q_entry));
    LWIP_ERROR("loadng_g3_route_disc: Out of memory!\n", n_entry != NULL, return ERR_MEM);
    n_entry->next = NULL;
    n_entry->p = p;
    pbuf_ref(p);
  }

  /* Check if we have already requested for this route */
  for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
    if (rreq_table[i].state != LOADNG_G3_RREQ_STATE_EMPTY && rreq_table[i].dest_addr == dst_short) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_route_disc: Route discovery of %04X already in progress. Buffer this packet\n",
                                 lwip_ntohs(dst_short)));
      if (p != NULL) {
        if (!rreq_table[i].q) {
          rreq_table[i].q = n_entry;
        } else {
          entry = rreq_table[i].q;
          while (entry->next) {
            entry = entry->next;
          }
          entry->next = n_entry;
        }
      }
      return ERR_OK;
    }
  }

  q = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_RREQ);
  if (q == NULL) {
    if (p != NULL) {
      pbuf_free(p);
      mem_free(n_entry);
    }
    return ERR_MEM;
  }

  rreq = loadng_g3_pbuf_msg_cast(q, struct loadng_g3_route_msg *);
  rreq->originator = src;
  rreq->destination = dst_short;
  rreq->route_cost = 0;
  rreq->flags = (ctx->unicast_rreq_gen_enable) ? LOADNG_G3_RREQ_FL_UNICAST : 0;
  rreq->flags |= (route_repair) ? LOADNG_G3_RREQ_FL_RREPAIR : 0;
  rreq->reserved = 0;
  rreq->hop_count = 0;
  rreq->hop_limit = max_hops;
  rreq->metric_type = ctx->metric_type;
  rreq->weak_link = 0;
  rreq->sequence_number = lwip_htons(ctx->loadng_sequnce_number++);

  /* Set first free entry in rreq_table */
  for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
    if (rreq_table[i].state == LOADNG_G3_RREQ_STATE_EMPTY) {
      rreq_table[i].dest_addr = dst_short;
       /* In case of failure, we shall send RERR to the frame's originator */
      rreq_table[i].originator = origin_short;
      rreq_table[i].is_route_repair = route_repair;
      rreq_table[i].n_retries = ctx->rreq_retries;
      /* After this time it can be retransmitted */
      rreq_table[i].valid_time = 2 * ctx->net_traversal_time;
      if (p != NULL) {
        rreq_table[i].q = n_entry;
      }
      rreq_table[i].msg = q;
      rreq_table[i].netif = netif;
      /* Set state to pending (transmit the frame) only if the
       * time passed since last RREQ transmission is greater than rreq_wait. */
      rreq_table[i].state = (now - last_rreq_time > ctx->rreq_wait) ? LOADNG_G3_RREQ_STATE_PENDING : LOADNG_G3_RREQ_STATE_WAITING;
      break;
    }
  }

  /* RREQ table full */
  if (i == LOADNG_G3_RREQ_TABLE_SIZE) {
    mem_free(n_entry);
    pbuf_free(q);
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_route_disc: Can't start the Route Discovery procedure. RREQ table full\n"));
    return ERR_BUF;
  }

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_route_disc: Route Discovery of %04X started. Unicast: %d Route repair %d\n",
                             lwip_ntohs(dst_short), ctx->unicast_rreq_gen_enable, route_repair));
  /* Transmit it if we can, or it will be transmitted later */
  if (rreq_table[i].state == LOADNG_G3_RREQ_STATE_PENDING) {
    last_rreq_time = now;
    loadng_g3_rreq_transmit(netif, q);
  } else {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_route_disc: We need to wait %ds before sending a new RREQ\n",
                                  ctx->rreq_wait - (now - last_rreq_time)));
  }

  return ERR_OK;
}

/**
 * Temporary helper function, which allows the upper layer to
 * start the Route Discovery procedure without scheduling a packet.
 */
err_t
adpm_route_discovery(struct netif *netif, struct lowpan6_link_addr *dst, u8_t max_hops)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  return loadng_g3_route_disc(netif, NULL, &ctx->short_mac_addr, dst, 0, max_hops);
}

static err_t
loadng_g3_routing_table_update(struct netif *netif, struct loadng_g3_route_msg *msg, u16_t previous_hop, u8_t weak_link_count,
                            u8_t used_metric_type, u16_t link_metric, u16_t route_metric,
                            u8_t hop_count, u8_t msg_type)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_g3_routing_entry *entry;
  u16_t msg_seq_num = lwip_ntohs(msg->sequence_number);

  /* Create or update entry to msg.originator */
  entry = lowpan6_g3_routing_table_lookup(msg->originator, 0);
  if (entry == NULL) {
    entry = lowpan6_g3_routing_table_add(msg->originator, previous_hop, LOADNG_G3_MAX_DIST, hop_count);
    if (!entry) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Failed to add a routing entry. Routing table full.\n"));
      return ERR_MEM;
    }
    /* Set other non default fields */
    entry->metric_type = used_metric_type;
    entry->hop_count = hop_count;
    entry->seq_num = LOADNG_G3_MAX_SEQ_NUM;
    entry->is_bidirectional = 0;
    entry->local_iface_addr = lowpan6_dev_short_addr(ctx);
    entry->weak_link_count = LOADNG_G3_MAX_HOP_COUNT;
  }

  if ((entry->seq_num == msg_seq_num && entry->metric_type == used_metric_type && entry->weak_link_count > weak_link_count) ||
      (entry->seq_num == msg_seq_num && entry->metric_type == used_metric_type && entry->weak_link_count == weak_link_count && entry->metric > route_metric) ||
      (entry->seq_num == msg_seq_num && entry->metric_type == used_metric_type && entry->weak_link_count == weak_link_count && entry->metric == route_metric && entry->hop_count > hop_count) ||
      (entry->seq_num == msg_seq_num && entry->metric_type != used_metric_type && entry->metric_type == LOADNG_G3_METRIC_HOPCOUNT) ||
      loadng_seq_num_gt(msg_seq_num, entry->seq_num)) {
    entry->next_addr = previous_hop;
    entry->metric_type = used_metric_type;
    entry->metric = route_metric;
    entry->hop_count = hop_count;
    entry->seq_num = msg_seq_num;
    entry->valid_time = ctx->routing_table_ttl;
    entry->weak_link_count = weak_link_count;
    /* RREQ is_bidirectional is going to be set if
     * sending RREP to this node succeeds
     */
    if (msg_type == LOADNG_G3_MSG_TYPE_RREP) {
      entry->is_bidirectional = 1;
    }

    loadng_g3_routing_entry_debug(entry);

    /* Create or update route to previous_hop */
    if (previous_hop != msg->originator) {
      entry = lowpan6_g3_routing_table_lookup(previous_hop, 0);

      if (entry == NULL) {
        entry = lowpan6_g3_routing_table_add(previous_hop, previous_hop, link_metric, 1);
        if (!entry) {
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Failed to add a routing entry. Routing table full.\n"));
          return ERR_MEM;
        }
      }

      entry->metric_type = used_metric_type;
      entry->hop_count = 1;
      entry->seq_num = -1;
      entry->valid_time = ctx->routing_table_ttl;
      entry->is_bidirectional = (msg_type == LOADNG_G3_MSG_TYPE_RREP) ? 1 : 0;
      entry->local_iface_addr = lowpan6_dev_short_addr(ctx);
      entry->weak_link_count = (link_metric > ctx->weak_lqi_value) ? 1 : 0;
      loadng_g3_routing_entry_debug(entry);
    }
  }

  return ERR_OK;
}

/**
 * Start a RLC procedure, if a neighbour table entry to previous_hop of a routing msg
 * is missing and RLC is enabled.
 * @param pbuf containing a routing msg, which should be buffered
 */
static err_t
loadng_g3_rlc_start(struct netif *netif, struct pbuf *p, u16_t previous_hop, u8_t metric_type,
                    u8_t msg_type, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr dest;
  struct loadng_g3_rlcreq_msg *rlcreq;
  struct loadng_g3_q_entry *qentry, *tmp;
  struct pbuf *q;
  unsigned i;
  u32_t now = sys_now();
  err_t ret = ERR_OK;

  qentry = mem_malloc(sizeof(struct loadng_g3_q_entry));
  if (qentry == NULL) {
    return ERR_MEM;
  }

  pbuf_ref(p);
  qentry->next = NULL;
  qentry->p = p;

  /* Check if there is already an RLC in progress */
  for (i = 0; i < LOADNG_G3_RLC_TABLE_SIZE; i++) {
    if (rlc_table[i].state != LOADNG_G3_RLC_STATE_EMPTY &&
        rlc_table[i].previous_hop == previous_hop) {
      if (rlc_table[i].q == NULL) {
        rlc_table[i].q = qentry;
      } else {
        tmp = rlc_table[i].q;
        while (tmp->next) {
          tmp = tmp->next;
        }
        tmp->next = qentry;
      }
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlc_start: RLC to %04X already in progress. Enqueue LOADng packet.\n",
                                 lwip_ntohs(previous_hop)));
      return ERR_OK;
    }
  }

  for (i = 0; i < LOADNG_G3_RLC_TABLE_SIZE; i++) {
    if (rlc_table[i].state == LOADNG_G3_RLC_STATE_EMPTY) {
      rlc_table[i].netif = netif;
      rlc_table[i].previous_hop = previous_hop;
      rlc_table[i].valid_time = ctx->rlc_time;
      rlc_table[i].q = qentry;
      rlc_table[i].msg_type = msg_type;
      rlc_table[i].rlc_msg = NULL;
      rlc_table[i].lqi = indication->msdu_linkquality;
      rlc_table[i].fwd_link_cost = loadng_g3_link_cost_dir(netif, indication->modulation,
                                                           indication->active_tones,
                                                           indication->msdu_linkquality);
      break;
    }
  }

  if (i == LOADNG_G3_RLC_TABLE_SIZE) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlc_start: Too many RLC procedures in progress. Discarding.\n"));
    mem_free(qentry);
    pbuf_free(p);
    return ERR_BUF;
  }

  q = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_RLCREQ);
  if (q == NULL) {
      return ERR_MEM;
  }

  rlcreq = loadng_g3_pbuf_msg_cast(q, struct loadng_g3_rlcreq_msg *);
  rlcreq->destination = previous_hop;
  rlcreq->originator = lowpan6_dev_short_addr(ctx);
  rlcreq->metric_type = metric_type;

  if (now - last_rlcreq_time <= ctx->rreq_wait) {
    /* Don't send RLCREQ yet */
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlc_start: We need to wait %d s before sending new RLCREQ. Buffering the packet.\n",
                                last_rlcreq_time));
    rlc_table[i].state = LOADNG_G3_RLC_STATE_WAITING;
    rlc_table[i].rlc_msg = q;
  } else {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlc_start: Sending RLCREQ to %04X.\n",
                                lwip_ntohs(previous_hop)));
    rlc_table[i].state = LOADNG_G3_RLC_STATE_PENDING;
    last_rlcreq_time = now;

    lowpan6_link_addr_set_u16(&dest, rlcreq->destination);
    ret = loadng_g3_output(netif, q, rlcreq->destination);

    pbuf_free(q);
  }

  return ret;
}

/**
 * This function should inform the upper layer, that
 * Path Discovery has finished successfully. Now it just prints
 * the result of this procedure.
 */
static void
loadng_g3_path_discovery_confirm(struct netif *netif, struct pbuf *p)
{
  struct loadng_g3_prep_msg *prep;
  struct loadng_g3_hop_field *hops;
  unsigned i;
  u8_t n_hops;

  prep = (struct loadng_g3_prep_msg *) (p->payload + 3);
  n_hops = (p->len - 3 - sizeof(struct loadng_g3_prep_msg)) / sizeof(struct loadng_g3_hop_field);
  hops = (struct loadng_g3_hop_field *) (p->payload + 3 + sizeof(struct loadng_g3_prep_msg));

  printf("\033[1;33m");
  printf("ADPM-PATH-DISCOVERY.confirm:\n");
  printf("\033[0;36m");
  printf("PathMetricType = %X\n", prep->path_metric_type >> 4);
  for (i = 0; i < n_hops / 2; i++) {
    printf("Hop-%d forward:\n", i + 1);
    printf("\tAddress = %04X\n", lwip_ntohs(hops[i].address));
    printf("\tMNS = %d\n", hops[i].reserved >> 7);
    printf("\tLinkCost = %d\n", hops[i].link_cost);
  }

  for (; i < n_hops; i++) {
    printf("Hop-%d backward:\n", (i + 1) % (n_hops / 2));
    printf("\tAddress = %04X\n", lwip_ntohs(hops[i].address));
    printf("\tMNS = %d\n", hops[i].reserved >> 7);
    printf("\tLinkCost = %d\n", hops[i].link_cost);
  }

  printf("\033[0m");
  printf("\n");
}

/**
 * Given a pbuf containing a PREQ or PREP msg, this function
 * allocates a new pbuf, which is a copy of the old one,
 * and appends a new msg with a hop field.
 */
static struct pbuf *
loadng_g3_hop_append(struct netif *netif, struct pbuf *p, u8_t path_metric_type, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *q;
  struct loadng_g3_hop_field *hop;

  /* Append a hop field to the PREQ msg */
  q = pbuf_alloc(PBUF_RAW, p->len + sizeof(struct loadng_g3_hop_field), PBUF_RAM);
  if (q == NULL)
      return NULL;

  pbuf_copy(q, p);
  hop = (struct loadng_g3_hop_field *) (q->payload + p->len);
  hop->address = lowpan6_dev_short_addr(ctx);

  if (path_metric_type != ctx->metric_type) {
    hop->link_cost = 0;
    hop->reserved = (1 << 7);
  } else {
    /* TODO: allow RLCREQ? */
    hop->link_cost = loadng_g3_link_cost(netif, indication, NULL);
    hop->reserved = 0;
  }

  return q;
}

static err_t
loadng_g3_prep_process(struct netif *netif, struct pbuf *p, u16_t previous_hop, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_prep_msg *prep;
  struct pbuf *q;
  u8_t ret = ERR_OK;
  unsigned i;

  LWIP_ERROR("loadng_g3_prep_process: msg too short\n",
             p->len >= sizeof(struct loadng_g3_prep_msg), return ERR_VAL;);

  prep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_prep_msg *);
  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_prep_process: PREP received with originator: %04X destination %04X\n",
                             lwip_ntohs(prep->originator), lwip_ntohs(prep->destination)));

  q = loadng_g3_hop_append(netif, p, prep->path_metric_type >> 4, indication);
  if (q == NULL)
    return ERR_MEM;

  if (prep->destination == lowpan6_dev_short_addr(ctx)) {
    /* PREP destined to us. Check if we have requested for it. */
    for (i = 0; i < LOADNG_G3_PREQ_TABLE_SIZE; i++) {
      if (preq_table[i].dst_addr == prep->expected_originator &&
          preq_table[i].valid_time > 0) {
        preq_table[i].valid_time = 0;
        loadng_g3_path_discovery_confirm(netif, q);
        break;
      }
    }
  } else {
    ret = loadng_g3_prep_transmit(netif, q);
  }

  pbuf_free(q);

  return ret;
}

/**
 * Start a Path Discovery Procedure used for maintenance.
 *
 * @param dest_addr short destination address in network-byte order
 * @param metric_type used metric type
 *
 */
err_t
loadng_g3_path_discovery(struct netif *netif, struct lowpan6_link_addr *dst, u8_t metric_type)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_preq_msg *preq;
  struct pbuf *p;
  err_t ret;
  unsigned i;
  u16_t dest_short = lowpan6_link_addr_to_u16(dst);

  for (i = 0; i < LOADNG_G3_PREQ_TABLE_SIZE; i++) {
    if (preq_table[i].valid_time > 0 && preq_table[i].dst_addr == dest_short) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_path_discovery: There is already a path discovery of %04X in progress\n",
                                  lwip_ntohs(rreq_table[i].dest_addr)));
      return ERR_INPROGRESS;
    }
  }

  for (i = 0; i < LOADNG_G3_PREQ_TABLE_SIZE; i++) {
    if (preq_table[i].valid_time == 0) {
      preq_table[i].netif = netif;
      preq_table[i].dst_addr = dest_short;
      preq_table[i].valid_time = ctx->path_discovery_time;
      break;
    }
  }

  if (i == LOADNG_G3_PREQ_TABLE_SIZE) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_path_discovery: Too many Path Discovery procedures in progress\n"));
    return ERR_BUF;
  }

  p = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_PREQ);
  if (p == NULL) {
    preq_table[i].valid_time = 0;
    return ERR_MEM;
  }

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_path_discovery: Starting a new Path Discovery destination: %04X\n",
                             lwip_ntohs(dest_short)));

  preq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_preq_msg *);
  preq->originator = lowpan6_dev_short_addr(ctx);
  preq->destination = dest_short;
  preq->path_metric_type = metric_type << 4;

  ret = loadng_g3_preq_transmit(netif, p);
  pbuf_free(p);

  return ret;
}

static err_t
loadng_g3_preq_process(struct netif *netif, struct pbuf *p, u16_t previous_hop, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_preq_msg *preq;
  struct pbuf *q;
  u8_t ret;

  LWIP_ERROR("loadng_g3_preq_process: msg too short\n",
             p->len >= sizeof(struct loadng_g3_preq_msg), return ERR_VAL;);

  preq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_preq_msg *);
  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_preq_process: PREQ received with originator: %04X destination %04X\n",
                             lwip_ntohs(preq->originator), lwip_ntohs(preq->destination)));

  /* Append a hop field to the PREQ msg */
  q = loadng_g3_hop_append(netif, p, preq->path_metric_type >> 4, indication);
  if (q == NULL)
    return ERR_MEM;

  if (preq->destination == lowpan6_dev_short_addr(ctx)) {
    ret = loadng_g3_prep_generate(netif, q, preq->destination, preq->originator);
  } else {
    ret = loadng_g3_preq_transmit(netif, q);
  }

  pbuf_free(q);

  return ret;
}

static err_t loadng_g3_rreq_process(struct netif *netif, struct pbuf *p, u16_t previous_hop, int hop_count,
                                 int hop_limit, u16_t route_metric, u8_t used_metric, u8_t weak_link_count)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *rrep, *rreq;
  struct pbuf *q;
  unsigned i;

  rreq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);

  /* Generate RREP, don't forward RREQ */
  if (rreq->destination == lowpan6_dev_short_addr(ctx)) {
    /* Check if we have already generated this RREP.
     * If we have generated it but not transmitted, do nothing,
     * as this RREP will be transmitted after rrep_wait time since arrival of
     * the first RREQ.
     * If we have transmitted it, we shall retransmit it after rrep_wait time
     * since transmission of the latest RREP.
     */
    for (i = 0; i < LOADNG_G3_RREP_TABLE_SIZE; i++) {
      if (rrep_table[i].state != LOADNG_G3_RREP_STATE_EMPTY &&
          rrep_table[i].rreq_originator == lwip_ntohs(rreq->originator) &&
          rrep_table[i].rreq_seq_num == lwip_ntohs(rreq->sequence_number)) {
        LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_process: Already seen RREQ from %04X. Don't generate any RREP.\n",
                                  lwip_ntohs(rreq->originator)));
        if (rrep_table[i].state == LOADNG_G3_RREP_STATE_TRANSMITTED) {
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_process: RREP to %04X already transmitted. Issue retransmission in %ds.\n",
                                  lwip_ntohs(rreq->originator), ctx->rrep_wait));
          rrep_table[i].state = LOADNG_G3_RREP_STATE_WAITING;
        }
        return ERR_OK;
      }
    }

    q = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_RREP);
    if (q == NULL)
      return ERR_MEM;

    rrep = loadng_g3_pbuf_msg_cast(q, struct loadng_g3_route_msg *);
    rrep->sequence_number = lwip_htons(ctx->loadng_sequnce_number++);
    rrep->metric_type = (rreq->metric_type == ctx->metric_type) ? rreq->metric_type : LOADNG_G3_METRIC_HOPCOUNT;
    rrep->route_cost = 0;
    rrep->hop_count = 0;
    rrep->hop_limit = ctx->max_hops;
    rrep->destination = rreq->originator;
    rrep->originator = lowpan6_dev_short_addr(ctx);
    rrep->weak_link = 0;
    rrep->flags = (rreq->flags & LOADNG_G3_RREQ_FL_RREPAIR) ? LOADNG_G3_RREP_FL_ROUTE_REPAIR : 0;

    /* We will send it later */
    for (i = 0; i < LOADNG_G3_RREP_TABLE_SIZE; i++) {
      if (rrep_table[i].state == LOADNG_G3_RREP_STATE_EMPTY) {
        rrep_table[i].netif = netif;
        rrep_table[i].p = q;
        rrep_table[i].state = LOADNG_G3_RREP_STATE_WAITING;
        rrep_table[i].time = ctx->rrep_wait;
        rrep_table[i].rreq_seq_num = rreq->sequence_number;
        rrep_table[i].rreq_originator = rreq->originator;
        LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_process: Generated RREP to %04X. Wait %ds before issuing.\n",
                                  lwip_ntohs(rreq->originator), ctx->rrep_wait));

        return ERR_OK;
      }
    }

    /* No free entry */
    pbuf_free(q);
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rreq_process: Failed to enqueue the RREP. Table full.\n"));
    return ERR_BUF;
  } else if (hop_count < LOADNG_G3_MAX_HOP_COUNT && hop_limit > 0) {
    /* Forward RREQ */
    rreq->hop_count = hop_count;
    rreq->hop_limit = hop_limit;
    rreq->route_cost = lwip_htons(route_metric);
    rreq->metric_type = used_metric;
    rreq->weak_link = weak_link_count;

    return loadng_g3_rreq_transmit(netif, p);
  }

  /* Dropping packet */
  return ERR_OK;
}

static err_t
loadng_g3_rrep_process(struct netif *netif, struct pbuf *p, u16_t src, int hop_count,
                       int hop_limit, u16_t route_metric, u8_t used_metric, u8_t weak_link_count)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *rrep;
  struct lowpan6_g3_routing_entry *r_entry;
  struct loadng_g3_q_entry *tmp;
  struct lowpan6_link_addr dest, final_dest;
  unsigned i;

  rrep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);
  if (rrep->destination == lowpan6_dev_short_addr(ctx)) {
    /* We have requested this path, so now we can check for queued packets */
    for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
      if (rreq_table[i].dest_addr == rrep->originator &&
          rreq_table[i].state != LOADNG_G3_RREQ_STATE_EMPTY) {
        /* If a packet transmission fails again after a route repair,
         * we shall not perform a route repair again, but instead
         * drop the packet.
         */
        if (rreq_table[i].is_route_repair)
          rreq_table[i].state = LOADNG_G3_RREQ_STATE_RREPAIR_SUCCESS;
        else
          rreq_table[i].state = LOADNG_G3_RREQ_STATE_EMPTY;
        rreq_table[i].valid_time = 0;
        pbuf_free(rreq_table[i].msg);
        r_entry = lowpan6_g3_routing_table_lookup(rreq_table[i].dest_addr, 0);
        if (r_entry != NULL) {
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_process: Route discovery procedure for %04X completed. Sending buffered LoWPAN6 packets to %04X\n",
                                     lwip_ntohs(rreq_table[i].dest_addr), lwip_ntohs(r_entry->next_addr)));
          lowpan6_link_addr_set_u16(&dest, r_entry->next_addr);
          lowpan6_link_addr_set_u16(&final_dest, rreq_table[i].dest_addr);
        } else {
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_process: Route discovery procedure for %04X completed, but there is no routing entry.\n",
                                     lwip_ntohs(rreq_table[i].dest_addr)));
        }

        /* Free all nodes. If routing entry was found, send pbufs */
        while (rreq_table[i].q) {
          tmp = rreq_table[i].q;
          if (r_entry)
            lowpan6_g3_encapsulate(rreq_table[i].netif, tmp->p,
                                   &ctx->short_mac_addr, &dest, &final_dest);
          rreq_table[i].q = tmp->next;
          pbuf_free(tmp->p);
          mem_free(tmp);
        }
        break;
      }
    }
    if (i == LOADNG_G3_RREQ_TABLE_SIZE)
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_process: Ignore this RREP. We have not requested for route to %04X\n",
                                 lwip_ntohs(rrep->originator)));
  } else {
    /* Forward RREP */
    if (hop_count == LOADNG_G3_MAX_HOP_COUNT || hop_limit == 0) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rrep_process: hop_count limit exceeded or hop_limit is 0. Give up forwarding.\n"));
      return ERR_OK;
    }
    rrep->metric_type = used_metric;
    rrep->route_cost = lwip_htons(route_metric);
    rrep->hop_count = hop_count;
    rrep->hop_limit = hop_limit;
    rrep->weak_link = weak_link_count;

    loadng_g3_rrep_transmit(netif, p);
  }

  return ERR_OK;
}

static err_t
loadng_g3_rreq_rrep_process(struct netif *netif, struct pbuf *p, u8_t msg_type, struct lowpan6_link_addr *src, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *msg;
  u16_t link_metric, route_metric, previous_hop;
  u8_t used_metric_type;
  u8_t weak_link_count;
  int hop_count, hop_limit;
  struct lowpan6_g3_routing_entry *r_entry;
  struct g3_mac_nb_entry nb_entry;
  int nb_valid;

  previous_hop = lowpan6_link_addr_to_u16(src);
  LWIP_ERROR("loadng_g3_rreq_rrep_process: msg too short\n",
             p->len >= sizeof(struct loadng_g3_route_msg), return ERR_VAL;);

  msg = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);
  /* If we are the originator, discard it */
  if (msg->originator == lowpan6_dev_short_addr(ctx)) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Discard %s msg, as it was originated by us.\n",
                              (msg_type == LOADNG_G3_MSG_TYPE_RREQ) ? "RREQ" : "RREP"));
    return ERR_OK;
  }

  /* Discard msg, if we have a routing entry newer than msg */
  r_entry = lowpan6_g3_routing_table_lookup(msg->originator, 0);
  if (r_entry != NULL && loadng_seq_num_gt(r_entry->seq_num, lwip_ntohs(msg->sequence_number))) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Discard %s msg, as we have a newer routing entry for destination: %04X.\n",
                              (msg_type == LOADNG_G3_MSG_TYPE_RREQ) ? "RREQ" : "RREP", lwip_ntohs(msg->originator)));
    return ERR_OK;
  }

  /* Discard msg if it came from a blacklisted device */
  if (msg_type == LOADNG_G3_MSG_TYPE_RREQ && lowpan6_g3_blacklist_table_lookup(previous_hop) != NULL) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Discarding RREP msg received from a blacklisted device: %04X.\n",
                               lwip_ntohs(previous_hop)));
    return ERR_OK;
  }


  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Valid %s msg from %04X received originator: %04X destination: %04X.\n",
                            (msg_type == LOADNG_G3_MSG_TYPE_RREQ) ? "RREQ" : "RREP", lwip_ntohs(previous_hop),
                            lwip_ntohs(msg->originator), lwip_ntohs(msg->destination)));

  /* Check if we need RLC mechanism to calculate link cost */
  if ((nb_valid = g3_mac_nb_table_lookup_sync(src, &nb_entry)) < 0 && ctx->enable_rlc) {
    return loadng_g3_rlc_start(netif, p, previous_hop, msg->metric_type, msg_type, indication);
  }

  hop_count = msg->hop_count + 1;
  hop_limit = msg->hop_limit - 1;
  weak_link_count = msg->weak_link;

  if (indication->msdu_linkquality > ctx->weak_lqi_value) {
    weak_link_count++;
  }

  if (msg->metric_type == ctx->metric_type &&
      msg->metric_type != LOADNG_G3_METRIC_HOPCOUNT) {
    used_metric_type = msg->metric_type;
    link_metric = loadng_g3_link_cost(netif, indication, (nb_valid < 0) ? NULL : &nb_entry);
    route_metric = link_metric + lwip_ntohs(msg->route_cost);
  } else {
    used_metric_type = LOADNG_G3_METRIC_HOPCOUNT;
    route_metric = LOADNG_G3_MAX_DIST;
    link_metric = LOADNG_G3_MAX_DIST;
  }

  /* If we don't update the routing table, discard the msg */
  if (loadng_g3_routing_table_update(netif, msg, previous_hop, weak_link_count, used_metric_type,
                                     link_metric, route_metric, hop_count, msg_type) < 0) {
    return ERR_OK;
  }

  if (msg_type == LOADNG_G3_MSG_TYPE_RREQ) {
    return loadng_g3_rreq_process(netif, p, previous_hop, hop_count, hop_limit, route_metric, used_metric_type, weak_link_count);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RREP) {
    return loadng_g3_rrep_process(netif, p, previous_hop, hop_count, hop_limit, route_metric, used_metric_type, weak_link_count);
  } else {
    return ERR_VAL;
  }
}


static err_t
loadng_g3_rlc_rreq_rrep_reprocess(struct netif *netif, struct pbuf *p, u8_t msg_type, u16_t rev_link_cost, u16_t fwd_link_cost, u16_t previous_hop, u8_t lqi)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *msg;
  u16_t link_metric, route_metric;
  u8_t used_metric_type;
  u8_t weak_link_count;
  int hop_count, hop_limit;

  msg = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);
  hop_count = msg->hop_count + 1;
  hop_limit = msg->hop_limit - 1;
  weak_link_count = msg->weak_link;

  if (lqi > ctx->weak_lqi_value)
    weak_link_count++;

  used_metric_type = msg->metric_type;
  link_metric = loadng_g3_link_cost_composite(netif, LWIP_MAX(rev_link_cost, fwd_link_cost));
  route_metric = lwip_ntohs(msg->route_cost) + link_metric;

  loadng_g3_routing_table_update(netif, msg, previous_hop, weak_link_count, used_metric_type,
                                link_metric, route_metric, hop_count, msg_type);

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlc_rreq_rrep_reprocess: Reprocessing %s msg destined to %04X\n",
                             (msg_type == LOADNG_G3_MSG_TYPE_RREQ) ? "RREQ" : "RREP", lwip_ntohs(msg->destination)));
  if (msg_type == LOADNG_G3_MSG_TYPE_RREQ) {
    return loadng_g3_rreq_process(netif, p, previous_hop, hop_count, hop_limit, route_metric, used_metric_type, weak_link_count);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RREP) {
    return loadng_g3_rrep_process(netif, p, previous_hop, hop_count, hop_limit, route_metric, used_metric_type, weak_link_count);
  } else {
    return ERR_VAL;
  }
}

static err_t
loadng_g3_rlcrep_process(struct netif *netif, struct pbuf *p, u16_t previous_hop, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_rlcrep_msg *rlcrep;
  struct loadng_g3_q_entry *tmp;
  unsigned i;

  LWIP_ERROR("loadng_g3_rlcrep_process: msg too short\n",
             p->len >= sizeof(struct loadng_g3_rlcrep_msg), return ERR_VAL;);

  rlcrep = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_rlcrep_msg *);
  if (rlcrep->destination != lowpan6_dev_short_addr(ctx)) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcrep_process: Received RLCREP not for us. Dropping.\n"));
    return ERR_VAL;
  }


  for (i = 0; i < LOADNG_G3_RLC_TABLE_SIZE; i++) {
    if (rlc_table[i].state == LOADNG_G3_RLC_STATE_PENDING &&
        rlc_table[i].previous_hop == rlcrep->originator) {
      break;
    }
  }

  if (i == LOADNG_G3_RLC_TABLE_SIZE) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcrep_process: Received RLCREP we were not waiting for.\n"));
      return ERR_VAL;
  }

  rlc_table[i].state = LOADNG_G3_RLC_STATE_EMPTY;

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcrep_process: Received RLCREP from %04X with link cost: %d\n",
                              lwip_ntohs(previous_hop), rlcrep->link_cost));
  while (rlc_table[i].q) {
    tmp = rlc_table[i].q;
    loadng_g3_rlc_rreq_rrep_reprocess(netif, tmp->p, rlc_table[i].msg_type, rlcrep->link_cost,
                                      rlc_table[i].fwd_link_cost, previous_hop, rlc_table[i].lqi);
    rlc_table[i].q = tmp->next;
    pbuf_free(tmp->p);
    mem_free(tmp);
  }

  return ERR_OK;
}

static err_t
loadng_g3_rlcreq_process(struct netif *netif, struct pbuf *p, struct g3_mcps_data_indication *indication)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_rlcreq_msg *rlcreq;
  struct loadng_g3_rlcrep_msg *rlcrep;
  struct pbuf *q;
  err_t ret = ERR_OK;

  LWIP_ERROR("loadng_g3_rlcreq_process: msg too short\n",
             p->len >= sizeof(struct loadng_g3_rlcreq_msg), return ERR_VAL;);

  rlcreq = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_rlcreq_msg *);

  /* RLCREQ not for us. Routing RLCREQ is not supported */
  if (rlcreq->destination != lowpan6_dev_short_addr(ctx)) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcreq_process: Received RLCREQ not for us. Dropping.\n"));
    return ERR_VAL;
  }

  if (rlcreq->metric_type != ctx->metric_type) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcreq_process: Received RLCREQ with unknown metric type. Dropping.\n"));
    return ERR_VAL;
  }

  q = loadng_g3_msg_init(LOADNG_G3_MSG_TYPE_RLCREP);
  if (q == NULL) {
    return ERR_MEM;
  }

  rlcrep = loadng_g3_pbuf_msg_cast(q, struct loadng_g3_rlcrep_msg *);
  rlcrep->destination = rlcreq->originator;
  rlcrep->originator = rlcreq->destination;
  rlcrep->metric_type = rlcreq->metric_type;
  /* Calculate forward link cost */
  rlcrep->link_cost = loadng_g3_link_cost_dir(netif, indication->modulation,
                                              indication->active_tones,
                                              indication->msdu_linkquality);
  rlcrep->reserved = 0;

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rlcreq_process: Received RLCREQ from %04X. Responding with RLCREP\n",
                             lwip_ntohs(rlcreq->originator)));

  ret = loadng_g3_output(netif, q, rlcrep->destination);
  pbuf_free(q);

  return ret;
}

static err_t
loadng_g3_rerr_process(struct netif *netif, struct pbuf *p, u16_t previous_hop)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_rerr_msg *rerr;
  struct lowpan6_g3_routing_entry *entry;

  if (p->len < sizeof(struct loadng_g3_rerr_msg)) {
    return ERR_VAL;
  }

  rerr = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_rerr_msg *);

  if (rerr->originator == lowpan6_dev_short_addr(ctx)) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rerr_process: Received RERR msg originated by us. Discarding.\n"));
    return ERR_OK;
  }

  rerr->hop_limit--;
  entry = lowpan6_g3_routing_table_lookup(rerr->unreachable_address, 0);
  if (entry != NULL && entry->next_addr == previous_hop) {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_rerr_process: Removing routing entry to %04X\n",
                               lwip_ntohs(entry->dest_addr)));
    lowpan6_g3_routing_table_delete(entry);
  }

  if (rerr->hop_limit > 0 && rerr->destination != lowpan6_dev_short_addr(ctx)) {
    /* RERR Forward */
    loadng_g3_rerr_transmit(netif, p);
  }

  return ERR_OK;
}

/* Timer function called every second
 * by the lowpan6 timer
 */
void
loadng_g3_tmr(void)
{
  lowpan6_g3_data_t *ctx;
  struct lowpan6_link_addr dest, orig;
  struct loadng_g3_q_entry *tmp;
  struct loadng_g3_route_msg *rreq;
  u32_t now = sys_now();
  unsigned i;

  /* Update RREP table */
  for (i = 0; i < LOADNG_G3_RREP_TABLE_SIZE; i++) {
    if (rrep_table[i].state != LOADNG_G3_RREP_STATE_EMPTY) {
      if (rrep_table[i].time > 0) {
        rrep_table[i].time--;
      }
      if (rrep_table[i].time == 0) {
        if (rrep_table[i].state == LOADNG_G3_RREP_STATE_TRANSMITTED) {
          pbuf_free(rrep_table[i].p);
          rrep_table[i].state = LOADNG_G3_RREP_STATE_EMPTY;
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: Freeing RREP entry with rreq_originator = %04X\n",
                                     lwip_ntohs(rrep_table[i].rreq_originator)));
        } else {
          ctx = (lowpan6_g3_data_t *) rrep_table[i].netif->state;
          loadng_g3_rrep_transmit(rrep_table[i].netif, rrep_table[i].p);
          rrep_table[i].state = LOADNG_G3_RREP_STATE_TRANSMITTED;
          rrep_table[i].time = ctx->rrep_wait;
        }
      }
    }
  }

  /* Update RREQ table */
  for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
    /* TODO: do we need more fair transmission? */
    ctx = (lowpan6_g3_data_t *) rreq_table[i].netif->state;
    if (rreq_table[i].state == LOADNG_G3_RREP_STATE_WAITING &&
        now - last_rreq_time > ctx->rreq_wait) {
      /* Send a scheduled RREQ */
      rreq_table[i].state = LOADNG_G3_RREQ_STATE_PENDING;
      last_rreq_time = now;
      loadng_g3_rreq_transmit(rreq_table[i].netif, rreq_table[i].msg);
    } else if (rreq_table[i].state == LOADNG_G3_RREQ_STATE_PENDING) {
      if (rreq_table[i].valid_time > 0) {
        rreq_table[i].valid_time--;
      }

      if (rreq_table[i].valid_time == 0) {
        if (rreq_table[i].n_retries > 0) {
          /* Prepare to retransmission */
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: No response to RREQ to %04X. Retries left: %d.\n",
                                     rreq_table[i].dest_addr, rreq_table[i].n_retries));
          rreq_table[i].n_retries--;
          rreq_table[i].valid_time = 2 * ctx->net_traversal_time;
          rreq = loadng_g3_pbuf_msg_cast(rreq_table[i].msg, struct loadng_g3_route_msg *);
          rreq->sequence_number = lwip_htons(ctx->loadng_sequnce_number++);
          loadng_g3_rreq_transmit(rreq_table[i].netif, rreq_table[i].msg);
        } else {
          /* Route discovery fail */
          LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: Route discovery of %04X failed.\n",
                                     lwip_ntohs(rreq_table[i].dest_addr)));

          /* If it was a route repair started by an intermediate device, inform the frame's
           * originator by sending an RERR.
           */
          if (rreq_table[i].is_route_repair &&
              rreq_table[i].originator != lowpan6_dev_short_addr(ctx)) {
            lowpan6_link_addr_set_u16(&dest, rreq_table[i].dest_addr);
            lowpan6_link_addr_set_u16(&orig, rreq_table[i].originator);
            loadng_g3_rerr_issue(rreq_table[i].netif, &dest, &orig, 0);
          }
          rreq_table[i].state = LOADNG_G3_RREQ_STATE_EMPTY;
          pbuf_free(rreq_table[i].msg);
          while (rreq_table[i].q) {
            tmp = rreq_table[i].q;
            rreq_table[i].q = tmp->next;
            pbuf_free(tmp->p);
            mem_free(tmp);
          }
        }
      }
    }
  }

  /* Update PREQ table */
  for (i = 0; i < LOADNG_G3_PREQ_TABLE_SIZE; i++) {
    if (preq_table[i].valid_time > 0) {
      preq_table[i].valid_time--;
      if (preq_table[i].valid_time == 0) {
        LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: Path discovery of %04X failed\n",
                                     lwip_ntohs(preq_table[i].dst_addr)));
      }
    }
  }

  /* Update RLCREQ table */
  for (i = 0; i < LOADNG_G3_RLC_TABLE_SIZE; i++) {
    ctx = (lowpan6_g3_data_t *) rlc_table[i].netif->state;
    if (rlc_table[i].state == LOADNG_G3_RLC_STATE_PENDING) {
      rlc_table[i].valid_time--;
      if (rlc_table[i].valid_time == 0) {
        LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: No response to RLCREQ %04X. Calculating reverse link cost using forward link cost.\n",
                                   lwip_ntohs(rlc_table[i].previous_hop)));
        rlc_table[i].state = LOADNG_G3_RLC_STATE_EMPTY;
        while (rlc_table[i].q) {
          tmp = rlc_table[i].q;
          loadng_g3_rlc_rreq_rrep_reprocess(rlc_table[i].netif, tmp->p, rlc_table[i].msg_type,
                                            rlc_table[i].fwd_link_cost + ctx->add_rev_link_cost,
                                            rlc_table[i].fwd_link_cost, rlc_table[i].previous_hop,
                                            rlc_table[i].lqi);
          rlc_table[i].q = rlc_table[i].q->next;
          pbuf_free(tmp->p);
          mem_free(tmp);
        }
      }
    } else if (rlc_table[i].state == LOADNG_G3_RLC_STATE_WAITING &&
               now - last_rlcreq_time > ctx->rreq_wait) {
      LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_tmr: Sending the buffered RLCREQ to %04X.\n",
                                 lwip_ntohs(rlc_table[i].previous_hop)));
      rlc_table[i].state = LOADNG_G3_RLC_STATE_PENDING;
      last_rlcreq_time = now;
      loadng_g3_output(rlc_table[i].netif, rlc_table[i].rlc_msg, rlc_table[i].previous_hop);
      pbuf_free(rlc_table[i].rlc_msg);
    }
  }
}

/**
 * This function is called by a status handler.
 * It checks if a confirmed frame was sent after
 * a successful route repair procedure. If yes, it returns 1
 * and updates the RREQ table. If not, it returns 0.
 */
err_t
loadng_g3_route_repair_status(struct netif *netif, struct lowpan6_link_addr *final_dest)
{
  unsigned i;

  for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
    if (rreq_table[i].state == LOADNG_G3_RREQ_STATE_RREPAIR_SUCCESS &&
        rreq_table[i].dest_addr == lowpan6_link_addr_to_u16(final_dest)) {
      rreq_table[i].state = LOADNG_G3_RREQ_STATE_EMPTY;
      return 1;
    }
  }

  return 0;
}

/**
 * This function gets called when the ADP layer
 * receives MCPS-DATA.confirm from MAC succeeding
 * sending a LOADng frame.
 */
err_t
loadng_g3_status_handle(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dest, u8_t status)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct loadng_g3_route_msg *msg;
  struct lowpan6_g3_routing_entry *rentry;
  struct lowpan6_g3_blacklist_entry *bentry;
  u8_t msg_type;
  u16_t dst_short;
  unsigned i;

  dst_short = lowpan6_link_addr_to_u16(dest);
  msg_type = *(u8_t *) (p->payload + 2);
  if (msg_type == LOADNG_G3_MSG_TYPE_RREP) {
    /* A successful sending of RREP sets the route as bidirectional */
    if (status == g3_mac_status_success) {
      msg = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);
      rentry = lowpan6_g3_routing_table_lookup(msg->destination, 0);
      if (rentry != NULL) {
        LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_status_handle: RREP msg status success. Setting route to %04X as bidirectional\n",
                                   lwip_ntohs(msg->destination)));
        rentry->is_bidirectional = 1;
      }
    } else if (status == g3_mac_status_no_ack || status == g3_mac_status_transaction_expires) {
      /* On failure, update blacklist table */
      bentry = lowpan6_g3_blacklist_table_lookup(dst_short);
      if (bentry == NULL) {
        bentry = lowpan6_g3_blacklist_table_add(dst_short);
        LWIP_ERROR("loadng_g3_status_handle: Blacklist table full!\n", bentry != NULL, return ERR_BUF);
      }
      bentry->valid_time = ctx->blacklist_table_ttl;
    }
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RREQ) {
    msg = loadng_g3_pbuf_msg_cast(p, struct loadng_g3_route_msg *);
    if ((msg->flags & LOADNG_G3_RREQ_FL_UNICAST) &&
        (status == g3_mac_status_no_ack || status == g3_mac_status_transaction_expires)) {
      /* A unicast RREQ failed, so let's try broadcast */
      for (i = 0; i < LOADNG_G3_RREQ_TABLE_SIZE; i++) {
        if (rreq_table[i].state != LOADNG_G3_RREQ_STATE_EMPTY &&
            rreq_table[i].dest_addr == lowpan6_link_addr_to_u16(dest)) {
          if (rreq_table[i].msg) {
            LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3_status_handle: A unicast RREQ to %04X failed. Trying broadcast\n",
                                       dst_short));
            loadng_g3_output(netif, rreq_table[i].msg, LOWPAN6_BROADCAST_SHORT_ADDR);
            rreq_table[i].valid_time = 2 * ctx->net_traversal_time;
          }
          break;
        }
      }
    }
  }

  return ERR_OK;
}

/**
 * LOADng output function.
 * @param dest 16-bits network order destination address.
 */
static err_t
loadng_g3_output(struct netif *netif, struct pbuf *p, u16_t short_dest)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr dest;

  lowpan6_link_addr_set_u16(&dest, short_dest);

  return g3_mcps_data_request(p, &ctx->short_mac_addr, &dest, ctx->security_level,
                              ctx->pan_id, 0, ctx->active_key_index);
}

/**
 * LOADng input function called by lowpan6_g3_input function.
 */
err_t
loadng_g3_input(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *src, struct g3_mcps_data_indication *indication)
{
  u16_t previous_hop;
  u8_t msg_type;
  err_t ret;

  LWIP_ERROR("loadng_g3_input: invalid pbuf\n", p != NULL && p->len > 0, return ERR_VAL);

  msg_type = *(u8_t *)(p->payload + 2);
  previous_hop = lowpan6_link_addr_to_u16(src);

  if (msg_type == LOADNG_G3_MSG_TYPE_RREP || msg_type == LOADNG_G3_MSG_TYPE_RREQ) {
    ret = loadng_g3_rreq_rrep_process(netif, p, msg_type, src, indication);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_PREQ) {
    ret = loadng_g3_preq_process(netif, p, previous_hop, indication);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_PREP) {
    ret = loadng_g3_prep_process(netif, p, previous_hop, indication);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RERR) {
    ret = loadng_g3_rerr_process(netif, p, previous_hop);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RLCREP) {
    ret = loadng_g3_rlcrep_process(netif, p, previous_hop, indication);
  } else if (msg_type == LOADNG_G3_MSG_TYPE_RLCREQ) {
    ret = loadng_g3_rlcreq_process(netif, p, indication);
  } else {
    LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Unknown msg type received: %02x\n", msg_type));
    ret = ERR_VAL;
  }

  pbuf_free(p);

  return ret;
}

#if LOADNG_G3_DEBUG

static void
loadng_g3_routing_entry_debug(struct lowpan6_g3_routing_entry *entry)
{
  printf("Entry for destination address %04X\n", lwip_ntohs(entry->dest_addr));
  printf("--------------------------------------\n");
  printf("|\tNext Hop Address: %04X\n", lwip_ntohs(entry->next_addr));
  printf("|\tRoute Cost: %d\n", entry->metric);
  printf("|\tHop Count: %d\n", entry->hop_count);
  printf("|\tWeak Link Count: %d\n", entry->weak_link_count);
  printf("|\tValid time: %d\n", entry->valid_time);
  printf("|\tIs bidirectional: %d\n", entry->is_bidirectional);
  printf("---------------------------------------\n");
}

#endif

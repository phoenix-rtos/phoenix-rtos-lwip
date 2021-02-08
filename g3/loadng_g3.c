/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - LoadNG routing protocol
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#include "loadng_g3.h"
#include "lwip/def.h"
#include "lwip/arch.h"

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
  LOADNG_G3_RREQ_STATE_RREPAIR_SUCCESS /* Route repair suceeded, waiting for MAC ack */
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

#if LOADNG_DEBUG
static void loadng_g3_routing_entry_debug(struct lowpan6_g3_routing_entry *entry);
#else
#define lodng_g3_routing_entry_debug(p)
#endif

static struct loadng_g3_rreq_entry rreq_table[LOADNG_G3_RREQ_TABLE_SIZE];
static struct loadng_g3_rlc_entry rlc_table[LOADNG_G3_RLC_TABLE_SIZE];
static struct loadng_g3_rrep_entry rrep_table[LOADNG_G3_RREP_TABLE_SIZE];
static struct loadng_g3_preq_entry preq_table[LOADNG_G3_PREQ_TABLE_SIZE];

static struct pbuf *
loadng_g3_msg_init(u8_t msg_type)
{
  struct pbuf *p;
  u8_t msg_len;
  u8_t *buf;

  /* 2 bytes for LOWPAN6 escape 1 byte for msg_type */
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
 * LoadNG output function.
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
 * LoadNG input function called by lowpan6_g3_input function.
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

  LWIP_DEBUGF(LOADNG_G3_DEBUG, ("loadng_g3: Unknown msg type received: %02x\n", msg_type));
  ret = ERR_VAL;

  pbuf_free(p);

  return ret;
}

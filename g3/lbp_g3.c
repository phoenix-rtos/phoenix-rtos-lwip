/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer - LoWPAN Bootstrapping Protocol
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#include "lbp_g3.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include <string.h>

#include "ps_eap.h"
#include "ps_eap_psk.h"

#define LBP_G3_HEADER_LEN 12
#define LBP_G3_PCHANNEL_EXT_TYPE_PARAM 0x02
#define LBP_G3_PARAM_RES_LEN  4

#define lbp_g3_gmk_is_set(idx) (ctx->gmk[idx].is_set)

#define lbp_g3_msg_payload(pbuf) ((u8_t *) ((pbuf)->payload + LBP_G3_HEADER_LEN))
#define lbp_g3_msg_payload_len(pbuf) ((pbuf)->tot_len - LBP_G3_HEADER_LEN)
#define lbp_g3_msg_code(pbuf) (((u8_t *)(pbuf)->payload)[2] >> 4)
#define lbp_g3_msg_addr(pbuf) ((u8_t *)((pbuf)->payload + 4))
#define lbp_g3_attr_flg(attr) (1 << ((attr) - 1))

#define LBP_G3_BOOTSTRAP_PARAMS_MASK (lbp_g3_attr_flg(LBP_G3_ATTR_SHORT_ADDR) | \
                                      lbp_g3_attr_flg(LBP_G3_ATTR_GMK) | \
                                      lbp_g3_attr_flg(LBP_G3_ATTR_GMK_ACTIVATION))

/* LBP Type and Message codes */
enum lbp_g3_msg_type {
  LBP_G3_MSG_JOINING = 0x01,
  LBP_G3_MSG_ACCEPTED = 0x09,
  LBP_G3_MSG_CHALLENGE = 0x0a,
  LBP_G3_MSG_DECLINE = 0x0b,
  LBP_G3_MSG_LBD_KICK = 0x04,
  LBP_G3_MSG_LBS_KICK = 0x0c
};

/* LIB attribute IDs */
enum lbp_g3_attr {
  LBP_G3_ATTR_PAN_ID = 1,
  LBP_G3_ATTR_PAN_TYPE = 2,
  LBP_G3_ATTR_ADDR_LBS = 3,
  LBP_G3_ATTR_JOIN_TIME = 4,
  LBP_G3_ATTR_DEVICE_ROLE = 5,
  LBP_G3_ATTR_SHORT_ADDR = 7,
  LBP_ATTR_SHORT_ADDR_DIST_MECH = 8,
  LBP_G3_ATTR_GMK = 9,
  LBP_G3_ATTR_GMK_ACTIVATION = 10,
  LBP_G3_ATTR_GMK_REMOVAL = 11,
  LBP_G3_ATTR_PARAM_RESULT = 12,
  LBP_G3_ATTR_OTHER = 15,
};

enum lbp_g3_dev_state {
  LBP_G3_STATE_IDLE = 0,
  LBP_G3_STATE_SCANNING,
  LBP_G3_STATE_SCAN_FINISHED,
  LBP_G3_STATE_JOINING,
  LBP_G3_STATE_WAIT_MSG3,
  LBP_G3_STATE_WAIT_ACCEPT,
  LBP_G3_STATE_ERROR
};

enum lbp_g3_param_result {
  LBP_G3_PARAM_SUCCESS = 0x00,
  LBP_G3_PARAM_MISSING = 0x01,
  LBP_G3_PARAM_INVALID_VAL = 0x02,
  LBP_G3_PARAM_INVALID_ID = 0x03
};

enum lbp_g3_param_type {
  LBP_G3_LIB_DSI = 0, /* Device Specific Information */
  LBP_G3_LIB_PSI = 1, /* Pan Specific Information */
};

enum LBP_G3_EAP_STATE {
  LBP_G3_EAP_STATE_IDLE = 0,
  LBP_G3_EAP_STATE_WAIT_MSG1,
  LBP_G3_EAP_STATE_WAIT_MSG2,
  LBP_G3_EAP_STATE_WAIT_MSG3,
  LBP_G3_EAP_STATE_WAIT_MSG4,
  LBP_G3_EAP_STATE_WAIT_ACCEPTED
};

static struct {
  ps_eap_psk_nai_t nai_p;
  ps_eap_psk_ctx_t eap_ctx;
} lbp_data;

static struct pbuf *
lbp_g3_msg_init(u8_t msg_type, const u8_t *lbd_addr, u16_t payload_size)
{
  struct pbuf *p;
  u8_t *buf;

  p = pbuf_alloc(PBUF_G3_MESH, LBP_G3_HEADER_LEN + payload_size, PBUF_RAM);
  if (p == NULL) {
    return NULL;
  }

  buf = (u8_t *) p->payload;

  buf[0] = LOWPAN6_HEADER_ESC;
  buf[1] = LOWPAN6_CMD_LBP;
  buf[2] = msg_type << 4;
  buf[3] = 0;
  if (lbd_addr != NULL) {
    MEMCPY(buf + 4, lbd_addr, 8);
  } else {
    memset(buf + 4, 0, 8);
  }

  return p;
}

void
lbp_g3_set_connected(struct netif *netif)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  ctx->state = LBP_G3_STATE_IDLE;
  ctx->connected = 1;
}

static err_t
lbp_g3_output(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dst)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr *src, next;
  u8_t security_level;

  /* If we're not connected yet, use MAC extended address */
  if (!ctx->connected) {
    src = &ctx->extended_mac_addr;
  } else {
    src = &ctx->short_mac_addr;
  }

  /* Assume, that if either src or dst address is extended,
   * we are sending packets between a device already connected to
   * the network and the one not connected. In this case,
   * turn the security off.
   */
  if (dst->addr_len == 8 || src->addr_len == 8) {
    security_level = 0;
  } else {
    security_level = ctx->security_level;
  }

  /* Check if there's a need for a mesh header.
   * Applies only to LBS - LBA communication.
   */
  if (dst->addr_len == 2 && src->addr_len == 2) {
    if (lowpan6_g3_routing_table_route(dst, &next) < 0) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_output: Destination unknown!\n"));
      /* TODO: route discovery? */
      return ERR_VAL;
    }

    if (!lowpan6_link_addr_cmp(dst, &next)) {
      /* Adding mesh header */
      pbuf_add_header(p, 5);
      lowpan6_g3_add_mesh_header((u8_t *) p->payload, ctx->max_hops, src, dst);
    }
  }

  return g3_mcps_data_request(p, src, dst, security_level,
                              ctx->pan_id, 0, ctx->active_key_index);
}

err_t
lbp_g3_input(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u8_t msg_code;
  u8_t *lbd_addr;
  err_t ret = ERR_OK;

  if (p->tot_len < LBP_G3_HEADER_LEN) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: Packet too short, discarding\n"));
    return ERR_VAL;
  }

  msg_code = lbp_g3_msg_code(p);
  lbd_addr = lbp_g3_msg_addr(p);

  if (ctx->device_type == LOWPAN6_G3_DEVTYPE_DEVICE) {
    if (memcmp(ctx->extended_mac_addr.addr, lbd_addr, 8)) {
      /* Frame not for us */
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: Frame not for us: %016llX. Discarding.\n", lowpan6_link_addr_to_u64(lbd_addr)));
      ret = ERR_VAL;
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: Wrong frame's originator!\n"));
      ret = ERR_VAL;
    }
  }

  pbuf_free(p);

  return ret;
}

/* Function called by the LBD and LBS */
void
lbp_g3_init(struct netif *netif, const u8_t *psk, const u8_t *rand, const u8_t *id, u8_t id_len)
{
  lowpan6_g3_data_t *ctx;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("psk != NULL", psk != NULL);
  LWIP_ASSERT("rand != NULL", rand != NULL);
  LWIP_ASSERT("id != NULL", id != NULL);

  ctx = (lowpan6_g3_data_t *) netif->state;
  ps_eap_psk_init(&lbp_data.eap_ctx, (ps_eap_psk_key_t *) psk);
  if (ctx->device_type == LOWPAN6_G3_DEVTYPE_COORD) {
    MEMCPY(&lbp_data.eap_ctx.rand_s.data, rand, PS_EAP_PSK_RAND_LENGTH);
    MEMCPY(&lbp_data.eap_ctx.nai_s.data, id, id_len);
    lbp_data.eap_ctx.nai_s.length = id_len;
  } else {
    MEMCPY(&lbp_data.eap_ctx.rand_p.data, rand, PS_EAP_PSK_RAND_LENGTH);
    ps_eap_psk_tek_init(&lbp_data.eap_ctx, &lbp_data.eap_ctx.rand_p);
    MEMCPY(&lbp_data.nai_p.data, id, id_len);
    lbp_data.nai_p.length = id_len;
  }
}

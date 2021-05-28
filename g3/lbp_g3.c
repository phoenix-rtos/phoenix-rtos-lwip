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

static struct g3_scan_entry scan_table[LBP_G3_SCAN_TABLE_SIZE];

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

/* TODO: this should be per-netif */
static struct {
#if LBP_G3_PAN_COORDINATOR
  u8_t eap_id;
#endif
  ps_eap_psk_nai_t nai_p;
  ps_eap_psk_ctx_t eap_ctx;
  u32_t nonce;
} lbp_data;

/* Code specific for LBS/PAN coordinator */
#if LBP_G3_PAN_COORDINATOR

enum lbp_g3_lbs_dev_state {
  LBP_G3_LBS_DEV_EMPTY = 0,
  LBP_G3_LBS_DEV_JOINING,
  LBP_G3_LBS_DEV_ACCEPTED,
  LBP_G3_LBS_DEV_REKEYING
};

/*
 * A structure used by the PAN coordinator in order
 * to manage devices.
 */
struct lbp_g3_lbs_devinfo {
  struct lowpan6_link_addr tmp_link_addr; /* Used only for bootstrapping it can be LBD or LBA */
  struct netif *netif;
  u16_t short_addr;
  u8_t ext_addr[8];
  u8_t dev_state;
  u8_t eap_state;
  u32_t join_time;
};

/* TODO: blacklist management */
struct lbp_g3_lbs_blacklist_entry {
  u8_t ext_addr[8];
  u8_t is_valid;
};

static struct lbp_g3_lbs_devinfo device_table[LBP_G3_PAN_DEVINFO_TABLE_SIZE];
static struct lbp_g3_lbs_blacklist_entry blacklist_table[LBP_G3_PAN_BLACKLIST_SIZE];

#endif /* LBP_G3_PAN_COORDINATOR */

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

static err_t
lbp_g3_output(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *dst);

/**
 * Starts the joining procedure using the given LBA. It sets
 * the PAN ID.
 * @param pan_id in machine order
 * @param lba in machine order
 */
err_t
lbp_g3_join(struct netif *netif, u16_t pan_id, u16_t lba)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *p;
  err_t ret;

  /* Set PAN ID in MAC and in ADP */
  if (lowpan6_g3_set_pan_id(netif, pan_id) != ERR_OK) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_join: Can't set PAN ID\n"));
    return ERR_VAL;
  }

  lowpan6_link_addr_set_u16(&ctx->lba_address, lwip_htons(lba));
  p = lbp_g3_msg_init(LBP_G3_MSG_JOINING, ctx->extended_mac_addr.addr, 0);
  if (p == NULL) {
    return ERR_MEM;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_join: Joining network PAN ID: %04X using LBA: %04X\n", pan_id, lba));
  ret = lbp_g3_output(netif, p, &ctx->lba_address);
  if (ret == ERR_OK) {
    ctx->state = LBP_G3_STATE_JOINING;
    ctx->join_timeout = ctx->max_join_wait_time;
  }

  pbuf_free(p);

  return ret;
}

/*
 * This function starts network scanning.
 * Equivalent to ADPM-DISCOVERY.request.
 */
err_t
lbp_g3_discovery(struct netif *netif, u8_t duration)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  unsigned i;

  if (ctx->state == LBP_G3_STATE_SCANNING) {
    return ERR_INPROGRESS;
  }

  for (i = 0; i < LBP_G3_SCAN_TABLE_SIZE; i++) {
    scan_table[i].valid = 0;
  }

  if (g3_mlme_scan_request(scan_table, LBP_G3_SCAN_TABLE_SIZE, duration) < 0) {
    return ERR_VAL;
  }
  ctx->state = LBP_G3_STATE_SCANNING;
  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_discovery: Network scan started\n"));

  return ERR_OK;
}


/**
 * Function used to start bootstrap procedure for a PAN device.
 * It is required to call lbp_g3_init prior to this call.
 */
err_t
lbp_g3_start(struct netif *netif, u8_t scan_duration)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  if (lbp_g3_discovery(netif, scan_duration) < 0) {
    return ERR_VAL;
  }

  ctx->state = LBP_G3_STATE_SCANNING;
  return ERR_OK;
}

void
lbp_g3_set_connected(struct netif *netif)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  ctx->state = LBP_G3_STATE_IDLE;
  ctx->connected = 1;
}

static u8_t
lbp_g3_param_encode(u8_t *buf, u8_t attr_id, u8_t attr_type, u8_t attr_len, const u8_t *attr_val)
{
  buf[0] = attr_id << 2 | attr_type << 1 | 1;
  buf[1] = attr_len;
  MEMCPY(buf + 2, attr_val, attr_len);

  return 2 + attr_len;
}

static u8_t
lbp_g3_param_decode(u8_t *buf, u8_t *attr_id, u8_t *attr_len, u8_t **attr_val)
{
  *attr_id = buf[0] >> 2;
  *attr_len = buf[1];
  *attr_val = buf + 2;

  return *attr_len + 2;
}

static u8_t
lbp_g3_encode_param_result(u8_t *buf, u8_t id, u8_t res)
{
  u8_t val[] = {id, res};

  return lbp_g3_param_encode(buf, LBP_G3_ATTR_PARAM_RESULT, LBP_G3_LIB_DSI, 2, val);
}

/*
 * This method is used by the PAN device to handle configuration parameters
 * sent by the LBS, either during bootstrapping, rekeying or in other situations.
 * It also encodes parameter-result as a response.
 */
static int
lbp_g3_handle_params(struct netif *netif, u8_t *in_buf, u16_t in_len,
                     u8_t *out_buf, u16_t out_len, ps_eap_psk_p_result_t *res, u16_t expected_attr_mask)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u8_t pos_in = 0, pos_out = 0;
  u16_t missing_param = 1;
  u8_t attr_id, attr_len;
  u8_t *attr_val;

  while (pos_in < in_len) {
    pos_in += lbp_g3_param_decode(in_buf + pos_in, &attr_id, &attr_len, &attr_val);
    expected_attr_mask &= ~lbp_g3_attr_flg(attr_id);
    switch (attr_id) {
      case LBP_G3_ATTR_GMK:
        if (attr_len != LOWPAN6_G3_GMK_LEN + 1 || *attr_val >= LOWPAN6_G3_N_GMK_KEYS) {
          if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
            pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_VAL);
          }
        } else {
          lowpan6_g3_set_gmk(netif, attr_val + 1, *attr_val);
        }
        break;
      case LBP_G3_ATTR_GMK_ACTIVATION:
        if (attr_len != 1 || *attr_val >= LOWPAN6_G3_N_GMK_KEYS || !ctx->gmk[*attr_val].is_set) {
          if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
            pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_VAL);
          }
        } else {
          ctx->active_key_index = *attr_val;
        }
        break;
      case LBP_G3_ATTR_SHORT_ADDR:
        if (attr_len != 2 || (attr_val[0] == 0xFF && attr_val[1] == 0xFF)) {
          if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
            pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_VAL);
          }
        } else {
          ctx->short_address = attr_val[0] << 8 | attr_val[1];
          LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_params: Received short address: %04X\n", ctx->short_address));
          /* If we received this address during bootstrapping, don't set it yet */
          if (ctx->state == LBP_G3_STATE_IDLE) {
            lowpan6_g3_set_short_addr(netif, attr_val[0], attr_val[1]);
          }
        }
        break;
      case LBP_G3_ATTR_ADDR_LBS:
        if (attr_len != sizeof(u16_t)) {
          if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
            pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_VAL);
          }
        } else {
          lowpan6_g3_set_coord_address(attr_val[0], attr_val[1]);
        }
        break;
      case LBP_G3_ATTR_GMK_REMOVAL:
        if (attr_len != 1 || *attr_val >= LOWPAN6_G3_N_GMK_KEYS ||
            !ctx->gmk[*attr_val].is_set || ctx->active_key_index == *attr_val) {
          if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
            pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_VAL);
          }
        } else {
          ctx->gmk[*attr_val].is_set = 0;
        }
        break;
      case LBP_G3_ATTR_JOIN_TIME:
      case LBP_G3_ATTR_PAN_ID:
      case LBP_G3_ATTR_PAN_TYPE:
      case LBP_G3_ATTR_PARAM_RESULT:
      case LBP_ATTR_SHORT_ADDR_DIST_MECH:
      case LBP_G3_ATTR_DEVICE_ROLE:
      case LBP_G3_ATTR_OTHER:
        /* Not implemented */
        break;
      default:
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_params: Unknown parameter received: %02X!\n", attr_id));
        if (pos_out + LBP_G3_PARAM_RES_LEN < out_len) {
          pos_out += lbp_g3_encode_param_result(out_buf + pos_out, attr_id, LBP_G3_PARAM_INVALID_ID);
        }
    }
  }

  /* We have not received all the expected params */
  while (expected_attr_mask != 0) {
    /* Find, which param is missing */
    while ((lbp_g3_attr_flg(missing_param) & expected_attr_mask) == 0) {
      missing_param++;
    }

    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_params: Missing expected param: %u!\n", missing_param));
    expected_attr_mask &= ~lbp_g3_attr_flg(missing_param);
    pos_out += lbp_g3_encode_param_result(out_buf + pos_out, missing_param, LBP_G3_PARAM_MISSING);
  }

  /* If we don't encounter any errors, encode SUCCESS result */
  if (pos_out == 0) {
    *res = ps_eap_psk_p_result__done_success;
    pos_out += lbp_g3_encode_param_result(out_buf + pos_out, 0, LBP_G3_PARAM_SUCCESS);
  } else{
    *res = ps_eap_psk_p_result__done_failure;
  }

  return pos_out;
}

static err_t
lbp_g3_handle_accepted(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  ps_eap_code_t eap_code;
  ps_eap_psk_t_subfield_t eap_subfield;
  ps_eap_psk_p_result_t p_res;
  u8_t *lbp_payload, *lbd_addr, *eap_data;
  u16_t payload_len, p_res_len, eap_data_len = 0;
  u8_t eap_id;
  struct pbuf *reply;
  err_t ret;
  u16_t expected_params_mask = 0;

  lbp_payload = lbp_g3_msg_payload(p);
  lbd_addr = lbp_g3_msg_addr(p);
  payload_len = lbp_g3_msg_payload_len(p);

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Got LBP ACCEPTED msg.\n"));

  if (payload_len == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Expecting payload!\n"));
    return ERR_VAL;
  }

  if (ctx->state == LBP_G3_STATE_WAIT_ACCEPT) {
    /* We are expecting an EAP SUCCESS msg */
    if (ps_eap_psk_decode_header(lbp_payload, payload_len, &eap_code, &eap_id,
                                  &eap_subfield, &eap_data, &eap_data_len) != ps_eap__success) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Error while decoding msg!\n"));
      ctx->state = LBP_G3_STATE_ERROR;
      return ERR_VAL;
    }

    if (eap_code != ps_eap_code__success) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Expecting EAP SUCCESS msg!\n"));
      ctx->state = LBP_G3_STATE_ERROR;
      return ERR_VAL;
    }

    if (!ctx->is_rekeying) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Bootstrapping succeeded. Setting short addr: %04X and GMK.\n",
                            ctx->short_address));

      ctx->state = LBP_G3_STATE_IDLE;
      if (lowpan6_g3_set_short_addr(netif, ctx->short_address >> 8, ctx->short_address & 0xFF) < 0) {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Can't set short address!\n"));
        ctx->state = LBP_G3_STATE_ERROR;
        return ERR_VAL;
      }

      ctx->connected = 1;
      lowpan6_g3_set_device_role(netif, LOWPAN6_G3_ROLE_LBA);
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Rekeying succeeded.\n"));
      ctx->state = LBP_G3_STATE_IDLE;
    }

    /* TODO: callback to inform the upper layer on success? */
    return ERR_OK;
  } else if (ctx->state == LBP_G3_STATE_IDLE) {
    /*
     * In this state we might receive a parameter, e.g. GMK-activation
     * after the rekeying.
     */
    if (!(lbp_payload[0] & 0x01)) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Expecting a parameter!\n"));
      ctx->state = LBP_G3_STATE_ERROR;
      return ERR_VAL;
    }
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_handle_accepted: Received params!\n"));

    /* Allocate maximum possible pbuf, since we don't know yet,
     * how many param results will be encoded */
    reply = lbp_g3_msg_init(LBP_G3_MSG_JOINING, lbd_addr,
                            LOWPAN6_MSDU_MAX - LBP_G3_HEADER_LEN);
    if (reply == NULL)
      return ERR_MEM;

    if (ctx->is_rekeying) {
      expected_params_mask = lbp_g3_attr_flg(LBP_G3_ATTR_GMK_ACTIVATION);
      ctx->is_rekeying = 0;
    }

    p_res_len = lbp_g3_handle_params(netif, lbp_payload, payload_len,
                                     lbp_g3_msg_payload(reply), lbp_g3_msg_payload_len(reply),
                                     &p_res, expected_params_mask);
    reply->len = reply->tot_len = LBP_G3_HEADER_LEN + p_res_len;

    /* Reply to coordinator */
    ret = lbp_g3_output(netif, reply, origin);
    pbuf_free(reply);

    return ret;
  }

  return ERR_OK;
}

static err_t
lbp_g3_handle_msg1(struct netif *netif, struct lowpan6_link_addr *origin, u8_t *lbd_addr,
                   u16_t eap_data_len, u8_t *eap_data, u8_t eap_id)
{
  ps_eap_psk_rand_t rand_s;
  ps_eap_psk_nai_t nai_s;
  err_t ret;
  struct pbuf *reply;

  if (ps_eap_psk_parse_message1(eap_data, eap_data_len, &rand_s, &nai_s) != ps_eap__success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg1: Error while decoding msg1!\n"));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg1: Received EAP msg1\n\n"));
  MEMCPY(&lbp_data.eap_ctx.rand_s, &rand_s, sizeof(rand_s));
  MEMCPY(lbp_data.eap_ctx.nai_s.data, nai_s.data, nai_s.length);
  lbp_data.eap_ctx.nai_s.length = nai_s.length;

  reply = lbp_g3_msg_init(LBP_G3_MSG_JOINING, lbd_addr,
                          ps_eap_psk_len__message2);
  if (reply == NULL) {
    return ERR_MEM;
  }

  if (ps_eap_psk_create_message2(lbp_g3_msg_payload(reply), ps_eap_psk_len__message2, &lbp_data.eap_ctx,
                                 &nai_s, &lbp_data.nai_p,
                                 &lbp_data.eap_ctx.rand_s, &lbp_data.eap_ctx.rand_p,
                                 eap_id) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg1: Error while encoding msg2!\n"));
    pbuf_free(reply);
    return ERR_VAL;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg1: Sending EAP msg2\n"));
  ret = lbp_g3_output(netif, reply, origin);
  pbuf_free(reply);

  return ret;
}

static err_t
lbp_g3_handle_msg3(struct netif *netif, struct lowpan6_link_addr *origin, u8_t *lbd_addr,
                  u16_t eap_data_len, u8_t *eap_data, u8_t eap_id, u8_t *hdr)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  err_t ret;
  u8_t p_data_out[32];
  struct pbuf *reply;
  ps_eap_psk_rand_t rand_s;
  ps_eap_psk_p_result_t p_result = 0;
  u8_t *p_data_in = NULL;
  u16_t len, p_data_len, p_data_out_len = 0, expected_params_mask = 0;
  u32_t nonce;

  if (ps_eap_psk_parse_message3(eap_data, eap_data_len, &lbp_data.eap_ctx,
                                hdr, &rand_s, &nonce,
                                &p_result, &p_data_in, &p_data_len) != ps_eap__success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg3: Error while decoding msg3!\n"));
    return ERR_VAL;
  }
  lbp_data.nonce++;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg3: Received EAP msg3\n"));

  reply = lbp_g3_msg_init(LBP_G3_MSG_JOINING, lbd_addr,
                          ps_eap_psk_len__message4 + sizeof(p_data_out));
  if (reply == NULL)
    return ERR_MEM;

  if (ctx->is_rekeying) {
    expected_params_mask = lbp_g3_attr_flg(LBP_G3_ATTR_GMK);
  } else {
    expected_params_mask = LBP_G3_BOOTSTRAP_PARAMS_MASK;
  }

  if (p_result == ps_eap_psk_p_result__done_success) {
    /* Parse configuration params. */
    if (p_data_in[0] != LBP_G3_PCHANNEL_EXT_TYPE_PARAM) {
      p_result = ps_eap_psk_p_result__done_failure;
    } else {
      p_data_out[0] = LBP_G3_PCHANNEL_EXT_TYPE_PARAM;
      p_data_out_len = lbp_g3_handle_params(netif, p_data_in + 1, p_data_len - 1, p_data_out + 1,
                                            sizeof(p_data_out) - 1, &p_result, expected_params_mask) + 1;
    }
  } else {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg3: Expected PCHANNEL_RESULT_DONE_SUCCESS. EAP failed.\n"));
    p_result = ps_eap_psk_p_result__done_failure;
  }

  if ((len = ps_eap_psk_create_message4(lbp_g3_msg_payload(reply), lbp_g3_msg_payload_len(reply), &lbp_data.eap_ctx,
                                 &lbp_data.eap_ctx.rand_s,
                                 lbp_data.nonce, p_result, p_data_out,
                                 p_data_out_len, eap_id)) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg3: Error while encoding msg4!\n"));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_msg3: Sending EAP msg4\n"));
  reply->len = reply->tot_len = LBP_G3_HEADER_LEN + len;
  ret = lbp_g3_output(netif, reply, origin);
  pbuf_free(reply);

  return ret;
}

err_t
lbp_g3_leave(struct netif *netif)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *p;
  err_t ret;

  if (!ctx->connected || ctx->device_type != LOWPAN6_G3_DEVTYPE_DEVICE) {
    return ERR_USE;
  }

  p = lbp_g3_msg_init(LBP_G3_MSG_LBD_KICK, ctx->extended_mac_addr.addr, 0);
  if (p == NULL)
    return ERR_MEM;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_leave: Leaving network\n"));

  ret = lbp_g3_output(netif, p, &ctx->coord_short_address);
  pbuf_free(p);

  if (ret == ERR_OK) {
    lowpan6_g3_set_short_addr(netif, 0xFF, 0xFF);
    ctx->state = LBP_G3_STATE_IDLE;
    ctx->connected = 0;
    /* TODO: reset device */
  }

  return ret;
}

static err_t
lbp_g3_handle_decline(struct netif *netif, struct pbuf *p)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_decline: Received decline msg!\n"));
  ctx->state = LBP_G3_STATE_ERROR;

  return ERR_OK;
}

static err_t
lbp_g3_handle_lbs_kick(struct netif *netif, struct pbuf *pbuf)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_lbs_kick: Received LBS kick msg!\n"));
  lowpan6_g3_set_short_addr(netif, 0xFF, 0xFF);
  ctx->state = LBP_G3_STATE_IDLE;
  ctx->connected = 0;
  /* TODO: reset device */

  return ERR_OK;
}

static err_t
lbp_g3_handle_challenge(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u8_t *lbp_payload;
  u8_t *lbd_addr;
  u16_t payload_len;
  ps_eap_psk_t_subfield_t eap_t_subfield;
  ps_eap_code_t eap_code;
  u8_t eap_id;
  u16_t eap_data_len;
  u8_t *eap_data;
  err_t ret = ERR_OK;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Received LBP Challenge msg.\n"));

  lbp_payload = lbp_g3_msg_payload(p);
  payload_len = lbp_g3_msg_payload_len(p);
  lbd_addr = lbp_g3_msg_addr(p);

  if (ps_eap_psk_decode_header(lbp_payload, payload_len, &eap_code, &eap_id,
                                &eap_t_subfield, &eap_data, &eap_data_len) != ps_eap__success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Can't decode msg!\n"));
    ctx->state = LBP_G3_STATE_ERROR;
    return ERR_VAL;
  }

  if (eap_code != ps_eap_code__request) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Expected EAP Request msg, got: %x\n", eap_code));
    ctx->state = LBP_G3_STATE_ERROR;
    return ERR_VAL;
  }

  if (ctx->state == LBP_G3_STATE_JOINING) {
    if (eap_t_subfield == ps_eap_psk__message1) {
      ret = lbp_g3_handle_msg1(netif, origin, lbd_addr, eap_data_len, eap_data, eap_id);
      if (ret == ERR_OK)
        ctx->state = LBP_G3_STATE_WAIT_MSG3;
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Expected EAP-PSK msg1, got: %x\n", eap_t_subfield));
      ret = ERR_VAL;
    }
  } else if (ctx->state == LBP_G3_STATE_WAIT_MSG3) {
    if (eap_t_subfield == ps_eap_psk__message3) {
      ret = lbp_g3_handle_msg3(netif, origin, lbd_addr, eap_data_len, eap_data, eap_id, lbp_payload);
      if (ret == ERR_OK)
        ctx->state = LBP_G3_STATE_WAIT_ACCEPT;
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Expected EAP-PSK msg3, got: %x\n", eap_t_subfield));
      ret = ERR_VAL;
    }
  } else if (ctx->state == LBP_G3_STATE_IDLE) {
    if (eap_t_subfield == ps_eap_psk__message1) {
      /* Begin rekeying */
      ctx->is_rekeying = 1;
      ret = lbp_g3_handle_msg1(netif, origin, lbd_addr, eap_data_len, eap_data, eap_id);
      if (ret == ERR_OK)
        ctx->state = LBP_G3_STATE_WAIT_MSG3;
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Expected EAP-PSK msg1, got: %x\n", eap_t_subfield));
      ret = ERR_VAL;
    }
  } else {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_handle_challenge: Unexpected challenge message.\n"));
    ret = ERR_VAL;
  }

  if (ret != ERR_OK)
    ctx->state = LBP_G3_STATE_ERROR;

  return ret;
}

#if LBP_G3_PAN_COORDINATOR
static int
lbp_g3_lbs_dev_find(u8_t *ext_addr)
{
  int i;

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if (!memcmp(ext_addr, device_table[i].ext_addr, 8) && device_table[i].dev_state != LBP_G3_LBS_DEV_EMPTY) {
      return i;
    }
  }

  return -1;
}

/**
 * Allocates a new device in the device table
 * and allocates a new future short address.
 */
static int
lbp_g3_lbs_dev_alloc(struct netif *netif, const u8_t *ext_addr)
{
  int i;

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if (device_table[i].dev_state == LBP_G3_LBS_DEV_EMPTY) {
      device_table[i].netif = netif;
      device_table[i].dev_state = LBP_G3_LBS_DEV_JOINING;
      device_table[i].eap_state = LBP_G3_EAP_STATE_WAIT_MSG2;
      /* TODO: Temporary policy to easily conform to G3 GR2 tests */
      device_table[i].short_addr = lwip_htons(0x00ED + i);
      MEMCPY(device_table[i].ext_addr, ext_addr, 8);
      return i;
    }
  }

  return -1;
}

static err_t
lbp_g3_lbs_dev_free(int idx)
{
  if (idx >= LBP_G3_PAN_DEVINFO_TABLE_SIZE) {
    return ERR_ARG;
  }

  device_table[idx].dev_state = LBP_G3_LBS_DEV_EMPTY;

  return ERR_OK;
}

/**
 * Function allows to manually register a device inside a PAN.
 * This is done for testing purposes.
 */
err_t
lbp_g3_lbs_dev_add(struct netif *netif, u16_t short_addr, const u8_t *ext_addr, int idx)
{
  if (idx > LBP_G3_PAN_DEVINFO_TABLE_SIZE) {
    return ERR_VAL;
  }

  device_table[idx].dev_state = LBP_G3_LBS_DEV_ACCEPTED;
  device_table[idx].short_addr = lwip_htons(short_addr);
  device_table[idx].netif = netif;
  MEMCPY(device_table[idx].ext_addr, ext_addr, 8);

  return ERR_OK;
}

err_t
lbp_g3_lbs_network_start(struct netif *netif)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  if (g3_network_start(ctx->pan_id) < 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_network_start: Can't start network\n"));
    return ERR_VAL;
  }

  ctx->state = LBP_G3_STATE_IDLE;
  ctx->connected = 1;
  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_network_start: PAN %04X started\n", ctx->pan_id));

  return ERR_OK;
}

static err_t
lbp_g3_lbs_kick_send(struct netif *netif, const u8_t *link_addr, struct lowpan6_link_addr *dest)
{
  struct pbuf *p;
  err_t ret;

  p = lbp_g3_msg_init(LBP_G3_MSG_LBS_KICK, link_addr, 0);
  if (p == NULL) {
    return ERR_MEM;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_kick_send: Kicking device: %02X%02X.\n",
                          dest->addr[0], dest->addr[1]));
  ret = lbp_g3_output(netif, p, dest);
  pbuf_free(p);

  return ret;
}

static int
lbp_g3_lbs_is_blacklisted(const u8_t *addr)
{
  unsigned i;

  for (i = 0; i < LBP_G3_PAN_BLACKLIST_SIZE; i++) {
    if (blacklist_table[i].is_valid && !memcmp(addr, blacklist_table[i].ext_addr, 8)) {
      return 1;
    }
  }

  return 0;
}

static err_t
lbp_g3_lbs_decline_send(struct netif *netif, const u8_t *lbd_addr, struct lowpan6_link_addr *dest)
{
  struct pbuf *reply;
  err_t ret;

  reply = lbp_g3_msg_init(LBP_G3_MSG_DECLINE, lbd_addr, ps_eap_psk_len__status);
  if (reply == NULL) {
    return ERR_MEM;
  }

  /* Encode EAP msg failure */
  if (ps_eap_psk_create_eap_failure(lbp_g3_msg_payload(reply),
                                    ps_eap_psk_len__status,
                                    lbp_data.eap_id) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_msg_decline: Can't encode EAP failure!\n"));
    ret = ERR_VAL;
  } else {
    lbp_data.eap_id++;
    ret = lbp_g3_output(netif, reply, dest);
  }
  pbuf_free(reply);

  return ret;
}


static err_t
lbp_g3_lbs_gen_msg1(struct netif *netif, u8_t *lbd_addr, struct lowpan6_link_addr *dst)
{
  struct pbuf *reply;
  err_t ret;

  reply = lbp_g3_msg_init(LBP_G3_MSG_CHALLENGE, lbd_addr,
                          ps_eap_psk_len__message1);
  if (reply == NULL) {
    return ERR_MEM;
  }

  /* TODO: since we are starting a new session, we should generate a new RAND_S */
  if (ps_eap_psk_create_message1(lbp_g3_msg_payload(reply), ps_eap_psk_len__message1,
                                 &lbp_data.eap_ctx.rand_s,
                                 &lbp_data.eap_ctx.nai_s,
                                 lbp_data.eap_id) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_req_msg1: Error while encoding msg1!\n"));
    pbuf_free(reply);
    return ERR_VAL;
  }

  lbp_data.eap_id++;
  ret = lbp_g3_output(netif, reply, dst);

  pbuf_free(reply);
  return ret;
}

/**
 * Try to start a PAN network. A device first
 * starts scanning to check if there are any networks
 * in the POS. If not, it will start a new network.
 * Values, which needs to be set outside this function:
 * - extended address (is automatically fetched from MAC during lowpan6_if_init)
 * - GMK,
 * - RAND_S,
 * @param scan_duration Duration of the discovery phase in seconds. If 0,
 *                      then network is started without discovery phase.
 * @param pan_id PAN ID, which should be set in machine byte order.
 * @param short_address 16-bit short address in machine byte order.
 */
err_t
lbp_g3_lbs_pan_start(struct netif *netif, u8_t scan_duration, u16_t pan_id, u16_t short_address)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  lowpan6_g3_set_device_type(LOWPAN6_G3_DEVTYPE_COORD);

  if (lowpan6_g3_set_pan_id(netif, pan_id) != ERR_OK) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_join: Can't set PAN ID\n"));
    return ERR_VAL;
  }

  if (lowpan6_g3_set_short_addr(netif, short_address >> 8, short_address & 0xFF) != ERR_OK) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_join: Can't set the short address\n"));
    return ERR_VAL;
  }

  if (scan_duration > 0) {
    if (lbp_g3_discovery(netif, scan_duration) < 0) {
      return ERR_VAL;
    }
    ctx->state = LBP_G3_STATE_SCANNING;
    return ERR_OK;
  } else {
    return lbp_g3_lbs_network_start(netif);
  }
}

/*
 * This function is used by the LBS in order to parse
 * parameter results sent by the peer. It returns ERR_OK,
 * if all the parameters received are SUCCESS.
 */
static err_t
lbp_g3_lbs_handle_param_result(u8_t *buf, u16_t buf_len)
{
  u8_t pos = 0;
  u8_t attr_id, attr_len;
  u8_t *attr_val;
  err_t ret = ERR_OK;

  if (buf_len == 0) {
    return ERR_VAL;
  }

  while (pos < buf_len) {
    pos += lbp_g3_param_decode(buf + pos, &attr_id, &attr_len, &attr_val);
    if (attr_id != LBP_G3_ATTR_PARAM_RESULT) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_handle_param_result: LBS expects only parameter-results!\n"));
      return ERR_VAL;
    }

    if (attr_val[1] != LBP_G3_PARAM_SUCCESS) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_handle_param_result: Received error (%02X) with parameter: %02X!\n",
                              attr_val[1], attr_val[0]));
      ret = ERR_VAL;
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_handle_param_result: Received parameter SUCCESS: %02X!\n",
                              attr_val[1]));
    }
  }

  return ret;
}

err_t lbp_g3_lbs_rekey(struct netif *netif, u8_t gmk_id)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr dst;
  unsigned i;

  if (gmk_id > 1 || !ctx->gmk[gmk_id].is_set || gmk_id == ctx->active_key_index) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_rekey: Invalid GMK id!\n"));
    return ERR_VAL;
  }

  ctx->rekey_gmk = gmk_id;
  ctx->is_rekeying = 1;

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if (device_table[i].dev_state == LBP_G3_LBS_DEV_ACCEPTED) {
      lowpan6_link_addr_set_u16(&dst, device_table[i].short_addr);
      if (lbp_g3_lbs_gen_msg1(netif, device_table[i].ext_addr, &dst) < 0) {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_rekey: Rekeying initiation failed!\n"));
        return ERR_VAL;
      }
      device_table[i].dev_state = LBP_G3_LBS_DEV_REKEYING;
      device_table[i].eap_state = LBP_G3_EAP_STATE_WAIT_MSG2;
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_rekey: Starting rekeying device: %04X.\n",
                              lwip_ntohs(device_table[i].short_addr)));
    }
  }

  return ERR_OK;
}

static err_t
lbp_g3_lbs_handle_lbd_kick(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  unsigned i;
  u8_t *lbd_addr;

  lbd_addr = lbp_g3_msg_addr(p);

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if (device_table[i].dev_state != LBP_G3_LBS_DEV_EMPTY &&
        !memcmp(lbd_addr, device_table[i].ext_addr, 8)) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_lbd_kick: Removing device short: %04X, extended: %016llX \n",
                          lwip_ntohs(lowpan6_link_addr_to_u16(origin)), lowpan6_link_addr_to_u64(lbd_addr)));
      return lbp_g3_lbs_dev_free(i);
    }
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_lbd_kick: Unknown device short: %04X, extended: %016llX!\n",
                          lwip_ntohs(lowpan6_link_addr_to_u16(origin)), lowpan6_link_addr_to_u64(lbd_addr)));

  return ERR_VAL;
}

/**
 * Kick a device from the network. It causes removal of the device
 * from the device table and freeing its short address. It also
 * sends a LBP_KICK message to the given device.
 * @param addr Address of a device to be kicked. Either short or extended.
 */
err_t
lbp_g3_lbs_kick(struct netif *netif, const struct lowpan6_link_addr *addr)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct pbuf *p;
  unsigned i;
  struct lowpan6_link_addr dst;
  err_t ret;

  if (ctx->device_type != LOWPAN6_G3_DEVTYPE_COORD) {
    return ERR_USE;
  }

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if ((addr->addr_len == 2 && device_table[i].short_addr == lowpan6_link_addr_to_u16(addr)) ||
        (addr->addr_len == 8 && !memcmp(device_table[i].ext_addr, addr->addr, 8))) {
      p = lbp_g3_msg_init(LBP_G3_MSG_LBS_KICK, device_table[i].ext_addr, 0);
      if (p == NULL) {
        return ERR_MEM;
      }

      lowpan6_link_addr_set_u16(&dst, device_table[i].short_addr);
      ret = lbp_g3_output(netif, p, &dst);
      pbuf_free(p);

      if (ret != ERR_OK) {
        return ret;
      }

      lbp_g3_lbs_dev_free(i);

      return ERR_OK;
    }
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_kick: Can't find device.\n"));

  return ERR_VAL;
}


/* 
 * This function is called every time, an authentication
 * phase of rekeying procedure finishes. If the phase
 * is already finished for all the devices, it sends
 * the ACCEPTED msg containing GMK-Activation parameter
 * to all the rekeying peers, which eventually finishes
 * the bootstrapping procedure.
 */
static err_t
lbp_g3_lbs_handle_rekey_update(struct netif *netif)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr dest;
  struct pbuf *p;
  unsigned i;

  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    /* Don't proceed, if any of the rekeying devices is not yet
     * authenticated
     */
    if (device_table[i].dev_state == LBP_G3_LBS_DEV_REKEYING &&
        device_table[i].eap_state != LBP_G3_EAP_STATE_IDLE) {
      return ERR_OK;
    }
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_handle_rekey_update: Authentication phase of rekeying finished.\n"));

  /* Once all devices are authenticated, we send them GMK-activation msg */
  for (i = 0; i < LBP_G3_PAN_DEVINFO_TABLE_SIZE; i++) {
    if (device_table[i].dev_state == LBP_G3_LBS_DEV_REKEYING) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lbs_handle_rekey_update: Sending GMK-activation\n"));
      p = lbp_g3_msg_init(LBP_G3_MSG_ACCEPTED, device_table[i].ext_addr, 3);
      if (p == NULL) {
        return ERR_MEM;
      }
      lbp_g3_param_encode(lbp_g3_msg_payload(p), LBP_G3_ATTR_GMK_ACTIVATION,
                          LBP_G3_LIB_PSI, 1, &ctx->rekey_gmk);
      lowpan6_link_addr_set_u16(&dest, device_table[i].short_addr);
      lbp_g3_output(netif, p, &dest);
      device_table[i].dev_state = LBP_G3_LBS_DEV_ACCEPTED;
      pbuf_free(p);
    }
  }

  ctx->is_rekeying = 0;
  ctx->active_key_index = ctx->rekey_gmk;

  return ERR_OK;
}

err_t
lbp_g3_lbs_blacklist_add(const u8_t *addr)
{
  unsigned i;

  for (i = 0; i < LBP_G3_PAN_BLACKLIST_SIZE; i++) {
    if (!blacklist_table[i].is_valid) {
      blacklist_table[i].is_valid = 1;
      MEMCPY(blacklist_table[i].ext_addr, addr, 8);

      return ERR_OK;
    }
  }

  return ERR_BUF;
}


static err_t
lbp_g3_lbs_handle_msg2(struct netif *netif, struct lowpan6_link_addr *origin, struct lbp_g3_lbs_devinfo *dev, u16_t eap_data_len, u8_t *eap_data)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u16_t p_data_len, len;
  u8_t val[17], p_data[32];
  struct pbuf *reply;
  ps_eap_psk_rand_t rand_s, rand_p;
  err_t ret;
  u8_t gmk_id;

  if (ps_eap_psk_parse_message2(eap_data, eap_data_len, &lbp_data.eap_ctx, &lbp_data.eap_ctx.nai_s,
                                 &rand_s, &rand_p, ctx->bandplan) != ps_eap__success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg2: Can't decode msg2\n"));
    return ERR_VAL;
  }

  if (memcmp(rand_s.data, lbp_data.eap_ctx.rand_s.data, PS_EAP_PSK_RAND_LENGTH) != 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg2: Received wrong rand_s value\n"));
    return ERR_VAL;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg2: Received correct EAP msg2\n"));
  reply = lbp_g3_msg_init(LBP_G3_MSG_CHALLENGE, dev->ext_addr,
                          ps_eap_psk_len__message3 + sizeof(p_data));
  if (reply == NULL)
    return ERR_MEM;

  /* Protected channel ESC byte */
  p_data[0] = LBP_G3_PCHANNEL_EXT_TYPE_PARAM;
  p_data_len = 1;
  /* Encode parameters sent using the protected channel */
  if (dev->dev_state == LBP_G3_LBS_DEV_REKEYING) {
    val[0] = ctx->rekey_gmk;
    MEMCPY(val + 1, ctx->gmk[ctx->rekey_gmk].key, LOWPAN6_G3_GMK_LEN);
    p_data_len += lbp_g3_param_encode(p_data + p_data_len, LBP_G3_ATTR_GMK, LBP_G3_LIB_PSI,
                                      LOWPAN6_G3_GMK_LEN + 1, val);
  } else {
    p_data_len += lbp_g3_param_encode(p_data + p_data_len, LBP_G3_ATTR_SHORT_ADDR, LBP_G3_LIB_DSI,
                                      sizeof(dev->short_addr), (u8_t *)&dev->short_addr);

    /* If the network is rekeying and a device tries to join a network, give it
     * a new GMK, to avoid rekeying it again.
     */
    if (ctx->is_rekeying) {
      gmk_id = ctx->rekey_gmk;
    } else {
      gmk_id = ctx->active_key_index;
    }

    val[0] = gmk_id;
    MEMCPY(val + 1, ctx->gmk[gmk_id].key, LOWPAN6_G3_GMK_LEN);
    p_data_len += lbp_g3_param_encode(p_data + p_data_len, LBP_G3_ATTR_GMK, LBP_G3_LIB_PSI, LOWPAN6_G3_GMK_LEN + 1, val);
    p_data_len += lbp_g3_param_encode(p_data + p_data_len, LBP_G3_ATTR_GMK_ACTIVATION, LBP_G3_LIB_PSI, sizeof(gmk_id), &gmk_id);
  }

  /* TODO: each device should have a separate TEK */
  ps_eap_psk_tek_init(&lbp_data.eap_ctx, &rand_p);

  if ((len = ps_eap_psk_create_message3(lbp_g3_msg_payload(reply), lbp_g3_msg_payload_len(reply), &lbp_data.eap_ctx, &rand_s, &rand_p,
                                        &lbp_data.eap_ctx.nai_s, lbp_data.nonce, ps_eap_psk_p_result__done_success,
                                        p_data, p_data_len, lbp_data.eap_id)) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg2: Error during msg3 encoding!\n"));
    pbuf_free(reply);
    return ERR_VAL;
  }

  lbp_data.eap_id++;
  reply->len = reply->tot_len = LBP_G3_HEADER_LEN + len;
  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg2: Sending msg3.\n"));
  ret = lbp_g3_output(netif, reply, origin);

  pbuf_free(reply);

  return ret;
}

static err_t
lbp_g3_lbs_handle_msg4(struct netif *netif, struct lowpan6_link_addr *origin, u8_t *lbd_addr, u16_t eap_data_len, u8_t *eap_data, u8_t *hdr)
{
  ps_eap_psk_rand_t rand_s;
  struct pbuf *reply;
  u32_t nonce;
  ps_eap_psk_p_result_t p_result;
  u8_t *p_data = NULL;
  u16_t p_data_len = 0;
  err_t ret = ERR_OK;

  if (ps_eap_psk_parse_message4(eap_data, eap_data_len, &lbp_data.eap_ctx, hdr,
                                &rand_s, &nonce, &p_result, &p_data, &p_data_len) != ps_eap__success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg4: Error during msg4 decoding!\n"));
    return ERR_VAL;
  }

  lbp_data.nonce++;

  /* TODO: Each session should have a different RAND_S */
  if (memcmp(rand_s.data, lbp_data.eap_ctx.rand_s.data, PS_EAP_PSK_RAND_LENGTH) != 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg4: Received wrong RAND_S value!\n"));
    return ERR_VAL;
  }

  if (p_result != ps_eap_psk_p_result__done_success) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg4: Expected PCHANNEL RESULT DONE_SUCCESS!\n"));
    return ERR_VAL;
  }

  reply = lbp_g3_msg_init(LBP_G3_MSG_ACCEPTED, lbd_addr, ps_eap_psk_len__status);
  if (reply == NULL) {
    return ERR_MEM;
  }

  if (ps_eap_psk_create_eap_success(lbp_g3_msg_payload(reply), ps_eap_psk_len__status, lbp_data.eap_id) == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_msg4: Error during EAP Success encoding!\n"));
    return ERR_VAL;
  }

  lbp_data.eap_id++;
  ret = lbp_g3_output(netif, reply, origin);
  pbuf_free(reply);

  return ret;
}

static err_t
lbp_g3_lbs_handle_joining(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  u16_t payload_len, eap_data_len = 0;
  u8_t *lbd_addr, *lbp_payload, *eap_data = NULL;
  ps_eap_code_t eap_code;
  ps_eap_psk_t_subfield_t eap_subfield;
  u8_t eap_id;
  int dev_idx;

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Received LBP Joining msg.\n"));

  lbp_payload = lbp_g3_msg_payload(p);
  payload_len = lbp_g3_msg_payload_len(p);
  lbd_addr = lbp_g3_msg_addr(p);

  if (lbp_g3_lbs_is_blacklisted(lbd_addr)) {
    return lbp_g3_lbs_decline_send(netif, lbd_addr, origin);
  }

  /* Check if we know this device */
  if ((dev_idx = lbp_g3_lbs_dev_find(lbd_addr)) == -1) {
    /* Start JOIN procedure for this device, if this is a correct LBP message */
    if (payload_len != 0 || (dev_idx = lbp_g3_lbs_dev_alloc(netif, lbd_addr)) < 0) {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Failed to start JOIN procedure\n"));
      return lbp_g3_lbs_decline_send(netif, lbd_addr, origin);
    }
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: New device allocated with short_addr: %04X extended: %016llX\n",
                            lwip_ntohs(device_table[dev_idx].short_addr), lowpan6_link_addr_to_u64(lbd_addr)));
    device_table[dev_idx].join_time = sys_now();
    device_table[dev_idx].tmp_link_addr = *origin;
    /* Start EAP authentication */
    return lbp_g3_lbs_gen_msg1(netif, lbd_addr, origin);
  }

  /* In all the other cases we expect payload */
  if (payload_len == 0) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Message has no payload!\n"));
    goto err;
  }

  switch (device_table[dev_idx].dev_state) {
    case LBP_G3_LBS_DEV_JOINING:
    case LBP_G3_LBS_DEV_REKEYING:
      /* We expect EAP */
      if (ps_eap_psk_decode_header(lbp_payload, payload_len, &eap_code, &eap_id, &eap_subfield,
                                   &eap_data, &eap_data_len) != ps_eap__success) {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Can't decode EAP msg!\n"));
        goto err;
      }

      if (eap_code != ps_eap_code__response) {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Expecting eap msg response\n"));
        goto err;
      }

      if (device_table[dev_idx].eap_state == LBP_G3_EAP_STATE_WAIT_MSG2) {
        if (eap_subfield != ps_eap_psk__message2) {
          LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Unexpected EAP msg type. Expecting msg2\n"));
          goto err;
        }
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Got EAP msg2\n"));

        if (lbp_g3_lbs_handle_msg2(netif, origin, &device_table[dev_idx], eap_data_len, eap_data) < 0) {
          goto err;
        }
        device_table[dev_idx].eap_state = LBP_G3_EAP_STATE_WAIT_MSG4;

        return ERR_OK;
      } else if (device_table[dev_idx].eap_state == LBP_G3_EAP_STATE_WAIT_MSG4) {
        if (eap_subfield != ps_eap_psk__message4) {
          LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Unexpected EAP msg type. Expecting msg4\n"));
          goto err;
        }

        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Got EAP msg4\n"));
        if (lbp_g3_lbs_handle_msg4(netif, origin, lbd_addr, eap_data_len, eap_data, lbp_payload) < 0) {
          goto err;
        }

        device_table[dev_idx].eap_state = LBP_G3_EAP_STATE_IDLE;
        /* It finishes the bootstrapping procedure */
        if (device_table[dev_idx].dev_state == LBP_G3_LBS_DEV_JOINING)
          device_table[dev_idx].dev_state = LBP_G3_LBS_DEV_ACCEPTED;

        /*
         * In case of rekeying, we have to send ACCEPTED msg
         * containing the GMK-activation parameter, once every device
         * has finished authentication phase.
         */
        if (ctx->is_rekeying) {
          lbp_g3_lbs_handle_rekey_update(netif);
        }

        return ERR_OK;
      } else {
        goto err;
      }
    case LBP_G3_LBS_DEV_ACCEPTED:
      /* Check if the msg contains parameter results */
      if (*lbp_payload & 0x1) {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Handle parameter result\n"));
        if (lbp_g3_lbs_handle_param_result(lbp_payload, payload_len) < 0) {
          goto err;
        }
      } else {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_lbs_handle_joining: Expected parameter result!\n"));
        goto err;
      }
      return ERR_OK;
  }

err:
  lbp_g3_lbs_dev_free(dev_idx);
  if (device_table[dev_idx].dev_state == LBP_G3_LBS_DEV_JOINING) {
    return lbp_g3_lbs_decline_send(netif, lbd_addr, origin);
  } else {
    return lbp_g3_lbs_kick_send(netif, lbd_addr, origin);
  }
}

#endif /* LBP_G3_PAN_COORDINATOR */


/**
 * Function called by a lower layer once the
 * scanning is completed. If the receiver is a PAN device,
 * this function initiates JOIN procedure, otherwise,
 * it starts a new PAN.
 */
void lbp_g3_discovery_confirm(struct netif *netif, u8_t status)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  unsigned i;
  int best_idx;

  if (ctx->state != LBP_G3_STATE_SCANNING) {
    return;
  }

  LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_discovery_confirm: MLME-SCAN finished with status: %02X\n", status));

#if LBP_G3_DEBUG
  printf("%-4s %-4s %-4s %s\n"
      "-----------------------\n",
      "PAN", "LBA", "LQI", "RC_COORD");
  for (i = 0; i < LBP_G3_SCAN_TABLE_SIZE; i++) {
    if (!scan_table[i].valid) {
      break;
    }
    printf("%04X %04X %-4d %04X\n", scan_table[i].pan_id, scan_table[i].lba, scan_table[i].lqi, scan_table[i].rc_coord);
  }
#endif

  /*
   * If the device is already connected, and the discovery was triggered
   * for maintenance purpose, return to idle.
   */
  if (ctx->connected) {
    ctx->state = LBP_G3_STATE_IDLE;
    return;
  }

  if (ctx->device_type == LOWPAN6_G3_DEVTYPE_DEVICE) {
    /* Choose the best LBA and start joining */
    if (!scan_table[0].valid) {
      ctx->state = LBP_G3_STATE_IDLE; /* Scan finished */
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_discovery_confirm: No devices found!\n"));
      return;
    }

    best_idx = 0;
    for (i = 1; i < LBP_G3_SCAN_TABLE_SIZE; i++) {
      if (!scan_table[i].valid)
        break;
      if (scan_table[i].rc_coord < scan_table[best_idx].rc_coord ||
         (scan_table[i].rc_coord == scan_table[best_idx].rc_coord && scan_table[i].lqi > scan_table[best_idx].lqi)) {
        best_idx = i;
      }
    }
    lbp_g3_join(netif, scan_table[best_idx].pan_id, scan_table[best_idx].lba);
  }
#if LBP_G3_PAN_COORDINATOR
  else if (ctx->device_type == LOWPAN6_G3_DEVTYPE_COORD) {
    if (!scan_table[0].valid) {
      /* If there is no PAN operating in the area, start a new one */
      lbp_g3_lbs_network_start(netif);
    } else {
      /* TODO: inform upper layer using a callback? */
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_discovery_confirm: Don't start a network. As there is already a PAN.\n"));
    }
  }
#endif
  /* TODO: clear scan table */
}

/* Timer function called every second by lowpan6_g3_tmr() */
void
lbp_g3_tmr(void *arg)
{
  struct netif *netif = (struct netif *) arg;
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;

  if (ctx->device_type == LOWPAN6_G3_DEVTYPE_DEVICE) {
    if (ctx->state != LBP_G3_STATE_IDLE && ctx->state != LBP_G3_STATE_ERROR
        && !ctx->connected) {
      if (--ctx->join_timeout == 0) {
        ctx->state = LBP_G3_STATE_ERROR;
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_tmr: Bootstrapping failed due to timeout.\n"));
      }
    }
  }
#if LBP_G3_PAN_COORDINATOR
  else if (ctx->device_type == LOWPAN6_G3_DEVTYPE_COORD) {
    u32_t now = sys_now();
    unsigned i;

    for (i = 0; i < LBP_G3_SCAN_TABLE_SIZE; i++) {
      if (device_table[i].dev_state == LBP_G3_LBS_DEV_JOINING
          && now - device_table[i].join_time > ctx->max_join_wait_time * 1000) {
        lbp_g3_lbs_decline_send(device_table[i].netif, device_table[i].ext_addr, &device_table[i].tmp_link_addr);
        lbp_g3_lbs_dev_free(i);
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_tmr: Bootstrapping of a device: %04X failed due to timeout.\n",
                                lwip_ntohs(device_table[i].short_addr)));
        /* TODO: temporary blacklist a device? */
      }
    }
  }
#endif /* LBP_G3_PAN_COORDINATOR */
}

err_t
lbp_g3_lba_route_msg(struct netif *netif, struct pbuf *p, struct lowpan6_link_addr *origin)
{
  lowpan6_g3_data_t *ctx = (lowpan6_g3_data_t *) netif->state;
  struct lowpan6_link_addr lbd_dest;
  u8_t msg_type = lbp_g3_msg_code(p);
  u8_t *lbd_addr = lbp_g3_msg_addr(p);

  lbd_dest.addr_len = 8;
  MEMCPY(lbd_dest.addr, lbd_addr, 8);

  if (lowpan6_link_addr_cmp(origin, &ctx->coord_short_address) &&
      (msg_type == LBP_G3_MSG_CHALLENGE || msg_type == LBP_G3_MSG_ACCEPTED ||
       msg_type == LBP_G3_MSG_DECLINE || msg_type == LBP_G3_MSG_LBS_KICK)) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lba_route_msg: Received a msg from LBS. Forwarding to LBD.\n"));

    return lbp_g3_output(netif, p, &lbd_dest);
  } else if (lowpan6_link_addr_cmp(&lbd_dest, origin) &&
             (msg_type == LBP_G3_MSG_JOINING || msg_type == LBP_G3_MSG_LBD_KICK)) {
    LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_lba_route_msg: Received a msg from LBD. Forwarding to LBS.\n"));

    return lbp_g3_output(netif, p, &ctx->coord_short_address);
  }

  return ERR_VAL;
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
      if (ctx->role_of_device == LOWPAN6_G3_ROLE_LBA) {
        ret = lbp_g3_lba_route_msg(netif, p, origin);
      } else {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: Frame not for us: %016llX. Discarding.\n", lowpan6_link_addr_to_u64(lbd_addr)));
        ret = ERR_VAL;
      }
    } else {
      /* During bootstrapping we may only accept frames from our LBA.
       * When we are connected - only from our LBS.
       */
      if ((!ctx->connected && lowpan6_link_addr_cmp(origin, &ctx->lba_address)) ||
          (ctx->connected && lowpan6_link_addr_cmp(origin, &ctx->coord_short_address))) {
        if (msg_code == LBP_G3_MSG_CHALLENGE) {
          ret = lbp_g3_handle_challenge(netif, p, origin);
        } else if (msg_code == LBP_G3_MSG_ACCEPTED) {
          ret = lbp_g3_handle_accepted(netif, p, origin);
        } else if (msg_code == LBP_G3_MSG_DECLINE) {
          ret = lbp_g3_handle_decline(netif, p);
        } else if (msg_code == LBP_G3_MSG_LBS_KICK) {
          ret = lbp_g3_handle_lbs_kick(netif, p);
        } else {
          LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: LBD received an unexpected msg_type: %02X!\n", msg_code));
          ret = ERR_VAL;
        }
      } else {
        LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: Wrong frame's originator!\n"));
        ret = ERR_VAL;
      }
    }
  }
#if LBP_G3_PAN_COORDINATOR
  else if (ctx->device_type == LOWPAN6_G3_DEVTYPE_COORD) {
    if (msg_code == LBP_G3_MSG_JOINING) {
      ret = lbp_g3_lbs_handle_joining(netif, p, origin);
    } else if (msg_code == LBP_G3_MSG_LBD_KICK) {
      ret = lbp_g3_lbs_handle_lbd_kick(netif, p, origin);
    } else {
      LWIP_DEBUGF(LBP_G3_DEBUG, ("lbp_g3_input: PAN coordinator received an unexpected msg_type: %02X!\n", msg_code));
      ret = ERR_VAL;
    }
  }
#endif /* LBP_G3_PAN_COORDINATOR */

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

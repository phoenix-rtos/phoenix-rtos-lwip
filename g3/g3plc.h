/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer opts
 *
 * Copyright 2025 Phoenix Systems
 *
 * %LICENSE%
 */

#ifndef LWIP_HDR_G3PLC_H
#define LWIP_HDR_G3PLC_H
/*
 * This file contains declarations of functions
 * used by lwip to communicate with MAC.
 */

struct g3plc_scan_entry {
  uint16_t pan_id;
  uint16_t lba;
  uint16_t lqi;
  uint16_t rc_coord;
  uint8_t valid;
};

/* MAC neighbour table entry */
struct g3plc_mac_nb_entry {
    uint16_t short_address;               /* 2 octets (16-bit) */
    uint8_t tone_map[3];                  /* 3 octets (24-bit) */
    uint8_t active_tones;
    uint8_t tx_coef[6];                   /* number of gain steps requested for the tones */
    uint8_t tx_res;                       /* tx gain corresponding to one step 0: 6dB, 1: 3dB */
    uint8_t tx_gain;                      /* tx gain to be used */
    uint8_t mod_type;                     /* ps_g3_phy_mod_type_t */
    uint8_t mod_scheme;                   /* ps_g3_phy_mod_scheme_t */
    uint8_t phase_diff;                   /* ps_g3_phy_phase_diff_t */
    uint8_t lqi;                          /* Reverse LQI */
    uint16_t tmr_valid_time;              /* TMRValidTime */
};

/* Simplified version of ps_g3_mcps_data_indication,
 * containing information needed by ADP layer */
struct g3plc_mcps_indication {
    uint8_t msdu_linkquality;      /* (forward) LQI value measured during reception of the message */
    uint8_t security_level;        /* security level of the received message 0x00: unencrypted, 0x05: encrypted */
    uint8_t modulation;            /* extension: modulation scheme and type */
    uint8_t active_tones;
};

typedef struct {
    struct lowpan6_link_addr src;
    struct lowpan6_link_addr dst;
    struct g3plc_mcps_indication indication;
    uint16_t len;
    u8_t payload[];
}  __attribute__((__packed__)) g3plc_packet_t;

enum g3plc_mac_status {
    g3plc_mac_status_success = 0x00,
    g3plc_mac_status_no_ack = 0xe9,
    g3plc_mac_status_transaction_expires = 0xf0
};


int g3plc_output(struct netif *netif, struct pbuf *p, const struct lowpan6_link_addr *src, const struct lowpan6_link_addr *dst,
	uint8_t security_level, uint16_t pan_id, uint8_t qos, uint8_t key_index);
int g3plc_mac_nb_table_lookup_sync(struct lowpan6_link_addr *addr, struct g3plc_mac_nb_entry *entry);
int g3plc_scan_request(struct g3plc_scan_entry *buf, int size, uint16_t duration);
int g3plc_mac_reset(void);
int g3plc_set_pan_id(uint16_t pan_id);
int g3plc_get_hwaddr(uint8_t *hwaddr);
int g3plc_set_hwaddr(const uint8_t *hwaddr);
int g3plc_set_rc_coord(uint16_t rc_coord);
int g3plc_set_shortaddr(uint16_t short_addr);
int g3plc_set_gmk(const uint8_t *gmk, uint8_t gmk_id);
int g3plc_network_start(uint16_t pan_id);
int g3_nb_table_set(uint16_t addr, uint8_t lqi, uint8_t ind);

#endif

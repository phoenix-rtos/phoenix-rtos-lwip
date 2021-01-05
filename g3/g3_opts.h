/*
 * Phoenix-RTOS --- networking stack
 *
 * G3-PLC Adaptation Layer opts
 *
 * Copyright 2021 Phoenix Systems
 * Author: Maciej Purski
 *
 * %LICENSE%
 */

#ifndef LWIP_HDR_G3_OPTS_H
#define LWIP_HDR_G3_OPTS_H

#include "lwip/opt.h"

/** LWIP_6LOWPAN_NUM_CONTEXTS: define the number of compression
 * contexts per netif type
 */
#ifndef LWIP_6LOWPAN_NUM_CONTEXTS
#define LWIP_6LOWPAN_NUM_CONTEXTS        10
#endif

/** LWIP_6LOWPAN_INFER_SHORT_ADDRESS: set this to 0 to disable creating
 * short addresses for matching addresses (debug only)
 */
#ifndef LWIP_6LOWPAN_INFER_SHORT_ADDRESS
#define LWIP_6LOWPAN_INFER_SHORT_ADDRESS 1
#endif

/** LWIP_6LOWPAN_IPHC: set this to 0 to disable IP header compression as per
 * RFC 6282 (which is mandatory for BLE)
 */
#ifndef LWIP_6LOWPAN_IPHC
#define LWIP_6LOWPAN_IPHC                1
#endif

/** Debug level for 6LoWPAN in general */
#ifndef LWIP_LOWPAN6_DEBUG
#define LWIP_LOWPAN6_DEBUG               LWIP_DBG_ON
#endif

/** LWIP_LOWPAN6_IP_COMPRESSED_DEBUG: enable compressed IP frame
 * output debugging
 */
#ifndef LWIP_LOWPAN6_IP_COMPRESSED_DEBUG
#define LWIP_LOWPAN6_IP_COMPRESSED_DEBUG      LWIP_DBG_OFF
#endif

/** LWIP_LOWPAN6_DECOMPRESSION_DEBUG: enable decompression debug output
 */
#ifndef LWIP_LOWPAN6_DECOMPRESSION_DEBUG
#define LWIP_LOWPAN6_DECOMPRESSION_DEBUG      LWIP_DBG_OFF
#endif

/** LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG: enable decompressed IP frame
 * output debugging */
#ifndef LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG
#define LWIP_RFC7668_IP_UNCOMPRESSED_DEBUG    LWIP_DBG_OFF
#endif

#ifndef LWIP_G3_PLC
#define LWIP_G3_PLC 1
#endif

/* Protocol tables sizes */
#ifndef LOWPAN6_G3_DEST_ADDRESS_SET_SIZE
#define LOWPAN6_G3_DEST_ADDRESS_SET_SIZE       4
#endif

#ifndef LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE
#define LOWPAN6_G3_BROADCAST_LOG_TABLE_SIZE    64
#endif

#ifndef LOWPAN6_G3_ROUTING_TABLE_SIZE
#define LOWPAN6_G3_ROUTING_TABLE_SIZE          64
#endif

#ifndef LOWPAN6_G3_GROUP_TABLE_SIZE
#define LOWPAN6_G3_GROUP_TABLE_SIZE            8
#endif

#ifndef LOWPAN6_G3_BLACKLIST_TABLE_SIZE
#define LOWPAN6_G3_BLACKLIST_TABLE_SIZE        8
#endif

#ifndef LOWPAN6_G3_N_GMK_KEYS
#define LOWPAN6_G3_N_GMK_KEYS               2
#endif

#ifndef LOWPAN6_G3_GMK_LEN
#define LOWPAN6_G3_GMK_LEN                  16
#endif

#endif

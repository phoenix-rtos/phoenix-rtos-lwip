/**
 * @brief IPsec security association data base management (PF_KEY)
 *
 * Phoenix-RTOS
 *
 * Operating system kernel
 *
 * @file
 * @copyright 2016 Phoenix Systems
 * @author Jaub Sejdak <jakub.sejdak@phoesys.com>
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <phoenix/pfkeyv2.h>

int ipsec_sadbDispatch(struct sadb_msg *msg, struct sadb_msg *reply, const size_t reply_len);

void ipsec_sadbInitCheckingTimeouts(void);
void ipsec_sadbStartCheckingTimeouts(void);
void ipsec_sadbStopCheckingTimeouts(void);

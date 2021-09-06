/*
 * Phoenix-RTOS --- LwIP port
 *
 * IPsec security association data base management (PF_KEY)
 *
 * Copyright 2016 Phoenix Systems
 * Author: Jacek Popko
 *
 * %LICENSE%
 */

#include "sadb.h"

#include "debug.h"
#include "ipsecdev.h"
#include "sa.h"
#include "key_sockets.h"

#include "lwip/sys.h"
#include "lwip/prot/ip.h"

#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>


#define DEBUG_SADB 1

#ifdef DEBUG_SADB
#define IPSEC_LOG_SADB(fmt, ...) syslog(LOG_DEBUG, "%s : " fmt "\n", __func__, ##__VA_ARGS__)
#else
#define IPSEC_LOG_SADB(fmt, ...)
#endif

/* in 64bits */
#define PFKEY_UNUNIT64(a) ((a) << 3)
#define PFKEY_UNIT64(a)   ((a) >> 3)

#define PFKEY_ADDR_PREFIX(ext) (((const struct sadb_address *)(const void *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext)  (((const struct sadb_address *)(const void *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext)  ((struct sockaddr *)(void *)((char *)(void *)(ext) + sizeof(struct sadb_address)))

#define SADB_THREAD_PRIO    4
#define SADB_THREAD_STACKSZ (4 * _PAGE_SIZE)

#define SADB_LARVAL_ADD_TIMEOUT_SECS (60 * 5)

static int sadb_check_timeouts_enabled = 0;

static inline void *_sadb_next(void *msg)
{
	return (uint64_t *)msg + ((struct sadb_ext *)msg)->sadb_ext_len;
}


union sadb_headers {
	struct sadb_ext *ext[SADB_EXT_MAX + 1];
	struct {
		void *reserved;
		struct sadb_sa *sa;
		struct sadb_lifetime *lifetime_current;
		struct sadb_lifetime *lifetime_hard;
		struct sadb_lifetime *lifetime_soft;
		struct sadb_address *address_src;
		struct sadb_address *address_dst;
		struct sadb_address *address_proxy;
		struct sadb_key *key_auth;
		struct sadb_key *key_encrypt;
		struct sadb_ident *identity_src;
		struct sadb_ident *identity_dst;
		struct sadb_sens *sensitivity;
		struct sadb_prop *proposal;
		struct sadb_supported *supported_auth;
		struct sadb_supported *supported_encrypt;
		struct sadb_spirange *spirange;
		struct sadb_x_kmprivate *kmprivate;
		struct sadb_x_policy *policy;
		struct sadb_x_sa2 *sa2;
		struct sadb_x_nat_t_type *nat_t_type;
		struct sadb_x_nat_t_port *nat_t_sport;
		struct sadb_x_nat_t_port *nat_t_dport;
		void *nat_t_oa;
		void *nat_t_oai;
		void *nat_t_oar;
		struct sadb_x_nat_t_frag *nat_t_frag;
	};
};

static void _sadb_deserializeMsg(const struct sadb_msg *msg, union sadb_headers *headers)
{
	struct sadb_ext *next_ext;
	size_t remaining;

	next_ext = (struct sadb_ext *)(msg + 1);
	remaining = PFKEY_UNUNIT64(msg->sadb_msg_len) - sizeof(struct sadb_msg);
	memset(headers, 0, sizeof(union sadb_headers));

	while (remaining >= sizeof(struct sadb_ext) && remaining >= PFKEY_UNUNIT64(next_ext->sadb_ext_len)) {
		if (next_ext->sadb_ext_type <= SADB_EXT_MAX && next_ext->sadb_ext_len > 0)
			headers->ext[next_ext->sadb_ext_type] = next_ext;
		else
			break;

		remaining -= PFKEY_UNUNIT64(next_ext->sadb_ext_len);
		next_ext = (struct sadb_ext *)((uint64_t *)next_ext + next_ext->sadb_ext_len);
	}
}


static int _sadb_serializeMsg(const struct sadb_msg *msg, union sadb_headers *headers)
{
	struct sadb_ext *next_ext;
	size_t remaining;
	int i;

	next_ext = (struct sadb_ext *)(msg + 1);
	remaining = PFKEY_UNUNIT64(msg->sadb_msg_len) - sizeof(struct sadb_msg);

	/* fast forward to the next populated extension */
	for (i = 1; i <= SADB_EXT_MAX && headers->ext[i] == NULL; i++)
		;

	while (i <= SADB_EXT_MAX && remaining >= PFKEY_UNUNIT64(headers->ext[i]->sadb_ext_len)) {
		memcpy(next_ext, headers->ext[i], PFKEY_UNUNIT64(headers->ext[i]->sadb_ext_len));
		remaining -= PFKEY_UNUNIT64(next_ext->sadb_ext_len);
		next_ext = (struct sadb_ext *)((uint64_t *)next_ext + next_ext->sadb_ext_len);
		/* fast forward to the next populated extension */
		for (i++; i <= SADB_EXT_MAX && headers->ext[i] == NULL; i++)
			;
	}

	return PFKEY_UNUNIT64(msg->sadb_msg_len) - remaining;
}


static int sadb_getSPI(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	union sadb_headers h;
	struct sadb_address *addr_reply;
	struct sadb_sa *sa_ext = NULL;
	db_set_netif *db_sets;
	struct sockaddr_in *addr;
	sad_entry_t *sa, larval_sa;

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.spirange == NULL || h.address_src == NULL || h.address_dst == NULL || h.sa2 == NULL)
		return -EINVAL;

	if (reply->sadb_msg_len < PFKEY_UNIT64(sizeof(struct sadb_msg) + sizeof(struct sadb_sa)) +
			h.address_dst->sadb_address_len + h.address_src->sadb_address_len) {
		reply->sadb_msg_len = PFKEY_UNIT64(sizeof(struct sadb_msg));
		return -ENOBUFS;
	}

	memset(&larval_sa, 0, sizeof(larval_sa));
	addr = (struct sockaddr_in *)(h.address_src + 1);
	larval_sa.initiator = pthread_self();
	larval_sa.addr.addr = addr->sin_addr.s_addr;
	larval_sa.mode = h.sa2->sadb_x_sa2_mode;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return -EINVAL;
	sa = ipsec_sad_add(&larval_sa, &db_sets->inbound_sad);
	if (sa == NULL)
		return -ENOMEM;

	ipsecdev_enable();

	/* WARN: SPI is a pointer to SA entry */
	sa->spi = htonl((uint32_t)sa);

	/* make LARVAL SPIs automatically expire */
	sa->lifetime.hard_add_expires_seconds = SADB_LARVAL_ADD_TIMEOUT_SECS;

	sa_ext = (struct sadb_sa *)(reply + 1);
	memset(sa_ext, 0, sizeof(struct sadb_sa));
	sa_ext->sadb_sa_len = PFKEY_UNIT64(sizeof(struct sadb_sa));
	sa_ext->sadb_sa_exttype = SADB_EXT_SA;
	sa_ext->sadb_sa_spi = sa->spi;
	sa_ext->sadb_sa_state = SADB_SASTATE_LARVAL;

	IPSEC_LOG_SADB("itor: %u  spi: %x  mode: %d  dst_addr: %x", sa->initiator, sa->spi, sa->mode, sa->addr.addr);

	addr_reply = (struct sadb_address *)_sadb_next(sa_ext);
	memcpy(addr_reply, h.address_src, PFKEY_UNUNIT64(h.address_src->sadb_address_len));

	addr_reply = (struct sadb_address *)_sadb_next(addr_reply);
	memcpy(addr_reply, h.address_dst, PFKEY_UNUNIT64(h.address_dst->sadb_address_len));

	reply->sadb_msg_len = PFKEY_UNIT64(sizeof(struct sadb_msg) + sizeof(struct sadb_sa)) +
		h.address_dst->sadb_address_len + h.address_src->sadb_address_len;
	return EOK;
}


static int sadb_fill_sa_common(const struct sadb_msg *msg, const union sadb_headers *h, sad_entry_t *sa, const char *func)
{
	if (h->sa->sadb_sa_auth) {
		if (h->key_auth == NULL || h->key_auth->sadb_key_bits == 0 ||
			h->key_auth->sadb_key_bits + sizeof(*h->key_auth) * 8 > h->key_auth->sadb_key_len * 64)
			return -EINVAL;

		if (h->key_auth->sadb_key_bits > IPSEC_MAX_AUTHKEY_LEN * 8)
			return -ENOMEM;

		memcpy(sa->authkey, h->key_auth + 1, (h->key_auth->sadb_key_bits - 1) / 8 + 1);
	}

	if (h->sa->sadb_sa_encrypt) {
		if (h->key_encrypt == NULL || h->key_encrypt->sadb_key_bits == 0 ||
			h->key_encrypt->sadb_key_bits + sizeof(*h->key_encrypt) * 8 > h->key_encrypt->sadb_key_len * 64)
			return -EINVAL;

		if (h->key_encrypt->sadb_key_bits > IPSEC_MAX_ENCKEY_LEN * 8)
			return -ENOMEM;

		sa->enckey_len = (h->key_encrypt->sadb_key_bits - 1) / 8 + 1;
		memcpy(sa->enckey, h->key_encrypt + 1, sa->enckey_len);
	}

	if (msg->sadb_msg_satype == SADB_SATYPE_AH)
		sa->proto = IP_PROTO_AH;
	else if (msg->sadb_msg_satype == SADB_SATYPE_ESP)
		sa->proto = IP_PROTO_ESP;
	else
		return -EINVAL;

	if (h->nat_t_type && h->nat_t_type->sadb_x_nat_t_type_type) {
		if (!h->nat_t_sport || !h->nat_t_dport)
			return -EINVAL;

		switch (h->nat_t_type->sadb_x_nat_t_type_type) {
			case UDP_ENCAP_ESPINUDP_NON_IKE:
			case UDP_ENCAP_ESPINUDP:
				sa->natt_mode = h->nat_t_type->sadb_x_nat_t_type_type;
				if (sa->proto != IP_PROTO_ESP)
					return -EINVAL;
				break;
			default:
				return -EINVAL;
		}

		sa->natt_sport = h->nat_t_sport->sadb_x_nat_t_port_port;
		sa->natt_dport = h->nat_t_dport->sadb_x_nat_t_port_port;

		IPSEC_LOG_SADB("%s(): itor: %u  spi: %x  nat-t(%u): %u->%u", func,
			sa->initiator, sa->spi, sa->natt_mode,
			lwip_ntohs(sa->natt_sport), lwip_ntohs(sa->natt_dport));
	}

	if (h->lifetime_soft) {
		sa->lifetime.soft_add_expires_seconds = h->lifetime_soft->sadb_lifetime_addtime;
		sa->lifetime.soft_use_expires_seconds = h->lifetime_soft->sadb_lifetime_usetime;
	}

	if (h->lifetime_hard) {
		sa->lifetime.hard_add_expires_seconds = h->lifetime_hard->sadb_lifetime_addtime;
		sa->lifetime.hard_use_expires_seconds = h->lifetime_hard->sadb_lifetime_usetime;
	}
	// lifetime_current should never arrive in the message

	sa->auth_alg = h->sa->sadb_sa_auth;
	sa->enc_alg = h->sa->sadb_sa_encrypt;
	sa->replay_win = h->sa->sadb_sa_replay;

	return 0;
}

static int sadb_fill_msg_common(struct sadb_msg *msg, sad_entry_t *sa, int hsc)
{
	memset(msg, 0, sizeof(struct sadb_msg));
	msg->sadb_msg_version = PF_KEY_V2;
	/* leaving set to 0 to be filled by the caller */
	/*
	msg->sadb_msg_seq = 0;
	msg->sadb_msg_pid = 0;
	msg->sadb_msg_type = 0;
	*/
	msg->sadb_msg_satype = sa->proto;

	if (sa->proto == IP_PROTO_AH)
		msg->sadb_msg_satype = SADB_SATYPE_AH;
	else if (sa->proto == IP_PROTO_ESP)
		msg->sadb_msg_satype = SADB_SATYPE_ESP;
	else
		return -EINVAL;

	struct sadb_ext *next_ext = (struct sadb_ext *)(msg + 1);

	/* sa */
	struct sadb_sa *sa_ext = (struct sadb_sa *)next_ext;
	sa_ext->sadb_sa_len = PFKEY_UNIT64(sizeof(struct sadb_sa));
	sa_ext->sadb_sa_exttype = SADB_EXT_SA;
	sa_ext->sadb_sa_spi = sa->spi;
	sa_ext->sadb_sa_replay = sa->replay_win;
	sa_ext->sadb_sa_state = sa->initiator ? SADB_SASTATE_LARVAL : SADB_SASTATE_MATURE;

	next_ext = (struct sadb_ext *)_sadb_next(next_ext);

	// NOTE: adding auth/encryption keys is not supported

	/* hard time */
	if (hsc & 2) {
		struct sadb_lifetime *lifetime = (struct sadb_lifetime *)next_ext;
		memset(lifetime, 0, sizeof(struct sadb_lifetime));
		lifetime->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
		lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
		lifetime->sadb_lifetime_allocations = 0;
		lifetime->sadb_lifetime_bytes = 0;
		lifetime->sadb_lifetime_addtime = sa->lifetime.hard_add_expires_seconds;
		lifetime->sadb_lifetime_usetime = sa->lifetime.hard_use_expires_seconds;

		next_ext = (struct sadb_ext *)_sadb_next(next_ext);
	}
	/* soft time */
	if (hsc & 1) {
		struct sadb_lifetime *lifetime = (struct sadb_lifetime *)next_ext;
		memset(lifetime, 0, sizeof(struct sadb_lifetime));
		lifetime->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
		lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
		lifetime->sadb_lifetime_allocations = 0;
		lifetime->sadb_lifetime_bytes = 0;
		lifetime->sadb_lifetime_addtime = sa->lifetime.soft_add_expires_seconds;
		lifetime->sadb_lifetime_usetime = sa->lifetime.soft_use_expires_seconds;

		next_ext = (struct sadb_ext *)_sadb_next(next_ext);
	}

	//TODO: add more
	msg->sadb_msg_len = PFKEY_UNIT64(((uint8_t *)next_ext - (uint8_t *)msg));

	return msg->sadb_msg_len;
}

static int sadb_update(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	sad_entry_t *sa;
	union sadb_headers h;
	int used, ret;

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.sa == NULL)
		return -EINVAL;

	/* WARN: SPI is a pointer to SA entry */
	/* TODO: find */
	sa = (sad_entry_t *)ntohl(h.sa->sadb_sa_spi);

	IPSEC_LOG_SADB("itor: %u  spi: %x  mode: %d  dst_addr: %x", sa->initiator, sa->spi, sa->mode, sa->addr.addr);

	/* Is SPI a valid SA entry pointer? */
	if (sa->spi != h.sa->sadb_sa_spi)
		return -ESRCH;

	if (!pthread_equal(sa->initiator, pthread_self()))
		return -EACCES;

	ret = sadb_fill_sa_common(msg, &h, sa, __func__);
	if (ret)
		return ret;

	/* forget initiator, SA moves from LARVAL to MATURE state */
	sa->initiator = 0;

	/* TODO: Add SADB_EXT_LIFETIME_* and SADB_EXT_IDENTITY_* extensions handling */
	h.key_auth = NULL;
	h.key_encrypt = NULL;
	used = _sadb_serializeMsg(reply, &h);
	reply->sadb_msg_len = PFKEY_UNIT64(used);
	return EOK;
}


static int sadb_add(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	sad_entry_t sa_entry, *sa;
	sad_table *sad;
	db_set_netif *db_sets;
	union sadb_headers h;
	uint32_t addr;
	int used, ret;
	/* uint8_t proto; */

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.sa == NULL || h.address_dst == NULL || h.address_src == NULL)
		return -EINVAL;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return -EINVAL;

	addr = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_src))->sin_addr.s_addr;
	/* proto = h.address_src->sadb_address_proto; */

	if (addr == ipsecdev_getIP()) {
		sad = &db_sets->outbound_sad;
		addr = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_dst))->sin_addr.s_addr;
		;
	}
	else
		sad = &db_sets->inbound_sad;

	memset(&sa_entry, 0, sizeof(sa_entry));

	ret = sadb_fill_sa_common(msg, &h, &sa_entry, __func__);
	if (ret)
		return ret;

	sa_entry.spi = h.sa->sadb_sa_spi;
	sa_entry.addr.addr = addr;
	if (h.sa2 != NULL) {
		sa_entry.mode = h.sa2->sadb_x_sa2_mode;
		sa_entry.seqnum = h.sa2->sadb_x_sa2_sequence;
	}
	else
		sa_entry.mode = IPSEC_MODE_TUNNEL;

	/* TODO: Add SADB_EXT_LIFETIME_* and SADB_EXT_IDENTITY_* extensions handling */
	if ((sa = ipsec_sad_add(&sa_entry, sad)) == NULL)
		return -ENOMEM;

	IPSEC_LOG_SADB("itor: %u  spi: %x  mode: %d  dst_addr: %x", sa->initiator, sa->spi, sa->mode, sa->addr.addr);

	ipsecdev_enable();

	h.key_auth = NULL;
	h.key_encrypt = NULL;
	used = _sadb_serializeMsg(reply, &h);
	reply->sadb_msg_len = PFKEY_UNIT64(used);
	return EOK;
}


static int sadb_del(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	db_set_netif *db_sets;
	union sadb_headers h;

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.sa == NULL || h.address_dst == NULL || h.address_src == NULL)
		return -EINVAL;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return -EINVAL;

	// FIXME: check src/dstaddr
	ipsec_sad_del_spi(h.sa->sadb_sa_spi, &db_sets->outbound_sad);
	ipsec_sad_del_spi(h.sa->sadb_sa_spi, &db_sets->inbound_sad);

	return EOK;
}


static int sadb_flush(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	db_set_netif *db_sets = ipsecdev_dbsget();

	if (db_sets == NULL)
		return -EINVAL;

	ipsecdev_disable();
	ipsec_sad_flush(&db_sets->inbound_sad);
	ipsec_sad_flush(&db_sets->outbound_sad);

	reply->sadb_msg_len = sizeof(struct sadb_msg) / sizeof(uint64_t);
	return EOK;
}


static int sadb_x_spdflush(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	spd_entry_t spd_default = { .protocol = IPSEC_PROTO_ANY, .policy = IPSEC_POLICY_BYPASS };
	db_set_netif *db_sets = ipsecdev_dbsget();

	if (db_sets == NULL)
		return -EINVAL;

	ipsec_spd_flush(&db_sets->inbound_spd, &spd_default);
	ipsec_spd_flush(&db_sets->outbound_spd, &spd_default);

	reply->sadb_msg_len = sizeof(struct sadb_msg) / sizeof(uint64_t);
	return EOK;
}


static int sadb_register(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	struct sadb_supported *supported;
	const struct sadb_alg *algs;
	size_t algs_size;
	int ext_type;
	static const struct sadb_alg enc_algs[] = {
		{ .sadb_alg_id = SADB_EALG_DESCBC,
			.sadb_alg_ivlen = 8,
			.sadb_alg_minbits = 64,
			.sadb_alg_maxbits = 64 },
		{ .sadb_alg_id = SADB_EALG_3DESCBC,
			.sadb_alg_ivlen = 8,
			.sadb_alg_minbits = 192,
			.sadb_alg_maxbits = 192 },
		{ .sadb_alg_id = SADB_X_EALG_AES,
			.sadb_alg_ivlen = 8,
			.sadb_alg_minbits = 128,
			.sadb_alg_maxbits = 256 },
	};
	static const struct sadb_alg auth_algs[] = {
		{ .sadb_alg_id = SADB_AALG_MD5HMAC,
			.sadb_alg_ivlen = 0,
			.sadb_alg_minbits = 128,
			.sadb_alg_maxbits = 128 },
		{ .sadb_alg_id = SADB_AALG_SHA1HMAC,
			.sadb_alg_ivlen = 0,
			.sadb_alg_minbits = 160,
			.sadb_alg_maxbits = 160 },
		{ .sadb_alg_id = SADB_X_AALG_SHA2_256,
			.sadb_alg_ivlen = 0,
			.sadb_alg_minbits = 256,
			.sadb_alg_maxbits = 256 },
	};

	switch (msg->sadb_msg_satype) {
		case SADB_SATYPE_AH:
			algs = auth_algs;
			algs_size = sizeof(auth_algs);
			ext_type = SADB_EXT_SUPPORTED_AUTH;
			break;

		case SADB_SATYPE_ESP:
			algs = enc_algs;
			algs_size = sizeof(enc_algs);
			ext_type = SADB_EXT_SUPPORTED_ENCRYPT;
			break;

		default:
			IPSEC_LOG_MSG("%s(): skipped registration of satype %d", msg->sadb_msg_satype);
			algs = NULL;
			algs_size = 0;
			ext_type = -1;
			break;
	}


	if (PFKEY_UNUNIT64(reply->sadb_msg_len) < sizeof(struct sadb_msg) + sizeof(struct sadb_supported) + algs_size) {
		reply->sadb_msg_len = PFKEY_UNIT64(sizeof(struct sadb_msg));
		return -ENOBUFS;
	}

	if (ext_type > 0) {
		supported = (struct sadb_supported *)(reply + 1);
		supported->sadb_supported_exttype = ext_type;
		supported->sadb_supported_len = PFKEY_UNIT64(sizeof(struct sadb_supported) + algs_size);
		memcpy(supported + 1, algs, algs_size);
		reply->sadb_msg_len = PFKEY_UNIT64(sizeof(struct sadb_msg)) + supported->sadb_supported_len;
	}
	else
		reply->sadb_msg_len = PFKEY_UNIT64(sizeof(struct sadb_msg));

	return EOK;
}

static int sadb_debug_ipsecreq(const struct sadb_x_ipsecrequest *req, unsigned idx)
{
	const struct sockaddr_in *sa = (void *)(req + 1);
	unsigned sa_len = req->sadb_x_ipsecrequest_len - sizeof(*req);
	unsigned addridx = 0;

	IPSEC_LOG_SADB("SADB_X_SPDADD: ipsec[%u]: proto=%u mode=%u level=%u id=%u (len=%u, sa_len=%u)",
		idx, req->sadb_x_ipsecrequest_proto,
		req->sadb_x_ipsecrequest_mode, req->sadb_x_ipsecrequest_level,
		req->sadb_x_ipsecrequest_reqid, req->sadb_x_ipsecrequest_len, sa_len);

	while (sa_len > 2) {
		if (sa->sin_family != AF_INET) {
			IPSEC_LOG_SADB("SADB_X_SPDADD: ipsec[%u].addr[%u]: family %u", idx, addridx, sa->sin_family);
			break;
		}

		IPSEC_LOG_SADB("SADB_X_SPDADD: ipsec[%u].addr[%u]: ip4 %08x:%u", idx, addridx, sa->sin_addr.s_addr, sa->sin_port);

		sa_len -= sizeof(*sa);
		++sa;
		++addridx;
	}

	return 0;
}

static int sadb_count_ipsecreqs(const struct sadb_x_ipsecrequest *req, unsigned len)
{
	unsigned count;

	if (len < sizeof(struct sadb_x_policy))
		return -EINVAL;
	len -= sizeof(struct sadb_x_policy);

	count = 0;
	while (len > 0) {
		if (len < sizeof(*req))
			return -EINVAL;
		if (len < req->sadb_x_ipsecrequest_len)
			return -EINVAL;

		if (sadb_debug_ipsecreq(req, count) < 0)
			return -EINVAL;

		len -= req->sadb_x_ipsecrequest_len;
		req = (void *)((uint8_t *)req + req->sadb_x_ipsecrequest_len);
		++count;
	}

	return count;
}

static int sadb_x_spdadd(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	union sadb_headers h;
	spd_table *spd;
	spd_entry_t *sp;
	uint32_t src_addr, src_mask, dst_addr, dst_mask, dst_tun = 0;
	uint16_t src_port, dst_port;
	db_set_netif *db_sets;

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.policy == NULL || h.address_dst == NULL || h.address_src == NULL)
		return -EINVAL;

	if (h.policy->sadb_x_policy_type == IPSEC_POLICY_IPSEC) {
		struct sadb_x_ipsecrequest *ipsecreq = (void *)(h.policy + 1);
		struct sockaddr_in *addr = (void *)(ipsecreq + 1);
		int n;

		if (h.sa2 == NULL)
			return -EINVAL;

		n = sadb_count_ipsecreqs(ipsecreq, PFKEY_UNUNIT64(h.policy->sadb_x_policy_len));
		if (n < 0)
			return n;

		if (n == 0) {
			IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "SADB_X_SPDADD: ipsec policy, but no encapsulation?\n");
			return -EINVAL;
		}

		if (n > 1)
			IPSEC_LOG_MSG("SADB_X_SPDADD: FIXME: ipsec: multiple encapsulations\n");

		if (ipsecreq->sadb_x_ipsecrequest_mode != IPSEC_MODE_TUNNEL) {
			IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "SADB_X_SPDADD: FIXME: ipsec: non-tunnel mode\n");
			return -EINVAL;
		}

		if (ipsecreq->sadb_x_ipsecrequest_len <= sizeof(*ipsecreq))
			return -EINVAL;  // addresses are required for tunnel mode

		if (ipsecreq->sadb_x_ipsecrequest_len != sizeof(*ipsecreq) + 2 * sizeof(*addr)) {
			IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "SADB_X_SPDADD: FIXME: ipsec: non-IPv4 addrs?\n");
			return -EINVAL;
		}

		if (addr[0].sin_family != AF_INET || addr[1].sin_family != AF_INET) {
			IPSEC_LOG_ERR(IPSEC_STATUS_FAILURE, "SADB_X_SPDADD: FIXME: ipsec: tunnel in non-IPv4\n");
			return -EINVAL;
		}

		dst_tun = addr[1].sin_addr.s_addr;
	}

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return -EINVAL;

	src_addr = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_src))->sin_addr.s_addr;
	src_mask = htonl((uint32_t)-1 << (32 - PFKEY_ADDR_PREFIX(h.address_src)));
	src_port = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_src))->sin_port;

	dst_addr = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_dst))->sin_addr.s_addr;
	dst_mask = htonl((uint32_t)-1 << (32 - PFKEY_ADDR_PREFIX(h.address_dst)));
	dst_port = ((struct sockaddr_in *)PFKEY_ADDR_SADDR(h.address_dst))->sin_port;

	if (h.policy->sadb_x_policy_dir == IPSEC_DIR_OUTBOUND)
		spd = &db_sets->outbound_spd;
	else if (h.policy->sadb_x_policy_dir == IPSEC_DIR_INBOUND)
		spd = &db_sets->inbound_spd;
	else
		return -EINVAL;

	sp = ipsec_spd_add(src_addr, src_mask, dst_addr, dst_mask, PFKEY_ADDR_PROTO(h.address_src),
		src_port, dst_port, h.policy->sadb_x_policy_type, dst_tun, spd,
		h.policy->sadb_x_policy_dir != IPSEC_DIR_OUTBOUND);
	if (sp == NULL) {
		return -ENOMEM;
	}
	h.policy->sadb_x_policy_id = (uint32_t)sp;

	reply->sadb_msg_len = PFKEY_UNIT64(_sadb_serializeMsg(reply, &h));
	return EOK;
}

static int sadb_x_spddel(const struct sadb_msg *msg, struct sadb_msg *reply)
{
	union sadb_headers h;
	spd_table *spd;
	spd_entry_t *sp;
	db_set_netif *db_sets;
	int ret;

	if (msg == NULL || reply == NULL)
		return -EIO;

	_sadb_deserializeMsg(msg, &h);

	if (h.policy == NULL)
		return -EINVAL;

	if (h.policy->sadb_x_policy_id == 0)
		return -EINVAL;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return -EINVAL;

	if (h.policy->sadb_x_policy_dir == IPSEC_DIR_OUTBOUND)
		spd = &db_sets->outbound_spd;
	else if (h.policy->sadb_x_policy_dir == IPSEC_DIR_INBOUND)
		spd = &db_sets->inbound_spd;
	else
		return -EINVAL;

	sp = (void *)h.policy->sadb_x_policy_id;
	ret = ipsec_spd_del_maybe(sp, spd);

	reply->sadb_msg_len = PFKEY_UNIT64(_sadb_serializeMsg(reply, &h));
	return ret;
}

static void ipsec_dump_tables(int dump_spd)
{
	db_set_netif *db_sets;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return;

	if (dump_spd) {
		ipsec_spd_dump_log(&db_sets->inbound_spd, "In  ");
		ipsec_spd_dump_log(&db_sets->outbound_spd, "Out ");
	}
	else {
		ipsec_sad_dump_log(&db_sets->inbound_sad, "In  ");
		ipsec_sad_dump_log(&db_sets->outbound_sad, "Out ");
	}
}

#define CHECK_TIMEOUT_SEC 5

static void ipsec_check_timeouts(void *arg)
{
	db_set_netif *db_sets;
	sad_entry_t *sa_expired = NULL;
	int is_soft;
	char msgbuf[512];
	struct sadb_msg *msg = (struct sadb_msg *)msgbuf;

	db_sets = ipsecdev_dbsget();
	if (db_sets == NULL)
		return;

	while (1) {
		do {
			sleep(CHECK_TIMEOUT_SEC);
		} while (!sadb_check_timeouts_enabled);

		// NOTE: we're sending one expiration at a time to avoid loops (the user is responsible for sending SADB_DELETE)
		if (((sa_expired = ipsec_sad_check_timeouts(&db_sets->inbound_sad, &is_soft)) != NULL) || ((sa_expired = ipsec_sad_check_timeouts(&db_sets->outbound_sad, &is_soft)) != NULL)) {
			msg->sadb_msg_len = PFKEY_UNIT64(sizeof(msgbuf));
			sadb_fill_msg_common(msg, sa_expired, (is_soft ? 1 : 2));
			msg->sadb_msg_type = SADB_EXPIRE;
			int is_larval = sa_expired->initiator != 0;

			IPSEC_LOG_SADB("SADB_EXPIRE (%s): spi: %x  mode: %d  dst_addr: %x",
				(is_soft ? "soft" : "hard"), sa_expired->spi, sa_expired->mode, sa_expired->addr.addr);

			key_sockets_notify(msg);

			if (!is_soft) {
				// note: we should mark SA not to be used again
			}

			if (!is_soft && is_larval) {
				// NOTE: i don't know if this is legal, but iked never deletes LARVAL spi's
				ipsec_sad_del_spi(sa_expired->spi, &db_sets->outbound_sad);
				ipsec_sad_del_spi(sa_expired->spi, &db_sets->inbound_sad);
			}
		}
	}
}

void ipsec_sadbStartCheckingTimeouts(void)
{
	sadb_check_timeouts_enabled = 1;
}

void ipsec_sadbStopCheckingTimeouts(void)
{
	sadb_check_timeouts_enabled = 0;
}

void ipsec_sadbInitCheckingTimeouts(void)
{
	sys_thread_opt_new("ipsec-sadb", ipsec_check_timeouts, NULL, SADB_THREAD_STACKSZ, SADB_THREAD_PRIO, NULL);
}

int ipsec_sadbDispatch(const struct sadb_msg *msg, struct sadb_msg *reply, size_t reply_size)
{
	int err = -EINVAL;
	int spd_req = 0;

	if (msg->sadb_msg_version != PF_KEY_V2)
		return -EINVAL;

	if (reply_size < sizeof(struct sadb_msg))
		return -ENOBUFS;

	memcpy(reply, msg, sizeof(struct sadb_msg));
	reply->sadb_msg_len = reply_size / sizeof(uint64_t);

	switch (msg->sadb_msg_type) {
		case SADB_GETSPI:
			IPSEC_LOG_SADB("SADB_GETSPI");
			err = sadb_getSPI(msg, reply);
			break;

		case SADB_UPDATE:
			IPSEC_LOG_SADB("SADB_UPDATE");
			err = sadb_update(msg, reply);
			break;

		case SADB_ADD:
			IPSEC_LOG_SADB("SADB_ADD");
			err = sadb_add(msg, reply);
			break;

		case SADB_DELETE:
			IPSEC_LOG_SADB("SADB_DELETE");
			err = sadb_del(msg, reply);
			break;

		case SADB_ACQUIRE:
			IPSEC_LOG_SADB("SADB_ACQUIRE");
			break;

		case SADB_REGISTER:
			IPSEC_LOG_SADB("SADB_REGISTER");
			err = sadb_register(msg, reply);
			break;

		case SADB_EXPIRE:
			IPSEC_LOG_SADB("SADB_EXPIRE");
			break;

		case SADB_FLUSH:
			IPSEC_LOG_SADB("SADB_FLUSH");
			err = sadb_flush(msg, reply);
			break;

		case SADB_X_SPDFLUSH:
			IPSEC_LOG_SADB("SADB_X_SPDFLUSH");
			err = sadb_x_spdflush(msg, reply);
			spd_req = 1;
			break;

		case SADB_X_SPDADD:
			IPSEC_LOG_SADB("SADB_X_SPDADD");
			err = sadb_x_spdadd(msg, reply);
			spd_req = 1;
			break;

		case SADB_X_SPDDELETE:
			IPSEC_LOG_SADB("SADB_X_SPDDELETE");
			err = sadb_x_spddel(msg, reply);
			spd_req = 1;
			break;

		default:
			IPSEC_LOG_SADB("SADB unhandled: [%d]", msg->sadb_msg_type);
			break;
	}

	reply->sadb_msg_errno = -err;
	ipsec_dump_tables(spd_req);
	return err;
}

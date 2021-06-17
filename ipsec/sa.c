#include <string.h>
#include <ipv4/lwip/inet.h>
#include <ipv4/lwip/ip4.h>
#include <lwip/tcp_impl.h>
#include <lwip/udp.h>
#include <lib/list.h>

#include "debug.h"
#include "util.h"

#include "sa.h"
#include "ah.h"
#include "esp.h"


typedef struct ipsec_in_ip_struct /**< IPsec in IP structure - used to access headers inside SA */
{
	struct ip_hdr ip; /**< IPv4 header */
	union {
		ipsec_ah_header ah;   /**< AH header  */
		ipsec_esp_header esp; /**< ESP header */
		struct tcp_hdr tcp;   /**< TCP header */
		struct udp_hdr udp;   /**< UDP header */
	} inner_header;
} ipsec_in_ip;


static u32 get_seconds(void)
{
	return (hal_upTime() / (1000 * 1000));
}

void ipsec_db_init(db_set_netif *dbs)
{
	proc_mutexCreate(&dbs->inbound_sad.mutex);
	LIST_HEAD_INIT(&dbs->inbound_sad);
	proc_mutexCreate(&dbs->outbound_sad.mutex);
	LIST_HEAD_INIT(&dbs->outbound_sad);
	proc_mutexCreate(&dbs->inbound_spd.mutex);
	LIST_HEAD_INIT(&dbs->inbound_spd);
	ipsec_spd_add(0, 0, 0, 0, IPSEC_PROTO_ANY, IPSEC_PORT_ANY, IPSEC_PORT_ANY, IPSEC_POLICY_BYPASS, 0, &dbs->inbound_spd, 1);
	proc_mutexCreate(&dbs->outbound_spd.mutex);
	LIST_HEAD_INIT(&dbs->outbound_spd);
	ipsec_spd_add(0, 0, 0, 0, IPSEC_PROTO_ANY, IPSEC_PORT_ANY, IPSEC_PORT_ANY, IPSEC_POLICY_BYPASS, 0, &dbs->outbound_spd, 0);
}


void ipsec_db_term(db_set_netif *dbs)
{
	spd_entry_t *sp;
	sad_entry_t *sa;

	proc_mutexLock(&dbs->inbound_spd.mutex);
	if (dbs->inbound_spd.first != NULL) {
		do {
			sp = dbs->inbound_spd.first;
			dbs->inbound_spd.first = sp->list.next;
			vm_kfree(sp);
		} while (dbs->inbound_spd.first != sp);
		dbs->inbound_spd.first = NULL;
	}
	proc_mutexTerminate(&dbs->inbound_spd.mutex);

	proc_mutexLock(&dbs->outbound_spd.mutex);
	if (dbs->outbound_spd.first != NULL) {
		do {
			sp = dbs->outbound_spd.first;
			dbs->outbound_spd.first = sp->list.next;
			vm_kfree(sp);
		} while (dbs->outbound_spd.first != sp);
		dbs->outbound_spd.first = NULL;
	}
	proc_mutexTerminate(&dbs->outbound_spd.mutex);

	proc_mutexLock(&dbs->inbound_sad.mutex);
	if (dbs->inbound_sad.first != NULL) {
		do {
			sa = dbs->inbound_sad.first;
			dbs->inbound_sad.first = sa->list.next;
			vm_kfree(sa);
		} while (dbs->inbound_sad.first != sa);
		dbs->inbound_sad.first = NULL;
	}
	proc_mutexTerminate(&dbs->inbound_sad.mutex);

	proc_mutexLock(&dbs->outbound_sad.mutex);
	if (dbs->outbound_sad.first != NULL) {
		do {
			sa = dbs->outbound_sad.first;
			dbs->outbound_sad.first = sa->list.next;
			vm_kfree(sa);
		} while (dbs->outbound_sad.first != sa);
		dbs->outbound_sad.first = NULL;
	}
	proc_mutexTerminate(&dbs->outbound_sad.mutex);
}


spd_entry_t *ipsec_spd_add(u32_t src, u32_t src_net, u32_t dst, u32_t dst_net, u8_t proto, u16_t src_port, u16_t dst_port, u8_t policy,
	u32_t tunnel_dest, spd_table *table, int sort_src_first)
{
	spd_entry_t *n;

	n = vm_kmalloc(sizeof(spd_entry_t));
	if (n == NULL)
		return NULL;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_spd_add", "src=0x%08lx/0x%08lx dst=0x%08lx/0x%08lx proto=%u port=%u->%u policy=%u tunnel_dest=0x%08lx",
		src, src_net, dst, dst_net, proto, src_port, dst_port, policy, tunnel_dest);

	LIST_ELEM_INIT(n, list);
	n->src = src;
	n->src_mask = src_net;
	n->dest = dst;
	n->dest_mask = dst_net;
	n->tunnel_dest = tunnel_dest;
	n->protocol = proto;
	n->src_port = src_port;
	n->dest_port = dst_port;
	n->policy = policy;

	proc_mutexLock(&table->mutex);
	if (LIST_IS_EMPTY(table))
		LIST_ADD(table, n, list);
	else {
		spd_entry_t *entry;
		int mask_len, mask_len2, entry_mask_len, port, port2, entry_port;

		mask_len = sort_src_first ? hal_cpuGetFirstBit(lwip_ntohl(n->src_mask)) : hal_cpuGetFirstBit(lwip_ntohl(n->dest_mask));
		mask_len2 = sort_src_first ? hal_cpuGetFirstBit(lwip_ntohl(n->dest_mask)) : hal_cpuGetFirstBit(lwip_ntohl(n->src_mask));
		port = sort_src_first ? src_port : dst_port;
		port2 = sort_src_first ? dst_port : src_port;

		LIST_FOR_EACH(table, entry, list)
		{
			entry_mask_len = sort_src_first ? hal_cpuGetFirstBit(lwip_ntohl(entry->src_mask)) : hal_cpuGetFirstBit(lwip_ntohl(entry->dest_mask));
			if (mask_len < entry_mask_len)
				break;
			if (mask_len > entry_mask_len)
				continue;

			entry_mask_len = sort_src_first ? hal_cpuGetFirstBit(lwip_ntohl(entry->dest_mask)) : hal_cpuGetFirstBit(lwip_ntohl(entry->src_mask));
			if (mask_len2 < entry_mask_len)
				break;
			if (mask_len2 > entry_mask_len)
				continue;

			entry_port = sort_src_first ? entry->src_port : entry->dest_port;
			if (port != IPSEC_PORT_ANY && entry_port == IPSEC_PORT_ANY)
				break;

			entry_port = sort_src_first ? entry->dest_port : entry->src_port;
			if (port2 != IPSEC_PORT_ANY && entry_port == IPSEC_PORT_ANY)
				break;
		}

		if (entry == NULL)
			LIST_ADD_ELEM(table->first, n, list);
		else {
			LIST_ADD_ELEM(entry, n, list);
			if (table->first == entry)
				table->first = n;
		}
	}
	proc_mutexUnlock(&table->mutex);
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_add", "return = %p", n);
	return n;
}


void ipsec_spd_del(spd_entry_t *entry, spd_table *table)
{
	proc_mutexLock(&table->mutex);
	LIST_REMOVE(table, entry, list);
	vm_kfree(entry);
	proc_mutexUnlock(&table->mutex);
}


int ipsec_spd_del_maybe(spd_entry_t *ep, spd_table *table)
{
	spd_entry_t *entry;
	int ret = -ENOENT;

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if (entry != ep)
			continue;

		LIST_REMOVE(table, entry, list);
		vm_kfree(entry);
		ret = 0;
		break;
	}
	proc_mutexUnlock(&table->mutex);

	return ret;
}


spd_entry_t *ipsec_spd_lookup(struct ip_hdr *header, spd_table *table, unsigned flags)
{
	spd_entry_t *entry;
	ipsec_in_ip *ip = (ipsec_in_ip *)header;
	int ignore_src = flags & IPSEC_MATCH_DST;
	int ignore_dst = flags & IPSEC_MATCH_SRC;

	//	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_spd_lookup", "header=%p, table=%p, [src=0x%08lx, dst=0x%08lx]",
	//		(void *)ip, (void *)table, header->src.addr, header->dest.addr);

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if ((ignore_src || ipsec_ip_addr_maskcmp(header->src.addr, entry->src, entry->src_mask)) &&
			(ignore_dst || ipsec_ip_addr_maskcmp(header->dest.addr, entry->dest, entry->dest_mask))) {

			if (entry->protocol == IPSEC_PROTO_ANY)
				break;
			if (entry->protocol == IPH_PROTO(header)) {
				if (IPH_PROTO(header) == IP_PROTO_TCP) {
					if ((entry->src_port == IPSEC_PORT_ANY) || (entry->src_port == ip->inner_header.tcp.src))
						if ((entry->dest_port == 0) || (entry->dest_port == ip->inner_header.tcp.dest)) {
							//							IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", "tmp_entry = %p", entry );
							break;
						}
				}
				else if (IPH_PROTO(header) == IP_PROTO_UDP) {
					if ((entry->src_port == IPSEC_PORT_ANY) || (entry->src_port == ip->inner_header.udp.src))
						if ((entry->dest_port == 0) || (entry->dest_port == ip->inner_header.udp.dest)) {
							//							IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", "tmp_entry = %p", entry );
							break;
						}
				}
				else
					break;
			}
		}
	}
	proc_mutexUnlock(&table->mutex);
	//	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", "return = %p", entry );
	return entry;
}


sad_entry_t *ipsec_sad_add(const sad_entry_t *entry, sad_table *table)
{
	sad_entry_t *n;

	n = vm_kmalloc(sizeof(sad_entry_t));
	if (n == NULL)
		return NULL;

	hal_memcpy(n, entry, sizeof(sad_entry_t));
	LIST_ELEM_INIT(n, list);
	n->lifetime.curr_add_time = get_seconds();

	proc_mutexLock(&table->mutex);
	LIST_ADD(table, n, list);
	proc_mutexUnlock(&table->mutex);
	return n;
}


void ipsec_sad_del(sad_entry_t *entry, sad_table *table)
{
	proc_mutexLock(&table->mutex);
	LIST_REMOVE(table, entry, list);
	vm_kfree(entry);
	proc_mutexUnlock(&table->mutex);
}


void ipsec_sad_del_spi(u32_t spi, sad_table *table)
{
	sad_entry_t *entry;
	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if (entry->spi != spi)
			continue;

		LIST_REMOVE(table, entry, list);
		vm_kfree(entry);
		break;  // FIXME: find more?
	}
	proc_mutexUnlock(&table->mutex);
}

sad_entry_t *ipsec_sad_lookup(ip_addr_p_t addr, u8_t proto, u32_t spi, sad_table *table)
{
	sad_entry_t *entry;

	//	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_sad_lookup", "dest=%lu, proto=%d, spi=%lu, table=%p", addr.addr, proto, spi, table);

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if (addr.addr == entry->addr.addr && (entry->spi == spi || spi == 0))
			break;
	}
	proc_mutexUnlock(&table->mutex);
	//	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_lookup", "return = %p", entry);

	if (entry)
		entry->lifetime.curr_use_time = get_seconds();

	return entry;
}

sad_entry_t *ipsec_sad_lookup_natt(struct ip_hdr *ip, sad_table *table)
{
	struct udp_hdr *udp = (void *)((char *)ip + IPH_HL(ip) * 4);
	ip_addr_p_t addr = ip->src;
	sad_entry_t *entry;
	u16_t sport, dport;
	u32_t spi, spi2;
	int len = lwip_ntohs(ip->_len) - IPH_HL(ip) * 4;

	// ignore non-UDP, too short, or fragmented packets
	if (ip->_proto != IP_PROTO_UDP || (ip->_offset & ~htons(IP_DF)))
		return NULL;

	sport = udp->src;
	dport = udp->dest;
	if (len > lwip_ntohs(udp->len))
		len = lwip_ntohs(udp->len);
	if (len < sizeof(*udp) + 16)
		return NULL;
	memcpy(&spi, (char *)udp + 8, sizeof(spi));
	memcpy(&spi2, (char *)udp + 16, sizeof(spi));

	//	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_sad_lookup_natt", "dest=%lu, sport=%u, dport=%u, table=%p",
	//			addr.addr, lwip_ntohs(sport), lwip_ntohs(dport), table);

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if (addr.addr != entry->addr.addr || !entry->natt_mode || entry->natt_sport != sport || entry->natt_dport != dport)
			continue;

		if (entry->natt_mode == UDP_ENCAP_ESPINUDP_NON_IKE) {
			if (entry->spi == spi2) {
				spi = spi2;
				break;
			}
		}
		else if (entry->natt_mode == UDP_ENCAP_ESPINUDP) {
			if (entry->spi == spi)
				break;
		}
	}
	proc_mutexUnlock(&table->mutex);
	//	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_lookup_natt", "return = %p, spi = %08lx", entry, spi);

	if (entry)
		entry->lifetime.curr_use_time = get_seconds();

	return entry;
}


/**
 * Returns the SPI from an IPsec header out of an IP packet.
 *
 * @param header	pointer to the IP header having an IPsec header as payload
 * @return the SPI if one could be extracted
 * @return 0 if no SPI could be extracted (not IPsec packet)
 */
u32_t ipsec_sad_get_spi(struct ip_hdr *header)
{
	ipsec_in_ip *ptr;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_sad_get_spi", "header=%p", header);

	ptr = (ipsec_in_ip *)header;
	if (IPH_PROTO(&ptr->ip) == IP_PROTO_ESP) {
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", "ptr->inner_header.esp.spi = %lu", ptr->inner_header.esp.spi);
		return ptr->inner_header.esp.spi;
	}

	if (IPH_PROTO(&ptr->ip) == IP_PROTO_AH) {
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", "ptr->inner_header.ah.spi = %lu", ptr->inner_header.ah.spi);
		return ptr->inner_header.ah.spi;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", "return = 0");
	return 0;
}

sad_entry_t *ipsec_sad_check_timeouts(sad_table *table, int *is_soft)
{
	sad_entry_t *entry;
	u32 now = get_seconds();

	*is_soft = 0;  // HARD by default

	//	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsec_sad_lookup", "dest=%lu, proto=%d, spi=%lu, table=%p", addr.addr, proto, spi, table);

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, entry, list)
	{
		if (entry->lifetime.hard_add_expires_seconds) {
			long tmo = entry->lifetime.hard_add_expires_seconds +
				entry->lifetime.curr_add_time - now;
			if (tmo <= 0)
				break;
		}
		if (entry->lifetime.hard_use_expires_seconds) {
			long tmo = entry->lifetime.hard_use_expires_seconds +
				(entry->lifetime.curr_use_time ?: now) - now;
			if (tmo <= 0)
				break;
		}
		if (entry->lifetime.soft_add_expires_seconds) {
			long tmo = entry->lifetime.soft_add_expires_seconds +
				entry->lifetime.curr_add_time - now;
			if (tmo <= 0) {
				*is_soft = 1;
				break;
			}
		}
		if (entry->lifetime.soft_use_expires_seconds) {
			long tmo = entry->lifetime.soft_use_expires_seconds +
				(entry->lifetime.curr_use_time ?: now) - now;
			if (tmo <= 0) {
				*is_soft = 1;
				break;
			}
		}
	}
	proc_mutexUnlock(&table->mutex);
	//	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_lookup", "return = %p", entry);

	return entry;
}

/**
 * Flushes an SPD table and sets a new default entry. The default entry allows to keep
 * a door open for IKE.
 *
 * @param table			pointer to the SPD table
 * @param def_entry 	pointer to the default entry
 * @return IPSEC_STATUS_SUCCESS if the flush was successful
 * @return IPSEC_STATUS_FAILURE if the flush failed
 */
ipsec_status ipsec_spd_flush(spd_table *table, spd_entry_t *def_entry)
{
	proc_mutexLock(&table->mutex);
	while (table->first) {
		LIST_REMOVE(table, table->first, list);
	}
	proc_mutexUnlock(&table->mutex);
	if (ipsec_spd_add(def_entry->src, def_entry->src_mask, def_entry->dest, def_entry->dest_mask,
			def_entry->protocol, def_entry->src_port, def_entry->dest_port, def_entry->policy, 0, table, 0) == NULL)
		return IPSEC_STATUS_FAILURE;

	return IPSEC_STATUS_SUCCESS;
}


void ipsec_spd_dump_log(spd_table *table, const char *pfx)
{
	spd_entry_t *sp;
	unsigned i = 0;

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, sp, list)
	{
		main_printf(ATTR_DEBUG, "%sSPD[%u]: from %08lx/%08lx to %08lx/%08lx tunnel -%08lx sport %u dport %u proto %u %s\n",
			pfx, i++, lwip_ntohl(sp->src), lwip_ntohl(sp->src_mask), lwip_ntohl(sp->dest), lwip_ntohl(sp->dest_mask),
			lwip_ntohl(sp->tunnel_dest), lwip_ntohs(sp->src_port), lwip_ntohs(sp->dest_port), sp->protocol,
			sp->policy == IPSEC_POLICY_IPSEC ? "IPSEC" : sp->policy == IPSEC_POLICY_BYPASS ? "BYPASS" : "DISCARD");
	}
	proc_mutexUnlock(&table->mutex);
}


void ipsec_sad_flush(sad_table *table)
{
	proc_mutexLock(&table->mutex);
	while (table->first) {
		LIST_REMOVE(table, table->first, list);
	}
	proc_mutexUnlock(&table->mutex);
}


void ipsec_sad_dump_log(sad_table *table, const char *pfx)
{
	sad_entry_t *sp;
	unsigned i = 0;

	proc_mutexLock(&table->mutex);
	LIST_FOR_EACH(table, sp, list)
	{
		main_printf(ATTR_DEBUG, "%sSAD[%u]: addr %08lx spi %08lx proto %u mode %s pmtu %u seq %lu win %u lft (S:%u H:%u) nat-t(mode %u port %u,%u) enc %u,%u auth %u%s\n",
			pfx, i++, lwip_ntohl(sp->addr.addr), sp->spi, sp->proto, sp->mode ? "TUNNEL" : "TRANSPORT", sp->path_mtu,
			sp->seqnum, sp->replay_win, sp->lifetime.soft_add_expires_seconds, sp->lifetime.hard_add_expires_seconds, sp->natt_mode,
			lwip_ntohs(sp->natt_sport), lwip_ntohs(sp->natt_dport),
			sp->enc_alg, sp->enckey_len, sp->auth_alg, sp->initiator ? " LARVAL" : "");
	}
	proc_mutexUnlock(&table->mutex);
}

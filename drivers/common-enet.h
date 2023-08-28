#ifndef COMMON_ENET_H_
#define COMMON_ENET_H_


typedef struct
{
	volatile struct enet_regs *mmio;

	struct netif *netif;
	unsigned drv_exit;

#define PRIV_RESOURCES(s) &(s)->irq_lock, 3, ~0x03
	handle_t irq_lock, tx_lock, irq_cond, irq_handle;

	net_bufdesc_ring_t rx, tx;

	addr_t devphys;
	uint32_t mscr;

	char name[32];

	eth_phy_state_t phy;

	uint32_t irq_stack[1024] __attribute__((aligned(16))), mdio_stack[1024];
} enet_priv_t;


void enet_printf(enet_priv_t *state, const char *format, ...);

void enet_reset(enet_priv_t *state);

void enet_start(enet_priv_t *state);

void enet_showCardId(enet_priv_t *state);

size_t enet_nextRxBufferSize(const net_bufdesc_ring_t *ring, size_t i);

int enet_pktRxFinished(const net_bufdesc_ring_t *ring, size_t i);

void enet_fillRxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg);

int enet_nextTxDone(const net_bufdesc_ring_t *ring, size_t i);

void enet_fillTxDesc(const net_bufdesc_ring_t *ring, size_t i, addr_t pa, size_t sz, unsigned seg);

int enet_initRings(enet_priv_t *state);

int enet_irq_handler(unsigned irq, void *arg);

void enet_irq_thread(void *arg);

int enet_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble);

void enet_mdioWait(enet_priv_t *state);

uint16_t enet_mdioIO(enet_priv_t *state, unsigned addr, unsigned reg, unsigned val, int read);

uint16_t enet_mdioRead(void *arg, unsigned addr, uint16_t reg);

void enet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val);

#endif
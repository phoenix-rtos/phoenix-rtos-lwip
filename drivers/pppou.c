/*
 * Phoenix-RTOS --- networking stack
 *
 * PPP over Serial (null modem) driver
 *
 * Copyright 2018, 2021 Phoenix Systems
 * Author: Marek Białowąs, Gerard Świderski
 *
 * %LICENSE%
 */

#include "netif-driver.h"

#include <lwip/dns.h>

#include <netif/ppp/pppapi.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <termios.h>
#include <syslog.h>

/*
 *  Setup full-duplex connection between host and device with RS232, uart USB-TTL adapter, direct TTL-TTL, bluetooth-UART/TTL, etc.
 *
 *  1. On device (phoenix-rtos) side, addr=10.0.0.2, use:
 *     lwip pppou:/dev/uart3:<speed>:up
 *     (speed defaults to 115200 if ommited, optional 'up' brings interface up after setup, optional `nodefault` instructs pppou driver
 *     to not add `default-route`)
 *
 *  2. On host (linux, bsd) side, addr=10.0.0.1, use e.g.:
 *     pppd /dev/ttyUSB0 <speed> 10.0.0.1:10.0.0.2 lock local nodetach noauth debug dump nocrtscts nodefaultroute maxfail 0 holdoff 1
 *
 *  Replace <speed> with any of the baud rate supported by the system, e.g. 9600, 115200, 230400 or 460800.
 */


enum conn_state_e {
	CONN_STATE_DISCONNECTING,
	CONN_STATE_DISCONNECTED,
	CONN_STATE_CONNECTING,
	CONN_STATE_CONNECTED,
};

enum cfg_flag_e {
	CFG_FLAG_DEFAULT_UP = 0x01,
	CFG_FLAG_NO_DEFAULT_ROUTE = 0x02,
};

typedef struct
{
	struct netif *netif;
	ppp_pcb* ppp;

	const char *serial_dev;
	speed_t serial_speed;
	int fd;

	volatile int thread_running;
	volatile int want_connected;
	volatile int conn_state;
	handle_t lock, cond;

	unsigned char main_loop_stack[4096] __attribute__((aligned(8)));
} pppou_priv_t;


#ifdef LOG_ENABLED

#define log_debug(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_at(fmt, ...)    syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)

#else

#define log_debug(fmt, ...)
#define log_at(fmt, ...)
#define log_info(fmt, ...)
#define log_warn(fmt, ...)
#define log_error(fmt, ...)

#endif

#define PPPOU_READ_DATA_TIMEOUT_STEP_MS  10

#define PPPOU_TRYOPEN_SERIALDEV_SEC      3
#define PPPOU_CONNECT_RETRY_SEC          5


/****** serial handling ******/


struct serial_speed_s {
	const char *str;
	speed_t speed;
};


static int _speedcmp(const void *l, const void *r)
{
	return strcmp(((struct serial_speed_s *)l)->str, ((struct serial_speed_s *)r)->str);
}


static speed_t serial_speed_from_string(const char *str)
{
	/* table is lexically sorted by `str` */
	static const struct serial_speed_s stab[] = {
		{ "0", B0 },           { "110", B110 },       { "115200", B115200 },
		{ "1200", B1200 },     { "134", B134 },       { "150", B150 },
		{ "1800", B1800 },     { "19200", B19200 },   { "200", B200 },
		{ "230400", B230400 }, { "2400", B2400 },     { "300", B300 },
		{ "38400", B38400 },   { "460800", B460800 }, { "4800", B4800 },
		{ "50", B50 },         { "57600", B57600 },   { "600", B600 },
		{ "75", B75 },         { "9600", B9600 },
	};

	struct serial_speed_s *sptr;

	if (str && (sptr = bsearch(&str, stab, sizeof(stab) / sizeof(stab[0]), sizeof(stab[0]), _speedcmp)))
		return sptr->speed;

	return -1;
}


static int serial_open(const char *devname, speed_t speed)
{
	oid_t oid;
	int fd, ret, cnt;
	struct termios tio;

	if (!devname)
		return -1;

	/* try if uart is registered */
	for (cnt = 0; (ret = lookup(devname, NULL, &oid)) < 0; cnt++) {
		usleep(200 * 1000);
		if (cnt > 3)
			return ret;
	}

	if ((fd = open(devname, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0)
		return fd;

	memset(&tio, 0, sizeof(tio));

	if ((ret = tcgetattr(fd, &tio)) < 0)
		goto on_error;

	if ((ret = cfsetspeed(&tio, speed)) < 0)
		goto on_error;

	tio.c_cc[VTIME] = 0; /* no timeout */
	tio.c_cc[VMIN] = 0;  /* polling */

	/* libtty does not support yet: IXON|IXOFF|IXANY|PARMRK|INPCK|IGNPAR */
	tio.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	tio.c_oflag &= ~OPOST;
	tio.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	tio.c_cflag &= ~(CSIZE | CSTOPB);

	tio.c_cflag |= CS8 | CREAD | CLOCAL;

	if ((ret = tcflush(fd, TCIOFLUSH)) < 0)
		goto on_error;

	if ((ret = tcsetattr(fd, TCSANOW, &tio)) < 0)
		goto on_error;

	return fd;

on_error:
	close(fd);
	return ret;
}


static void serial_close(int fd)
{
	log_info("close()");

	if (fd >= 0)
		close(fd);
}


#define WRITE_MAX_RETRIES 2
static int serial_write(int fd, const u8_t *data, u32_t len)
{
	int off = 0;
	int retries = 0;
	while (off < len) {
		int to_write = len - off;
		int res = write(fd, data + off, to_write);

		if (res < 0) {
			if (errno == EINTR) {
				/* log_sys_err("%s() : write(%d)\n", __func__, to_write); */
				usleep(5 * 1000);
				continue;
			}
			if (errno == EWOULDBLOCK) {
				goto retry;
			}
			log_error("%s() : write(%d) = %d (%s)", __func__, to_write, errno, strerror(errno));
			return -1;
		}

		/* at least partial-write succeeded */
		off += res;
		retries = 0;
		continue;

retry:
		if (retries >= WRITE_MAX_RETRIES) {
			return off;
		}
		else {
			retries += 1;
			usleep(5 * 1000);
			continue;
		}
	}

	return off;
}


/****** PPPoU support functions ******/


static u32_t pppou_output_cb(ppp_pcb *pcb, u8_t *data, u32_t len, void *ctx)
{
	pppou_priv_t *state = (pppou_priv_t *)ctx;

	log_debug("%s : write(%d)", __func__, len);
	int res = serial_write(state->fd, data, len);
	/* log_debug("%s : write(%d) = %d", __func__, len, res); */
	if (res < 0 && errno != EINTR && errno != EWOULDBLOCK) {
		log_error("%s() : write(%d) = %d (%d -> %s)", __func__, len, res, errno, strerror(errno));
		serial_close(state->fd);
		state->fd = -1;
		return 0;
	}

	return res;
}


static void pppou_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx)
{
#ifdef LOG_ENABLED
	struct netif *pppif = ppp_netif(pcb);
#endif

	pppou_priv_t *state = (pppou_priv_t *)ctx;
	log_debug("%s : status", __func__);
	mutexLock(state->lock);

	switch(err_code) {
		case PPPERR_NONE:               /* No error. */
			{
				state->conn_state = CONN_STATE_CONNECTED;

				log_info("ppp_link_status_cb: PPPERR_NONE");
#if LWIP_IPV4
				log_info("   our_ip4addr = %s", ip4addr_ntoa(netif_ip4_addr(pppif)));
				log_info("   his_ip4addr = %s", ip4addr_ntoa(netif_ip4_gw(pppif)));
				log_info("   netmask     = %s", ip4addr_ntoa(netif_ip4_netmask(pppif)));
#if LWIP_DNS
				log_info("   dns0_addr   = %s", ipaddr_ntoa(dns_getserver(0)));
				log_info("   dns1_addr   = %s", ipaddr_ntoa(dns_getserver(1)));
#endif /* LWIP_DNS */

#endif /* LWIP_IPV4 */
#if LWIP_IPV6
				log_info("   our_ip6addr = %s", ip6addr_ntoa(netif_ip6_addr(pppif, 0)));
#endif /* LWIP_IPV6 */

#if PPP_IPV6_SUPPORT
				log_info("   our6_ipaddr = %s\n\r", ip6addr_ntoa(netif_ip6_addr(pppif, 0)));
#endif /* PPP_IPV6_SUPPORT */
			}
			break;

		case PPPERR_PARAM:             /* Invalid parameter. */
			log_info("ppp_link_status_cb: PPPERR_PARAM");
			/* TODO: error? */
			break;

		case PPPERR_OPEN:              /* Unable to open PPP session. */
			log_info("ppp_link_status_cb: PPPERR_OPEN");
			break;

		case PPPERR_DEVICE:            /* Invalid I/O device for PPP. */
			log_info("ppp_link_status_cb: PPPERR_DEVICE");
			serial_close(state->fd);
			state->fd = -1;
			break;

		case PPPERR_ALLOC:             /* Unable to allocate resources. */
			log_info("ppp_link_status_cb: PPPERR_ALLOC");
			/* TODO: broken */
			break;

		case PPPERR_USER:              /* User interrupt. */
			log_info("ppp_link_status_cb: PPPERR_USER");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_CONNECT:           /* Connection lost. */
			log_info("ppp_link_status_cb: PPPERR_CONNECT");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_AUTHFAIL:          /* Failed authentication challenge. */
			log_info("ppp_link_status_cb: PPPERR_AUTHFAIL");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_PROTOCOL:          /* Failed to meet protocol. */
			log_info("ppp_link_status_cb: PPPERR_PROTOCOL");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_PEERDEAD:          /* Connection timeout. */
			log_info("ppp_link_status_cb: PPPERR_PEERDEAD");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_IDLETIMEOUT:       /* Idle Timeout. */
			log_info("ppp_link_status_cb: PPPERR_IDLETIMEOUT");
			break;

		case PPPERR_CONNECTTIME:       /* Max connect time reached */
			log_info("ppp_link_status_cb: PPPERR_CONNECTTIME");
			state->conn_state = CONN_STATE_DISCONNECTED;
			break;

		case PPPERR_LOOPBACK:          /* Loopback detected */
			log_info("ppp_link_status_cb: PPPERR_LOOPBACK");
			break;

		default:
			log_info("ppp_link_status_cb: unknown error code: %d", err_code);
			break;
	}

	log_info("ppp_link_status_cb out");
	mutexUnlock(state->lock);
	condSignal(state->cond);
}


static void pppou_do_rx(pppou_priv_t *state)
{
	int len;
	u8_t buffer[1024];

	while (state->conn_state != CONN_STATE_DISCONNECTED
			&& state->conn_state != CONN_STATE_DISCONNECTING) {
		len = read(state->fd, buffer, sizeof(buffer));
		if (len > 0) {
			/* Pass received raw characters from PPPoU to be decoded through lwIP
			 * TCPIP thread using the TCPIP API. This is thread safe in all cases
			 * but you should avoid passing data byte after byte. */

			/* log_debug("%s : read() = %d", __func__, len); */
			pppos_input_tcpip(state->ppp, buffer, len);
		}
		else {
			if (len < 0 && errno != EINTR && errno != EWOULDBLOCK) {
				log_error("%s() : read(%d) = %d (%d -> %s)", __func__, sizeof(buffer), len, errno, strerror(errno));
				serial_close(state->fd);
				state->fd = -1;
				state->conn_state = CONN_STATE_DISCONNECTED;
				return;
			}
			usleep(PPPOU_READ_DATA_TIMEOUT_STEP_MS * 1000);
		}
	}

	log_warn("%s: exiting\n", __func__);
}


static void pppou_mainLoop(void *arg)
{
	pppou_priv_t *state = (pppou_priv_t *)arg;

	state->thread_running = 1;

	while (state->thread_running) {
		mutexLock(state->lock);
		while (!state->want_connected) {
			condWait(state->cond, state->lock, 0);
		}
		mutexUnlock(state->lock);

		/* Wait for the serial device */
		if (state->fd < 0) {
			while ((state->fd = serial_open(state->serial_dev, state->serial_speed)) < 0) {
				sleep(PPPOU_TRYOPEN_SERIALDEV_SEC);
			}

			log_info("open %s success!", state->serial_dev);
		}

		log_debug("ppp_connect");
		state->conn_state = CONN_STATE_CONNECTING;
		pppapi_connect(state->ppp, 0);

		log_debug("receiving");
		pppou_do_rx(state);

		log_debug("pppapi_close");
		pppapi_close(state->ppp, 0);

		mutexLock(state->lock);
		log_debug("waiting for close to complete");
		while (state->conn_state != CONN_STATE_DISCONNECTED) {
			condWait(state->cond, state->lock, 0);
			log_debug("still waiting for close to complete");
		}
		mutexUnlock(state->lock);

		log_debug("connection closed");

		serial_close(state->fd);
		state->fd = -1;
		state->conn_state = CONN_STATE_DISCONNECTED;

		sleep(PPPOU_CONNECT_RETRY_SEC);
	}

	/* NOTE: never tested */
	if (state->ppp) {
		pppapi_close(state->ppp, 0);
		pppapi_free(state->ppp);
	}

	endthread();
}


static int pppou_netifUp(pppou_priv_t *state)
{
	mutexLock(state->lock);
	state->want_connected = 1;
	condSignal(state->cond);
	mutexUnlock(state->lock);

	return 0;
}


static int pppou_netifDown(pppou_priv_t *state)
{
	/* Unconditional use of pppapi_close() in the status callback
	 * can (and will) cause recursive firing of the callback */

	mutexLock(state->lock);
	state->conn_state = CONN_STATE_DISCONNECTING;
	state->want_connected = 0;
	mutexUnlock(state->lock);

	return 0;
}


static pppou_priv_t *pppou_netifState(struct netif *netif)
{
	struct netif_alloc *s = (void *)netif;
	pppou_priv_t *state = (void *) ((char *)s + ((sizeof(*s) + (_Alignof(pppou_priv_t) - 1)) & ~(_Alignof(pppou_priv_t) - 1)));
	return state;
}


static void pppou_statusCallback(struct netif *netif)
{
	pppou_priv_t *state = pppou_netifState(netif);

	if (netif->flags & NETIF_FLAG_UP) {
		if (pppou_netifUp(state))
			netif->flags &= ~NETIF_FLAG_UP;
	}
	else if (pppou_netifDown(state)) {
		netif->flags |= NETIF_FLAG_UP;
	}
}


static char *cfg_get_next_arg(char *arg)
{
	if (arg == NULL || *arg == '\0')
		return NULL;

	for (; *arg; arg++) {
		if (*arg == ':') {
			*arg++ = '\0';
			break;
		}
	}

	return arg;
}


static int pppou_netifInit(struct netif *netif, char *cfg)
{
	char *next;
	pppou_priv_t *state;
	int retries, flags = 0;

	if (cfg == NULL || *cfg == '\0') {
		log_error("no config");
		return ERR_IF;
	}

	/*
	 * NOTE: netif->state cannot be used to keep our private state as it is used
	 * by LWiP PPP implementation, pass it as *ctx to callbacks
	 */
	state = netif->state;
	netif->state = NULL;

	memset(state, 0, sizeof(pppou_priv_t));

	state->serial_speed = B115200;
	state->netif = netif;
	state->fd = -1;

	for (; (next = cfg_get_next_arg(cfg)); cfg = next) {
		speed_t speed = serial_speed_from_string(cfg);
		if (speed > 0) {
			state->serial_speed = speed;
			log_info("config speed: %s bps => %d", cfg, speed);
			continue;
		}

		if (!strncmp(cfg, "/dev/", 5)) {
			state->serial_dev = cfg;
			log_info("config device: ", cfg);
			continue;
		}

		if (strcmp(cfg, "up") == 0) {
			flags |= CFG_FLAG_DEFAULT_UP;
			log_info("config up: yes");
			continue;
		}

		if (strcmp(cfg, "nodefault") == 0) {
			flags |= CFG_FLAG_NO_DEFAULT_ROUTE;
			log_info("config no default route: yes");
			continue;
		}

		/* TODO: extend with other flags */
	}

	if (!state->serial_dev) {
		log_error("no device");
		return ERR_IF;
	}

	mutexCreate(&state->lock);
	condCreate(&state->cond);

	/* FIXME: resolve `pp` name conflict with `pppos`
	 * and is required for e.g. netif_is_ppp() */
	netif->name[0] = 'p';
	netif->name[1] = 'p';

	if (!state->ppp) {
		state->ppp = pppapi_pppos_create(state->netif, pppou_output_cb, pppou_link_status_cb, state);

		if (!state->ppp) {
			log_error("could not create PPP control interface");
			return ERR_IF; /* TODO: maybe permanent broken state? */
		}
		netif->flags &= ~NETIF_FLAG_UP;
		ppp_set_netif_statuscallback(state->ppp, pppou_statusCallback);
#if LWIP_DNS
		ppp_set_usepeerdns(state->ppp, 1);
#endif /* LWIP_DNS */
		if (!(flags & CFG_FLAG_NO_DEFAULT_ROUTE))
			ppp_set_default(state->ppp);
	}

	beginthread(pppou_mainLoop, 4, (void *)state->main_loop_stack, sizeof(state->main_loop_stack), state);

	/* FIXME: (imxrt106x) the below blocking loop is temporary
	 * because of lack of real ifconfig on the target platform
	 */
	for (retries = 3; retries > 0; retries--) {
		/* wait until thread started */
		if (!state->thread_running) {
			sleep(1);
			continue;
		}

		if (flags & CFG_FLAG_DEFAULT_UP) {
			log_info("pppou netif up");
			netif_set_up(netif);
		}

		break;
	}

	return ERR_OK;
}


const char *pppou_media(struct netif *netif)
{
	return "null-modem";
}


static netif_driver_t pppou_drv = {
	.init = pppou_netifInit,
	.state_sz = sizeof(pppou_priv_t),
	.state_align = _Alignof(pppou_priv_t),
	.name = "pppou",
	.media = pppou_media,
};


__constructor__(1000)
void register_driver_pppou(void)
{
	register_netif_driver(&pppou_drv);
}

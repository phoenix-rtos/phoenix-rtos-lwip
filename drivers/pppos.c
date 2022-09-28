/*
 * Phoenix-RTOS --- networking stack
 *
 * PPP over Serial driver
 *
 * Copyright 2018, 2021 Phoenix Systems
 * Author: Marek Białowąs, Maciej Purski
 *
 * %LICENSE%
 */

#include "netif-driver.h"

#include <netif/ppp/pppapi.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <sys/threads.h>
#include <sys/msg.h>
#include <syslog.h>
#include <termios.h>

#include <pppos_modem.h>

enum {
	CONN_STATE_DISCONNECTING,
	CONN_STATE_DISCONNECTED,
	CONN_STATE_CONNECTING,
	CONN_STATE_CONNECTED,
};

enum {
	CFG_FLAG_DEFAULT_UP = 0x01,
	CFG_FLAG_NO_DEFAULT_ROUTE = 0x02,
	CFG_FLAG_NO_DNS = 0x04,
};

typedef struct
{
	struct netif *netif;
	ppp_pcb* ppp;

	const char *serialdev_fn;
	const char *serialat_fn;
#if PPPOS_USE_CONFIG_FILE
	const char *config_path;
	char apn[64];
#endif
	int fd;

	volatile int thread_running;
	volatile int want_connected;
	volatile int conn_state;
	handle_t lock, cond;

	uint32_t main_loop_stack[4096];
} pppos_priv_t;

#define COL_RED     "\033[1;31m"
#define COL_CYAN    "\033[1;36m"
#define COL_YELLOW  "\033[1;33m"
#define COL_NORMAL  "\033[0m"

#if 0
#define log_debug(fmt, ...)     do { if (1) pppos_printf(state, fmt, ##__VA_ARGS__); } while (0)
#define log_at(fmt, ...)     	do { if (1) pppos_printf(state, COL_CYAN fmt COL_NORMAL, ##__VA_ARGS__); } while (0)
#define log_info(fmt, ...)      do { if (1) pppos_printf(state, COL_CYAN fmt COL_NORMAL, ##__VA_ARGS__); } while (0)
#define log_warn(fmt, ...)      do { if (1) pppos_printf(state, COL_YELLOW fmt COL_NORMAL, ##__VA_ARGS__); } while (0)
#define log_error(fmt, ...)     do { if (1) pppos_printf(state, COL_RED  fmt COL_NORMAL, ##__VA_ARGS__); } while (0)

static void pppos_printf(pppos_priv_t *state, const char *format, ...)
{
	char buf[256];
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, sizeof(buf), format, arg);
	va_end(arg);

	printf("lwip: ppp@%s %s\n", state->serialdev_fn, buf);
}
#else

#define log_debug(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_at(fmt, ...)    syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)

#endif

#define PPPOS_READ_AT_TIMEOUT_STEP_MS 		5
#define PPPOS_READ_DATA_TIMEOUT_STEP_MS 	10

#define PPPOS_TRYOPEN_SERIALDEV_SEC 		3
#define PPPOS_CONNECT_RETRY_SEC 		5
#define PPPOS_CONNECT_CMD_RETRY_MS		500

/****** serial handling ******/

static void serial_close(int fd)
{
	log_info("close()");

	if (fd >= 0)
		close(fd);

//	state->fd = -1;
	// NOTE: set DISCONNECTED in status callback
	// state->conn_state = CONN_STATE_DISCONNECTED;
}

static void serial_set_non_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		log_error("%s() : fcntl(%d, O_NONBLOCK) = (%d -> %s)", __func__, fd, errno, strerror(errno));
}

#if 0
static void serial_set_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0)
		log_error("%s() : fcntl(%d, ~O_NONBLOCK) = (%d -> %s)", __func__, fd, errno, strerror(errno));
}
#endif

#define WRITE_MAX_RETRIES 2
static int serial_write(int fd, const u8_t* data, u32_t len)
{
	int off = 0;
	int retries = 0;
	while (off < len) {
		int to_write = len - off;
		int res = write(fd, data + off, to_write);

		if (res < 0) {
			if (errno == EINTR) {
				//log_sys_err("%s() : write(%d)\n", __func__, to_write);
				usleep(5*1000);
				continue;
			}
			if (errno == EWOULDBLOCK) {
				goto retry;
			}
			log_error("%s() : write(%d) = %d (%s)", __func__, to_write, errno, strerror(errno));
			return -1;
		}

		// at least partial-write succeeded
		off += res;
		retries = 0;
		continue;

retry:
		if (retries >= WRITE_MAX_RETRIES) {
			return off;
		} else {
			retries += 1;
			usleep(5*1000);
			continue;
		}
	}

	return off;
}

/****** AT commands support ******/

// AT commands result codes
enum {
	AT_RESULT_OK,
	AT_RESULT_CONNECT,
	AT_RESULT_RING,
	AT_RESULT_NO_CARRIER,
	AT_RESULT_ERROR,
	AT_RESULT_NO_ANSWER
};

static const char* at_result_codes[] = { "OK", "CONNECT", "RING", "NO CARRIER", "ERROR", "NO ANSWER", NULL };
static int at_result_codes_len = sizeof(at_result_codes) / sizeof(at_result_codes[0]);

static int at_check_result(const char* buf)
{
	int res = 0;
	char* result;

	while (at_result_codes[res]) {
		if ((result = strstr(buf, at_result_codes[res])) != NULL) {
			return res;
		}
		res += 1;
	}

	return -1;
}

static const char * at_result_to_str(int res) {
	if (res < 0 || res >= at_result_codes_len)
		return "!INVALID!";

	return at_result_codes[res];
}


static int at_send_cmd_res(int fd, const char* cmd, int timeout_ms, char *rx_buf, int rx_bufsize)
{
	int max_len = rx_bufsize - 1;
	char *end;

	if (fd < 0) {
		log_error("%s: invalid file descriptor!", __func__);
		return ERR_ARG;
	}

	serial_write(fd, (u8_t*)cmd, strlen(cmd));
	end = strstr(cmd, "\r\n");
	/* remove newlines for better result printing */
	log_at("AT Tx: [%*s]", (end != NULL) ? end - cmd : strlen(cmd), cmd);

	// wait for result with optional response text
	int off = 0;
	while (off < max_len) {
		int len = read(fd, rx_buf + off, max_len - off);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK)
				goto retry;
			log_error("%s() : read(%d) = %d (%d -> %s)", __func__, max_len - off, len, errno, strerror(errno));
			serial_close(fd);
			return -1;
		} else if (len == 0) {
			log_error("%s() : read(%d) = %d (%d -> %s)", __func__, max_len - off, len, errno, strerror(errno));
			serial_close(fd);
			return -1;
		} else {
			rx_buf[off + len] = '\0';

			int res = at_check_result(rx_buf);
			off += len;

			if (res >= 0) {
#if 1
				// remove newlines for better result printing
				for (int i = 0; i < off; ++i)
					if (rx_buf[i] == '\n' || rx_buf[i] == '\r')
						rx_buf[i] = '.';
#endif
				log_at("AT Rx: result=[%s] data=[%s]", at_result_to_str(res), rx_buf);
				return res;
			}

		}
		continue;

retry:
		usleep(PPPOS_READ_AT_TIMEOUT_STEP_MS * 1000);
		if (timeout_ms >= 0) {
			timeout_ms -= PPPOS_READ_AT_TIMEOUT_STEP_MS;
			if (timeout_ms <= 0) {
				log_warn("%s: timeouted while waiting for response!", __func__);
				return -1;
			}
		}
	}

	log_warn("%s: AT response too large", __func__);
	return -1;
}


static int at_send_cmd(int fd, const char* cmd, int timeout_ms)
{
	char rx_buf[512];
	return at_send_cmd_res(fd, cmd, timeout_ms, rx_buf, sizeof(rx_buf));
}


// NOTE: this only disconnects the AT modem from the data connection
// Currently only used in initialisation
#if PPPOS_DISCONNECT_ON_INIT
static int at_disconnect(int fd)
{
	int res;
	int retries = 3;
	do {
		/* send AT check command before trying to escape PPP */
		if (at_send_cmd(fd, "AT\r\n", 3000) != AT_RESULT_OK) {
			serial_write(fd, (u8_t *)"+++", 3);
			usleep(1000 * 1000);
		}
		res = at_send_cmd(fd, AT_DISCONNECT_CMD, 3000);
	} while (res != AT_RESULT_OK && --retries);

	return res;
}
#endif

static int at_is_responding(int fd, int timeout_ms)
{
	int res;
	int retry = 5;
	while ((res = at_send_cmd(fd, "AT\r\n", timeout_ms)) != AT_RESULT_OK && retry--);

	if (res != AT_RESULT_OK) {
		log_warn("modem not responding, res=%d", res);
		return 0;
	}

	return 1;
}


/****** PPPoS support functions ******/

static u32_t pppos_output_cb(ppp_pcb *pcb, u8_t *data, u32_t len, void *ctx)
{
	pppos_priv_t* state = (pppos_priv_t*) ctx;

	int res = serial_write(state->fd, data, len);
	//log_debug("%s : write(%d) = %d", __func__, len, res);
	if (res < 0 && errno != EINTR && errno != EWOULDBLOCK) {
		log_error("%s() : write(%d) = %d (%d -> %s)", __func__, len, res, errno, strerror(errno));
		serial_close(state->fd);
		state->fd = -1;
		return 0;
	}

	return res;
}

static void pppos_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx)
{
	struct netif *pppif = ppp_netif(pcb);
	pppos_priv_t* state = (pppos_priv_t*) ctx;
	mutexLock(state->lock);

	switch(err_code) {
	case PPPERR_NONE:               /* No error. */
		{
			state->conn_state = CONN_STATE_CONNECTED;

			log_info("ppp_link_status_cb: PPPERR_NONE");
#if LWIP_IPV4
			log_info("   our_ip4addr = %s", ip4addr_ntoa(netif_ip4_addr(pppif)));
			log_info("   his_ipaddr  = %s", ip4addr_ntoa(netif_ip4_gw(pppif)));
			log_info("   netmask     = %s", ip4addr_ntoa(netif_ip4_netmask(pppif)));
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
		// TODO: error?
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
		//TODO: broken
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

static void pppos_do_rx(pppos_priv_t* state)
{
	int len;
	u8_t buffer[1024];

	while (state->conn_state != CONN_STATE_DISCONNECTED
			&& state->conn_state != CONN_STATE_DISCONNECTING) {
		len = read(state->fd, buffer, sizeof(buffer));
		if (len > 0) {
			/* Pass received raw characters from PPPoS to be decoded through lwIP
			* TCPIP thread using the TCPIP API. This is thread safe in all cases
			* but you should avoid passing data byte after byte. */
			//log_debug("%s : read() = %d", __func__, len);
			pppos_input_tcpip(state->ppp, buffer, len);
		} else {
			if (len < 0 && errno != EINTR && errno != EWOULDBLOCK) {
				log_error("%s() : read(%d) = %d (%d -> %s)", __func__, sizeof(buffer), len, errno, strerror(errno));
				serial_close(state->fd);
				state->fd = -1;
				return;
			}
			usleep(PPPOS_READ_DATA_TIMEOUT_STEP_MS * 1000);
		}
	}

	log_warn("%s: exiting\n", __func__);
}


static void pppos_mainLoop(void* _state)
{
	pppos_priv_t* state = (pppos_priv_t*) _state;
	int res;
	int retries;

	int running = 1;

	state->thread_running = 1;
	while (running) {
		mutexLock(state->lock);
		while (!state->want_connected) {
			condWait(state->cond, state->lock, 0);
		}
		mutexUnlock(state->lock);

		/* Wait for the serial device */
		if (state->fd < 0)  {
			while ((state->fd = open(state->serialdev_fn, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0)
				sleep(PPPOS_TRYOPEN_SERIALDEV_SEC);

			log_info("open success!");
		}

		serial_set_non_blocking(state->fd);
#if PPPOS_DISCONNECT_ON_INIT
		if (at_disconnect(state->fd) != AT_RESULT_OK)
			goto fail;
#endif

#if PPPOS_USE_CONFIG_FILE
		mutexLock(state->lock);
		while (!state->apn[0])
			condWait(state->cond, state->lock, 0);
		mutexUnlock(state->lock);
#endif

		if (!at_is_responding(state->fd, 1000)) {
			goto fail;
		}
		const char** at_cmd = at_init_cmds;
		while (*at_cmd) {
			if ((res = at_send_cmd(state->fd, *at_cmd, AT_INIT_CMDS_TIMEOUT_MS)) != AT_RESULT_OK) {
				log_warn("failed to initialize modem (cmd=%s), res=%d, retrying", *at_cmd, res);
				goto fail;
			}

			at_cmd += 1;
		}

#if PPPOS_USE_CONFIG_FILE
		{ /* Configure APN */
			char at_set_apn[256];
			if (snprintf(at_set_apn, sizeof(at_set_apn), "AT+CGDCONT=1,\"IP\",\"%s\"\r\n", state->apn) >= sizeof(at_set_apn)) {
				log_error("APN name too long");
				goto fail;
			}

			if ((res = at_send_cmd(state->fd, at_set_apn, 3000)) != AT_RESULT_OK) {
				log_warn("failed to set APN, retrying");
				goto fail;
			}
		}
#endif

		/* Some modems hanging on AT_CONNECT_CMD, some returning error when not ready yet.
		 * Retrying until receive AT_RESULT_CONNECT or standard timeout is reached (res < 0)
		 */
		retries = AT_CONNECT_CMD_TIMEOUT_MS / PPPOS_CONNECT_CMD_RETRY_MS;
		while ((res = at_send_cmd(state->fd, AT_CONNECT_CMD, AT_CONNECT_CMD_TIMEOUT_MS)) != AT_RESULT_CONNECT) {
			if (retries-- <= 0 || res < 0) {
				log_warn("failed to dial PPP, res=%d, retrying", res);
				goto fail;
			}
			usleep(PPPOS_CONNECT_CMD_RETRY_MS * 1000);
		}

		log_debug("ppp_connect");
		state->conn_state = CONN_STATE_CONNECTING;
		pppapi_connect(state->ppp, 0);

		//serial_set_blocking(state);
		log_debug("receiving");
		pppos_do_rx(state);

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

fail:
		serial_close(state->fd);
		state->fd = -1;

		sleep(PPPOS_CONNECT_RETRY_SEC);
	}

	// NOTE: never tested
	if (state->ppp) {
		pppapi_close(state->ppp, 0);
		pppapi_free(state->ppp);
	}

	endthread();
}


static int pppos_netifUp(pppos_priv_t *state)
{
#if PPPOS_USE_CONFIG_FILE
	char lcfg[256] = { 0 };
	int line = 0;
	FILE *fcfg = fopen(state->config_path, "r");
	char *cfgval;
	char *eq;

	if (fcfg == NULL)
		return 1;

	if (state->apn[0]) {
		fclose(fcfg);
		return 0;
	}

	mutexLock(state->lock);
	while (fgets(lcfg, sizeof(lcfg), fcfg) != NULL) {
		line++;
		if (lcfg[0] == '#')
			continue;

		if ((eq = strchr(lcfg, '=')) == NULL) {
			log_error("[line %d] invalid format - missing '='", line);
			continue;
		}

		lcfg[strcspn(lcfg, "\r\n")] = 0;

		*eq = 0;
		cfgval = eq + 1;

		if (cfgval[0] == '"' || cfgval[0] == '\'') {
			cfgval++;
			cfgval[strlen(cfgval) - 1] = 0;
		}

		if (!strcasecmp(lcfg, "apn"))
			strncpy(state->apn, cfgval, sizeof(state->apn) - 1);
		else
			log_warn("[line %d] unsupported option: %s (val: %s)", line, lcfg, cfgval);
	}

	fclose(fcfg);
#else
	mutexLock(state->lock);
#endif
	state->want_connected = 1;
	condSignal(state->cond);
	mutexUnlock(state->lock);

	return 0;
}


static int pppos_netifDown(pppos_priv_t *state)
{
	/* Unconditional use of pppapi_close() in the status callback
	can (and will) cause recursive firing of the callback */

	mutexLock(state->lock);
#if PPPOS_USE_CONFIG_FILE
	if (state->apn[0]) {
		state->apn[0] = 0;
		state->conn_state = CONN_STATE_DISCONNECTING;
	}
#else
	state->conn_state = CONN_STATE_DISCONNECTING;
#endif
	state->want_connected = 0;
	mutexUnlock(state->lock);

	return 0;
}


static pppos_priv_t *pppos_netifState(struct netif *netif)
{
	struct netif_alloc *s = (void *)netif;
	pppos_priv_t *state = (void *) ((char *)s + ((sizeof(*s) + (_Alignof(pppos_priv_t) - 1)) & ~(_Alignof(pppos_priv_t) - 1)));
	return state;
}


static void pppos_statusCallback(struct netif *netif)
{
	pppos_priv_t *state = pppos_netifState(netif);

	if (netif->flags & NETIF_FLAG_UP) {
		if (pppos_netifUp(state))
			netif->flags &= ~NETIF_FLAG_UP;
	} else if (pppos_netifDown(state)) {
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


static int pppos_netifInit(struct netif *netif, char *cfg)
{
	pppos_priv_t* state;
	int retries, flags = 0;
	char *next;

	// NOTE: netif->state cannot be used to keep our private state as it is used by LWiP PPP implementation, pass it as *ctx to callbacks
	state = netif->state;
	netif->state = NULL;

	memset(state, 0, sizeof(pppos_priv_t));
	state->netif = netif;
	state->serialdev_fn = cfg;
	state->serialat_fn = "/dev/ttyacm1";
	state->fd = -1;

#if PPPOS_USE_CONFIG_FILE
	state->config_path = cfg;
#endif

	for (; (next = cfg_get_next_arg(cfg)); cfg = next) {
		if (!strncmp(cfg, "/dev/", 5)) {
			state->serialat_fn = cfg;
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

		if (strcmp(cfg, "nodns") == 0) {
			flags |= CFG_FLAG_NO_DNS;
			log_info("config no DNS: yes");
			continue;
		}
	}

	mutexCreate(&state->lock);
	condCreate(&state->cond);

	netif->name[0] = 'p';
	netif->name[1] = 'p';

	if (!cfg)
		return ERR_ARG;

	if (!state->ppp) {
		state->ppp = pppapi_pppos_create(state->netif, pppos_output_cb, pppos_link_status_cb, state);

		if (!state->ppp) {
			log_error("could not create PPP control interface");
			return ERR_IF ; // TODO: maybe permanent broken state?
		}
		netif->flags &= ~NETIF_FLAG_UP;
		ppp_set_netif_statuscallback(state->ppp, pppos_statusCallback);
		if (!(flags & CFG_FLAG_NO_DEFAULT_ROUTE))
			ppp_set_default(state->ppp);

#if LWIP_DNS
		if (!(flags & CFG_FLAG_NO_DNS))
			ppp_set_usepeerdns(state->ppp, 1);
#endif /* LWIP_DNS */

#if PPPOS_USE_AUTH
		ppp_set_auth(state->ppp, PPPOS_AUTH_TYPE, PPPOS_AUTH_USER, PPPOS_AUTH_PASSWD);
#endif /* PPPOS_USE_AUTH */
	}

	beginthread(pppos_mainLoop, 4, (void *)state->main_loop_stack, sizeof(state->main_loop_stack), state);

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


const char *pppos_media(struct netif *netif)
{
	pppos_priv_t *state = pppos_netifState(netif);
	int fd = open(state->serialat_fn, O_RDWR | O_NONBLOCK);
	char buffer[256];
	int result;

	if (fd < 0)
		return "error/open";

	if ((result = at_send_cmd_res(fd, "AT+COPS?\r\n", 300, buffer, sizeof(buffer))) != AT_RESULT_OK)
		return "error/read";

	close(fd);

	if (strstr(buffer, "\",0") != NULL)
		return "2G";
	else if (strstr(buffer, "\",2") != NULL)
		return "3G";
	else if (strstr(buffer, "\",7") != NULL || strstr(buffer, "\",9") != NULL)
		return "4G";
	else
		return "unrecognized";
}


static netif_driver_t pppos_drv = {
	.init = pppos_netifInit,
	.state_sz = sizeof(pppos_priv_t),
	.state_align = _Alignof(pppos_priv_t),
	.name = "pppos",
	.media = pppos_media,
};


__constructor__(1000)
void register_driver_pppos(void)
{
	register_netif_driver(&pppos_drv);
}

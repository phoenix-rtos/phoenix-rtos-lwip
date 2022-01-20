#ifndef INCLUDED_NVRAM_IMAGE_H_
#define INCLUDED_NVRAM_IMAGE_H_

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Character array of NVRAM image
 * Generated from brcmfmac43439-sdio_210707.txt
 */
static const char aw_nm512_wifi_nvram_image[] =
	"NVRAMRev=$Rev$\0"
	"manfid=0x2d0\0"
	"prodid=0x0727\0"
	"vendid=0x14e4\0"
	"devid=0x43e2\0"
	"boardtype=0x0887\0"
	"boardrev=0x1102\0"
	"boardnum=22\0"
	"sromrev=11\0"
	"boardflags=0x00404001\0"
	"boardflags3=0x08000000\0"
	"xtalfreq=26000\0"
	"nocrc=1\0"
	"ag0=255\0"
	"aa2g=1\0"
	"ccode=ALL\0"
	"rssicorrnorm=0\0"
	"pa0itssit=0x20\0"
	"extpagain2g=0\0"
	"pa2ga0=-155,6912,-779\0"
	"AvVmid_c0=0x0,0xc8\0"
	"cckpwroffset0=5\0"
	"maxp2ga0=78\0"
	"txpwrbckof=6\0"
	"cckbw202gpo=0\0"
	"legofdmbw202gpo=0x44444444\0"
	"mcsbw202gpo=0x66666666\0"
	"propbw202gpo=0xdd\0"
	"ofdmdigfilttype=18\0"
	"ofdmdigfilttypebe=18\0"
	"papdmode=1\0"
	"papdvalidtest=1\0"
	"pacalidx2g=45\0"
	"papdepsoffset=-30\0"
	"papdendidx=58\0"
	"wl0id=0x431b\0"
	"deadman_to=0xffffffff\0"
	"muxenab=0x1\0"
	"spurconfig=0x3\0"
	"glitch_based_crsmin=1\0"
	"btc_mode=0\0"
	"bt_default_ant=0\0"
	"edonthd20l=-72\0"
	"edoffthd20ul=-78\0"
	"\0\0";


/**
 * Character array of NVRAM image
 * Generated from brcmfmac43430-sdio-etsi.txt
 */

static const char sterling_lwb_wifi_nvram_image[] =
	"manfid=0x2d0\0"
	"prodid=0x0726\0"
	"vendid=0x14e4\0"
	"devid=0x43e2\0"
	"boardtype=0x0726\0"
	"boardrev=0x1101\0"
	"boardnum=22\0"
	"sromrev=11\0"
	"boardflags=0x00404201\0"
	"boardflags3=0x08000000\0"
	"xtalfreq=37400\0"
	"nocrc=1\0"
	"ag0=255\0"
	"aa2g=1\0"
	"ccode=ALL\0"
	"regrev=0\0"
	"pa0itssit=0x20\0"
	"extpagain2g=0\0"
	"pa2ga0=-168,7161,-820\0"
	"AvVmid_c0=0x0,0xc8\0"
	"cckpwroffset0=5\0"
	"maxp2ga0=0x54\0"
	"txpwrbckof=6\0"
	"cckbw202gpo=0\0"
	"legofdmbw202gpo=0x66111111\0"
	"mcsbw202gpo=0x77711111\0"
	"propbw202gpo=0xdd\0"
	"ofdmdigfilttype=18\0"
	"ofdmdigfilttypebe=18\0"
	"papdmode=1\0"
	"papdvalidtest=1\0"
	"pacalidx2g=32\0"
	"papdepsoffset=-36\0"
	"papdendidx=61\0"
	"wl0id=0x431b\0"
	"muxenab=0x11\0"
	"spurconfig=0x3\0"
	"\0\0";

#ifdef __cplusplus
} /*extern "C" */
#endif

#else /* ifndef INCLUDED_NVRAM_IMAGE_H_ */

#error Wi-Fi NVRAM image included twice

#endif /* ifndef INCLUDED_NVRAM_IMAGE_H_ */

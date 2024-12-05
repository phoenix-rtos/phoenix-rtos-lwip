# lwIP network server for Phoenix-RTOS


## Run

```bash
netsrv driver [driver...]
```

where *driver* is one of:

1. RTL8139C+ (eg. as emulated by qemu)

	rtl:pcidev:irq

	pcidev = (bus << 8) | (dev << 3) | (fn << 0)

For qemu, it's usually: `rtl:0x10:10`

2. iMX ENET module (== "Freescale Ethernet Controller"?)

	enet:mmio:irq[:no-mdio][:phyinfo]

`no-mdio` disables MDIO support (only one module can drive MDIO bus)

When an external PHY is used, *phyinfo* is formatted as follows:

	PHY:model:[busnr.]id[:reset:[-]n:/dev/gpioX][:irq:[-]n:/dev/gpioX]

model = PHY chip model in lowercase, e.g. `ksz8081rnb`

busnr = bus registered by driver (in driver-arg-order, counted from 0)

id = PHY address

reset/irq: GPIO descriptors:

minus = signal is active-low

n = pin number

/dev/gpioX = GPIO bank driver node

(When GPIOs are used, gpiosrv must be already running.)

iMX.6ULL's evaluation board needs:
```
enet:0x02188000:150:PHY:ksz8081rnb:0.2:irq:5:/dev/gpio5 enet:0x020b4000:152:no-mdio:PHY:ksz8081rnb:0.1:irq:6:/dev/gpio5
```

iMX.RT1064's evaluation board needs:
```
enet:0x402D8000:130:PHY:ksz8081rnb:0.2:irq:-10:/dev/gpio1:reset:-9:/dev/gpio1
```

## Build

```bash
make TARGET=target
```

where *target* matches kernel/libphoenix TARGET value.


## License

This work is licensed under a BSD license. See the LICENSE file for details.

SPDX-License-Identifier: BSD-3-Clause

/*
 * Phoenix-RTOS --- networking stack
 *
 * TDA4VM enet register definitions
 * 
 * Based on J721E DRA829/TDA4VM/AM68P Processors Silicon Revision 1.1
 *
 * Copyright 2025 Phoenix Systems
 * Author: Rafał Mikielis
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef NET_TDM4VA_REGS
#define NET_TDM4VA_REGS

#include <stdint.h>

#define SIZE(start, end)       (uint32_t)((end - start)/sizeof(uint32_t))

#define PLLCTRL0_BASE_ADDR                 0x00410000
#define MAIN_PLL_BASE_ADDR                 0x00680000
#define INTR_ROUTER_MAIN2MCU_LVL_BASE_ADDR 0x00a10000
#define INTR_ROUTER_MAIN2MCU_PLS_BASE_ADDR 0x00a20000
#define INTR_ROUTER_MCU_NAVSS0_BASE_ADDR   0x28540000
#define INTR_ROUTER_NAVSS0_BASE_ADDR       0x310e0000
#define MCU_PLL_BASE_ADDR                  0x40d00000
#define CTRLMMR_MCU_BASE_ADDR              0x40f00000
#define MCU_ARMSS_RAT_BASE_ADDR            0x40f90000
#define WKUP_PLLCTRL0_BASE_ADDR            0x42010000
#define INTR_ROUTER_WKUP_GPIOMUX_BASE_ADDR 0x42200000
#define CTRLMMR_WKUP_BASE_ADDR             0x43000000

#define MCU_CTRL_MMR0_BASE              0x40f00000
#define MCU_CPSW0_NUSS_CONTROL_BASE     0x46000000
#define MCU_CPSW0_ECC_BASE              0x40709000

#define MCU_CPSW0_CPINT_OFF     0x01000
#define MCU_CPSW0_CONTROL_OFF   0x20000
#define MCU_CPSW0_ALE_OFF       0x3e000
#define MCU_CPSW0_CPTS_OFF      0x3d000
#define MCU_CPSW0_MDIO_OFF      0x00f00
#define MCU_CPSW0_STAT0_OFF     0x3a000
#define MCU_CPSW0_STAT1_OFF     0x3a200

#define MCU_CPSW0_NUSS_CPINT_ADDR    ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_CPINT_OFF))
#define MCU_CPSW0_NUSS_CONTROL_ADDR  ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_CONTROL_OFF))
#define MCU_CPSW0_NUSS_ALE_ADDR      ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_ALE_OFF))
#define MCU_CPSW0_NUSS_CPTS_ADDR     ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_CPTS_OFF))   
#define MCU_CPSW0_NUSS_MDIO_ADDR     ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_MDIO_OFF))   
#define MCU_CPSW0_NUSS_STAT0_ADDR    ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_STAT0_OFF))  
#define MCU_CPSW0_NUSS_STAT1_ADDR    ((MCU_CPSW0_NUSS_CONTROL_BASE + MCU_CPSW0_STAT1_OFF))  



 struct MCU_CTRL_MMR0 {

    uint32_t CTRLMMR_MCU_PID;                    /* Peripheral Identification Register 0x2000h */
    uint32_t __RESERVED0[SIZE(0x2004, 0x2008)];
    uint32_t CTRLMMR_MCU_MMR_CFG1;               /* Configuration register 1 0x2008h */
    uint32_t __RESERVED1[SIZE(0x200C, 0x2100)];
    uint32_t CTRLMMR_MCU_IPC_SET0;               /* IPC Generation Register 0 0x2100h */
    uint32_t CTRLMMR_MCU_IPC_SET1;               /* IPC Generation Register 1 0x2104h */
    uint32_t __RESERVED2[SIZE(0x2108, 0x2120)];
    uint32_t CTRLMMR_MCU_IPC_SET8;               /* IPC Generation Register 8 0x2120h */
    uint32_t __RESERVED3[SIZE(0x2124, 0x2180)];
    uint32_t CTRLMMR_MCU_IPC_CLR0;               /* IPC Acknowledge Register 0 0x2180h */
    uint32_t CTRLMMR_MCU_IPC_CLR1;               /* IPC Acknowledge Register 1 0x2184h */
    uint32_t __RESERVED4[SIZE(0x2188, 0x21A0)];
    uint32_t CTRLMMR_MCU_IPC_CLR8;               /* IPC Acknowledge Register 8 0x21A0h */
    uint32_t __RESERVED5[SIZE(0x21A4, 0x2200)];
    uint32_t CTRLMMR_MCU_MAC_ID0;                /* MAC Address Lo register 0x2200h */
    uint32_t CTRLMMR_MCU_MAC_ID1;                /* MAC Address Hi Register 0x2204h */
    uint32_t __RESERVED6[SIZE(0x2208, 0x3008)];
    uint32_t CTRLMMR_MCU_LOCK0_KICK0;            /* Partition 0 Lock Key 0 Register 0x3008h */
    uint32_t CTRLMMR_MCU_LOCK0_KICK1;            /* Partition 0 Lock Key 1 Register 0x300Ch */
    uint32_t CTRLMMR_MCU_INTR_RAW_STAT;          /* Interrupt Raw Status Register 0x3010h */
    uint32_t CTRLMMR_MCU_INTR_STAT_CLR;          /* Interrupt Status and Clear Register 0x3014h */
    uint32_t CTRLMMR_MCU_INTR_EN_SET;            /* Interrupt Enable Set Register 0x3018h */
    uint32_t CTRLMMR_MCU_INTR_EN_CLR;            /* Interrupt Enable Clear Register 0x301Ch */
    uint32_t CTRLMMR_MCU_EOI;                    /* End of Interrupt Register 0x3020h */
    uint32_t CTRLMMR_MCU_FAULT_ADDR;             /* Fault Address Register 0x3024h */
    uint32_t CTRLMMR_MCU_FAULT_TYPE;             /* Fault Type Register 0x3028h */
    uint32_t CTRLMMR_MCU_FAULT_ATTR;             /* Fault Attribute Register 0x302Ch */
    uint32_t CTRLMMR_MCU_FAULT_CLR;              /* Fault Clear Register 0x3030h */
    uint32_t __RESERVED7[SIZE(0x3034, 0x3100)];
    uint32_t CTRLMMR_MCU_P0_CLAIM0;              /* Partition 0 Claim Register 0 0x3100h */
    uint32_t CTRLMMR_MCU_P0_CLAIM1;              /* Partition 0 Claim Register 1 0x3104h */
    uint32_t CTRLMMR_MCU_P0_CLAIM2;              /* Partition 0 Claim Register 2 0x3108h */
    uint32_t CTRLMMR_MCU_P0_CLAIM3;              /* Partition 0 Claim Register 3 0x310Ch */
    uint32_t CTRLMMR_MCU_P0_CLAIM4;              /* Partition 0 Claim Register 4 0x3110h */
    uint32_t __RESERVED8[SIZE(0x3114, 0x6030)];
    uint32_t CTRLMMR_MCU_MSMC_CFG;               /* MSMC Configuration Register 0x6030h */
    uint32_t __RESERVED9[SIZE(0x6034, 0x6040)];
    uint32_t CTRLMMR_MCU_ENET_CTRL;              /* MCU Ethernet Port1 Control Register 0x6040h */
    uint32_t __RESERVED10[SIZE(0x6044, 0x6060)];
    uint32_t CTRLMMR_MCU_SPI1_CTRL;              /* MCU SPI1 Conectivity Control Register 0x6060h */
    uint32_t __RESERVED11[SIZE(0x6064, 0x6070)];
    uint32_t CTRLMMR_MCU_I3C0_CTRL0;             /* MCU I3C0 Control Register 0 0x6070h */
    uint32_t CTRLMMR_MCU_I3C0_CTRL1;             /* MCU I3C0 Control Register 1 0x6074h */
    uint32_t CTRLMMR_MCU_I3C1_CTRL0;             /* MCU I3C1 Control Register 0 0x6078h */
    uint32_t CTRLMMR_MCU_I3C1_CTRL1;             /* MCU I3C1 Control Register 1 0x607Ch */
    uint32_t CTRLMMR_MCU_I2C0_CTRL;              /* MCU I2C0 Control Register 0x6080h */
    uint32_t __RESERVED12[SIZE(0x6084, 0x60A0)];
    uint32_t CTRLMMR_MCU_FSS_CTRL;               /* Flash Subsystem Control Register 0x60A0h */
    uint32_t __RESERVED13[SIZE(0x60A4, 0x60B0)];
    uint32_t CTRLMMR_MCU_ADC0_CTRL;              /* MCU_ADC0 Control Register 0x60B0h */
    uint32_t CTRLMMR_MCU_ADC1_CTRL;              /* MCU_ADC1 Control Register 0x60B4h */
    uint32_t __RESERVED14[SIZE(0x60B8, 0x6200)];
    uint32_t CTRLMMR_MCU_TIMER0_CTRL;            /* MCU_TIMER0 Control Register 0x6200h */
    uint32_t CTRLMMR_MCU_TIMER1_CTRL;            /* MCU_TIMER1 Control Register 0x6204h */
    uint32_t CTRLMMR_MCU_TIMER2_CTRL;            /* MCU_TIMER2 Control Register 0x6208h */
    uint32_t CTRLMMR_MCU_TIMER3_CTRL;            /* MCU_TIMER3 Control Register 0x620Ch */
    uint32_t CTRLMMR_MCU_TIMER4_CTRL;            /* MCU_TIMER4 Control Register 0x6210h */
    uint32_t CTRLMMR_MCU_TIMER5_CTRL;            /* MCU_TIMER5 Control Register 0x6214h */
    uint32_t CTRLMMR_MCU_TIMER6_CTRL;            /* MCU_TIMER6 Control Register 0x6218h */
    uint32_t CTRLMMR_MCU_TIMER7_CTRL;            /* MCU_TIMER7 Control Register 0x621Ch */
    uint32_t CTRLMMR_MCU_TIMER8_CTRL;            /* MCU_TIMER8 Control Register 0x6220h */
    uint32_t CTRLMMR_MCU_TIMER9_CTRL;            /* MCU_TIMER9 Control Register 0x6224h */
    uint32_t __RESERVED15[SIZE(0x6228, 0x6280)];
    uint32_t CTRLMMR_MCU_TIMERIO0_CTRL;          /* MCU_TIMERIO0 Control Register 0x6280h */
    uint32_t CTRLMMR_MCU_TIMERIO1_CTRL;          /* MCU_TIMERIO1 Control Register 0x6284h */
    uint32_t CTRLMMR_MCU_TIMERIO2_CTRL;          /* MCU_TIMERIO2 Control Register 0x6288h */
    uint32_t CTRLMMR_MCU_TIMERIO3_CTRL;          /* MCU_TIMERIO3 Control Register 0x628Ch */
    uint32_t CTRLMMR_MCU_TIMERIO4_CTRL;          /* MCU_TIMERIO4 Control Register 0x6290h */
    uint32_t CTRLMMR_MCU_TIMERIO5_CTRL;          /* MCU_TIMERIO5 Control Register 0x6294h */
    uint32_t CTRLMMR_MCU_TIMERIO6_CTRL;          /* MCU_TIMERIO6 Control Register 0x6298h */
    uint32_t CTRLMMR_MCU_TIMERIO7_CTRL;          /* MCU_TIMERIO7 Control Register 0x629Ch */
    uint32_t CTRLMMR_MCU_TIMERIO8_CTRL;          /* MCU_TIMERIO8 Control Register 0x62A0h */
    uint32_t CTRLMMR_MCU_TIMERIO9_CTRL;          /* MCU_TIMERIO9 Control Register 0x62A4h */
    uint32_t __RESERVED16[SIZE(0x62A8, 0x7008)];
    uint32_t CTRLMMR_MCU_LOCK1_KICK0;            /* Partition 1 Lock Key 0 Register 0x7008h */
    uint32_t CTRLMMR_MCU_LOCK1_KICK1;            /* Partition 1 Lock Key 1 Register 0x700Ch */
    uint32_t __RESERVED17[SIZE(0x7010, 0x7100)];
    uint32_t CTRLMMR_MCU_P1_CLAIM0;              /* Partition 1 Claim Register 0 0x7100h */
    uint32_t CTRLMMR_MCU_P1_CLAIM1;              /* Partition 1 Claim Register 1 0x7104h */
    uint32_t CTRLMMR_MCU_P1_CLAIM2;              /* Partition 1 Claim Register 2 0x7108h */
    uint32_t CTRLMMR_MCU_P1_CLAIM3;              /* Partition 1 Claim Register 3 0x710Ch */
    uint32_t CTRLMMR_MCU_P1_CLAIM4;              /* Partition 1 Claim Register 4 0x7110h */
    uint32_t CTRLMMR_MCU_P1_CLAIM5;              /* Partition 1 Claim Register 5 0x7114h */
    uint32_t __RESERVED18[SIZE(0x7118, 0xA010)];
    uint32_t CTRLMMR_MCU_CLKOUT0_CTRL;           /* MCU_CLKOUT0 Control Register 0xA010h */
    uint32_t __RESERVED19[SIZE(0xA014, 0xA018)];
    uint32_t CTRLMMR_MCU_EFUSE_CLKSEL;           /* MCU eFuse Controller Clock Select Register 0xA018h */
    uint32_t __RESERVED20[SIZE(0xA01C, 0xA020)];
    uint32_t CTRLMMR_MCU_MCAN0_CLKSEL;           /* MCU_MCAN Clock Select Register 0xA020h */
    uint32_t CTRLMMR_MCU_MCAN1_CLKSEL;           /* MCU_MCAN Clock Select Register 0xA024h */
    uint32_t __RESERVED21[SIZE(0xA028, 0xA030)];
    uint32_t CTRLMMR_MCU_OSPI0_CLKSEL;           /* MCU_OSPI Clock Select Register 0xA030h */
    uint32_t CTRLMMR_MCU_OSPI1_CLKSEL;           /* MCU_OSPI Clock Select Register 0xA034h */
    uint32_t __RESERVED22[SIZE(0xA038, 0xA040)];
    uint32_t CTRLMMR_MCU_ADC0_CLKSEL;            /* MCU_ADC Clock Select Register 0xA040h */
    uint32_t CTRLMMR_MCU_ADC1_CLKSEL;            /* MCU_ADC Clock Select Register 0xA044h */
    uint32_t __RESERVED23[SIZE(0xA048, 0xA050)];
    uint32_t CTRLMMR_MCU_ENET_CLKSEL;            /* MCU Ethernet Port1 Clock Select Register 0xA050h */
    uint32_t __RESERVED24[SIZE(0xA054, 0xA080)];
    uint32_t CTRLMMR_MCU_R5_CORE0_CLKSEL;        /* MCU R5 Core 0 Clock Select Register 0xA080h */
    uint32_t __RESERVED25[SIZE(0xA084, 0xA100)];
    uint32_t CTRLMMR_MCU_TIMER0_CLKSEL;          /* MCU_TIMER0 Clock Select Register 0xA100h */
    uint32_t CTRLMMR_MCU_TIMER1_CLKSEL;          /* MCU_TIMER1 Clock Select Register 0xA104h */
    uint32_t CTRLMMR_MCU_TIMER2_CLKSEL;          /* MCU_TIMER2 Clock Select Register 0xA108h */
    uint32_t CTRLMMR_MCU_TIMER3_CLKSEL;          /* MCU_TIMER3 Clock Select Register 0xA10Ch */
    uint32_t CTRLMMR_MCU_TIMER4_CLKSEL;          /* MCU_TIMER4 Clock Select Register 0xA110h */
    uint32_t CTRLMMR_MCU_TIMER5_CLKSEL;          /* MCU_TIMER5 Clock Select Register 0xA114h */
    uint32_t CTRLMMR_MCU_TIMER6_CLKSEL;          /* MCU_TIMER6 Clock Select Register 0xA118h */
    uint32_t CTRLMMR_MCU_TIMER7_CLKSEL;          /* MCU_TIMER7 Clock Select Register 0xA11Ch */
    uint32_t CTRLMMR_MCU_TIMER8_CLKSEL;          /* MCU_TIMER8 Clock Select Register 0xA120h */
    uint32_t CTRLMMR_MCU_TIMER9_CLKSEL;          /* MCU_TIMER9 Clock Select Register 0xA124h */
    uint32_t __RESERVED26[SIZE(0xA128, 0xA180)];
    uint32_t CTRLMMR_MCU_RTI0_CLKSEL;            /* MCU_RTI[0:0] Clock Select Register 0xA180h */
    uint32_t CTRLMMR_MCU_RTI1_CLKSEL;            /* MCU_RTI[0:0] Clock Select Register 0xA184h */
    uint32_t __RESERVED27[SIZE(0xA188, 0xA1C0)];
    uint32_t CTRLMMR_MCU_USART_CLKSEL;           /* MCU_USART0 Clock Select Register 0xA1C0h */
    uint32_t __RESERVED28[SIZE(0xA1C4, 0xB008)];
    uint32_t CTRLMMR_MCU_LOCK2_KICK0;            /* Partition 2 Lock Key 0 Register 0xB008h */
    uint32_t CTRLMMR_MCU_LOCK2_KICK1;            /* Partition 2 Lock Key 1 Register 0xB00Ch */
    uint32_t __RESERVED29[SIZE(0xB010, 0xB100)];
    uint32_t CTRLMMR_MCU_P2_CLAIM0;              /* Partition 2 Claim Register 0 0xB100h */
    uint32_t CTRLMMR_MCU_P2_CLAIM1;              /* Partition 2 Claim Register 1 0xB104h */
    uint32_t CTRLMMR_MCU_P2_CLAIM2;              /* Partition 2 Claim Register 2 0xB108h */
    uint32_t CTRLMMR_MCU_P2_CLAIM3;              /* Partition 2 Claim Register 3 0xB10Ch */
    uint32_t __RESERVED30[SIZE(0xB110, 0xE000)];
    uint32_t CTRLMMR_MCU_LBIST_CTRL;             /* MCU_Pulsar Logic BIST Control Register 0xE000h */
    uint32_t CTRLMMR_MCU_LBIST_PATCOUNT;         /* MCU_Pulsar Logic BIST Pattern Count Register 0xE004h */
    uint32_t CTRLMMR_MCU_LBIST_SEED0;            /* MCU_Pulsar Logic BIST Seed0 Register 0xE008h */
    uint32_t CTRLMMR_MCU_LBIST_SEED1;            /* MCU_Pulsar Logic BIST Seed1 Register 0xE00Ch */
    uint32_t CTRLMMR_MCU_LBIST_SPARE0;           /* MCU_Pulsar Logic BIST Spare0 Register 0xE010h */
    uint32_t CTRLMMR_MCU_LBIST_SPARE1;           /* MCU_Pulsar Logic BIST Spare1 Register 0xE014h */
    uint32_t CTRLMMR_MCU_LBIST_STAT;             /* MCU_Pulsar Logic BIST Status Register 0xE018h */
    uint32_t CTRLMMR_MCU_LBIST_MISR;             /* MCU_Pulsar Logic BIST MISR Register 0xE01Ch */
    uint32_t __RESERVED31[SIZE(0xE020, 0xE280)];
    uint32_t CTRLMMR_MCU_LBIST_SIG;              /* MCU Pulsar Logic BIST MISR Signature Register 0xE280h */
    uint32_t __RESERVED32[SIZE(0xE284, 0xF008)];
    uint32_t CTRLMMR_MCU_LOCK3_KICK0;            /* Partition 3 Lock Key 0 Register 0xF008h */
    uint32_t CTRLMMR_MCU_LOCK3_KICK1;            /* Partition 3 Lock Key 1 Register 0xF00Ch */
    uint32_t __RESERVED33[SIZE(0xF010, 0xF100)];
    uint32_t CTRLMMR_MCU_P3_CLAIM0;              /* Partition 3 Claim Register 0 0xF100h */
    uint32_t CTRLMMR_MCU_P3_CLAIM1;              /* Partition 3 Claim Register 1 0xF104h */
    uint32_t CTRLMMR_MCU_P3_CLAIM2;              /* Partition 3 Claim Register 2 0xF108h */
    uint32_t CTRLMMR_MCU_P3_CLAIM3;              /* Partition 3 Claim Register 3 0xF10Ch */
    uint32_t CTRLMMR_MCU_P3_CLAIM4;              /* Partition 3 Claim Register 4 0xF110h */
    uint32_t CTRLMMR_MCU_P3_CLAIM5;              /* Partition 3 Claim Register 5 0xF114h */
 };

#define CTRLMMR_MCU_ENET_CTRL_RMII       (1 << 0)
#define CTRLMMR_MCU_ENET_CTRL_RGMII      (1 << 1)
#define ENET_MCU_PLL2_HSDIV1_CLKOUT      (0xE)

 struct MCU_CPSW0_NUSS_CPINT {

    uint32_t CPSW_INT_REVISION;                  /* Revision Register 0x1000h */
    uint32_t __RESERVED1[SIZE(0x01004, 0x01010)];
    uint32_t CPSW_INT_EOI_REG;                   /* End of Interrupt Register 0x1010h */
    uint32_t CPSW_INT_INTR_VECTOR_REG;           /* Interrupt Vector Register 0x1014h */
    uint32_t __RESERVED2[SIZE(0x01018, 0x01100)];
    uint32_t CPSW_INT_ENABLE_REG_OUT_PULSE_0;    /* Enable Register 0 0x1100h */
    uint32_t __RESERVED3[SIZE(0x01104, 0x01300)];
    uint32_t CPSW_INT_ENABLE_CLR_REG_OUT_PULSE_0;/* Enable Clear Register 0 0x1300h */
    uint32_t __RESERVED4[SIZE(0x01304, 0x01500)];
    uint32_t CPSW_INT_STATUS_REG_OUT_PULSE_0;    /* Status Register 0 0x1500h */
    uint32_t __RESERVED5[SIZE(0x01504, 0x01A80)];
    uint32_t CPSW_INT_INTR_VECTOR_REG_OUT_PULSE;/* Interrupt Vector for out_pulse 0x1A80h */
 };

 
 struct MCU_CPSW0_NUSS_CONTROL {

    uint32_t CPSW_CPSW_ID_VER_REG;               /* ID Version Register 0x20000h */
    uint32_t CPSW_CONTROL_REG;                   /* Control Register 0x20004h */
    uint32_t __RESERVED1[SIZE(0x20008, 0x20010)];
    uint32_t CPSW_EM_CONTROL_REG;                /* Emulation Control Register 0x20010h */
    uint32_t CPSW_STAT_PORT_EN_REG;              /* Statistics Port Enable Register 0x20014h */
    uint32_t CPSW_PTYPE_REG;                     /* Transmit Priority Type Register 0x20018h */
    uint32_t CPSW_SOFT_IDLE_REG;                 /* Software Idle Register 0x2001Ch */
    uint32_t CPSW_THRU_RATE_REG;                 /* Thru Rate Register 0x20020h */
    uint32_t CPSW_GAP_THRESH_REG;                /* Transmit FIFO Short Gap Threshold Register 0x20024h */
    uint32_t CPSW_TX_START_WDS_REG;              /* Transmit FIFO Start Words Register 0x20028h */
    uint32_t CPSW_EEE_PRESCALE_REG;              /* Energy Efficient Ethernet Prescale Value Register 0x2002Ch */
    uint32_t CPSW_TX_G_OFLOW_THRESH_SET_REG;     /* PFC Tx Global Out Flow Threshold Set Register 0x20030h */
    uint32_t CPSW_TX_G_OFLOW_THRESH_CLR_REG;     /* PFC Tx Global Out Flow Threshold Clear Register 0x20034h */
    uint32_t CPSW_TX_G_BUF_THRESH_SET_L_REG;     /* PFC Global Tx Buffer Threshold Set Low Register 0x20038h */
    uint32_t CPSW_TX_G_BUF_THRESH_SET_H_REG;     /* PFC Global Tx Buffer Threshold Set High Register 0x2003Ch */
    uint32_t CPSW_TX_G_BUF_THRESH_CLR_L_REG;     /* PFC Global Tx Buffer Threshold Clear Low Register 0x20040h */
    uint32_t CPSW_TX_G_BUF_THRESH_CLR_H_REG;     /* PFC Global Tx Buffer Threshold Clear High Register 0x20044h */
    uint32_t __RESERVED2[SIZE(0x20048, 0x20050)];
    uint32_t CPSW_VLAN_LTYPE_REG;                /* VLAN LTYPE Outer and Inner Register 0x20050h */
    uint32_t CPSW_EST_TS_DOMAIN_REG;             /* EST Timestamp Domain Register 0x20054h */
    uint32_t __RESERVED3[SIZE(0x20058, 0x20100)];
    uint32_t CPSW_TX_PRI0_MAXLEN_REG;            /* Priority 0 Maximum Transmit Packet Length Register 0x20100h */
    uint32_t CPSW_TX_PRI1_MAXLEN_REG;            /* Priority 1 Maximum Transmit Packet Length Register 0x20104h */
    uint32_t CPSW_TX_PRI2_MAXLEN_REG;            /* Priority 2 Maximum Transmit Packet Length Register 0x20108h */
    uint32_t CPSW_TX_PRI3_MAXLEN_REG;            /* Priority 3 Maximum Transmit Packet Length Register 0x2010Ch */
    uint32_t CPSW_TX_PRI4_MAXLEN_REG;            /* Priority 4 Maximum Transmit Packet Length Register 0x20110h */
    uint32_t CPSW_TX_PRI5_MAXLEN_REG;            /* Priority 5 Maximum Transmit Packet Length Register 0x20114h */
    uint32_t CPSW_TX_PRI6_MAXLEN_REG;            /* Priority 6 Maximum Transmit Packet Length Register 0x20118h */
    uint32_t CPSW_TX_PRI7_MAXLEN_REG;            /* Priority 7 Maximum Transmit Packet Length Register 0x2011Ch */
    uint32_t __RESERVED4[SIZE(0x20120, 0x21004)];
    uint32_t CPSW_P0_CONTROL_REG;                /* CPPI Port 0 Control Register 0x21004h */
    uint32_t CPSW_P0_FLOW_ID_OFFSET_REG;         /* CPPI Port 0 Transmit FLOW ID Offset Register 0x21008h */
    uint32_t __RESERVED5[SIZE(0x2100C, 0x21010)];
    uint32_t CPSW_P0_BLK_CNT_REG;                /* CPPI Port 0 FIFO Block Usage Count Register 0x21010h */
    uint32_t CPSW_P0_PORT_VLAN_REG;              /* CPPI Port 0 VLAN Register 0x21014h */
    uint32_t CPSW_P0_TX_PRI_MAP_REG;             /* CPPI Port 0 Tx Header Priority to Switch Priority Map Register 0x21018h */
    uint32_t CPSW_P0_PRI_CTL_REG;                /* CPPI Port 0 Priority Control Register 0x2101Ch */
    uint32_t CPSW_P0_RX_PRI_MAP_REG;             /* CPPI Port 0 RX Packet Priority to Header Priority Map Register 0x21020h */
    uint32_t CPSW_P0_RX_MAXLEN_REG;              /* CPPI Port 0 Receive Frame Max Length Register 0x21024h */
    uint32_t CPSW_P0_TX_BLKS_PRI_REG;            /* CPPI Port 0 Transmit Block Sub Per Priority Register 0x21028h */
    uint32_t __RESERVED6[SIZE(0x2102C, 0x21030)];
    uint32_t CPSW_P0_IDLE2LPI_REG;               /* CPPI Port 0 EEE Idle to LPI Count Register 0x21030h */
    uint32_t CPSW_P0_LPI2WAKE_REG;               /* CPPI Port 0 EEE LPI to Wakeup Count Register 0x21034h */
    uint32_t CPSW_P0_EEE_STATUS_REG;             /* CPPI Port 0 EEE Port Status Register 0x21038h */
    uint32_t CPSW_P0_RX_PKTS_PRI_REG;            /* CPPI Port 0 Receive Packets Per Priority Register 0x2103Ch */
    uint32_t __RESERVED7[SIZE(0x21040, 0x2104C)];
    uint32_t CPSW_P0_RX_GAP_REG;                 /* CPPI Port 0 Receive Gap Register 0x2104Ch */
    uint32_t CPSW_P0_FIFO_STATUS_REG;            /* CPPI Port 0 FIFO Status Register 0x21050h */
    uint32_t __RESERVED8[SIZE(0x21054, 0x21120)];
    uint32_t CPSW_P0_RX_DSCP_MAP_REG[8];         /* CPPI Port 0 Receive IPV4/IPV6 DSCP Map 0 to Map 7 Registers 0x21120h */
    uint32_t CPSW_P0_PRI_CIR_REG[8];             /* CPPI Port 0 Rx Priority 0 to Priority 7 Committed Information Rate Registers 0x21140h */
    uint32_t CPSW_P0_PRI_EIR_REG[8];             /* CPPI Port 0 Rx Priority 0 to Priority 7 Excess Information Rate Registers 0x21160h */
    uint32_t CPSW_P0_TX_D_THRESH_SET_L_REG;      /* CPPI Port 0 Tx PFC Destination Threshold Set Low Register 0x21180h */
    uint32_t CPSW_P0_TX_D_THRESH_SET_H_REG;      /* CPPI Port 0 Tx PFC Destination Threshold Set High Register 0x21184h */
    uint32_t CPSW_P0_TX_D_THRESH_CLR_L_REG;      /* CPPI Port 0 Tx PFC Destination Threshold Clear Low Register 0x21188h */
    uint32_t CPSW_P0_TX_D_THRESH_CLR_H_REG;      /* CPPI Port 0 Tx PFC Destination Threshold Clear High Register 0x2118Ch */
    uint32_t CPSW_P0_TX_G_BUF_THRESH_SET_L_REG;  /* CPPI Port 0 Tx PFC Global Buffer Threshold Set Low Register 0x21190h */
    uint32_t CPSW_P0_TX_G_BUF_THRESH_SET_H_REG;  /* CPPI Port 0 Tx PFC Global Buffer Threshold Set High Register 0x21194h */
    uint32_t CPSW_P0_TX_G_BUF_THRESH_CLR_L_REG;  /* CPPI Port 0 Tx PFC Global Buffer Threshold Clear Low Register 0x21198h */
    uint32_t CPSW_P0_TX_G_BUF_THRESH_CLR_H_REG;  /* CPPI Port 0 Tx PFC Global Buffer Threshold Clear High Register 0x2119Ch */
    uint32_t __RESERVED9[SIZE(0x211A0, 0x21300)];
    uint32_t CPSW_P0_SRC_ID_A_REG;               /* CPPI Port 0 CPPI Source ID A Register 0x21300h */
    uint32_t __RESERVED10[SIZE(0x21304, 0x21320)];
    uint32_t CPSW_P0_HOST_BLKS_PRI_REG;          /* CPPI Port 0 Host Blocks Priority Register 0x21320h */
    uint32_t __RESERVED11[SIZE(0x21324, 0x22000)];
    uint32_t CPSW_PN_RESERVED_REG;               /* Reserved Register 0x22000h */
    uint32_t CPSW_PN_CONTROL_REG;                /* Ethernet Port N Control Register 0x22004h */
    uint32_t CPSW_PN_MAX_BLKS_REG;               /* Ethernet Port N Maximum Blocks Register 0x22008h */
    uint32_t __RESERVED12[SIZE(0x2200C, 0x22010)];
    uint32_t CPSW_PN_BLK_CNT_REG;                /* Ethernet Port N FIFO Block Usage Count Register 0x22010h */
    uint32_t CPSW_PN_PORT_VLAN_REG;              /* Ethernet Port N VLAN Register 0x22014h */
    uint32_t CPSW_PN_TX_PRI_MAP_REG;             /* Ethernet Port N Tx Header Priority to Switch Priority Mapping Register 0x22018h */
    uint32_t CPSW_PN_PRI_CTL_REG;                /* Ethernet Port N Priority Control Register 0x2201Ch */
    uint32_t CPSW_PN_RX_PRI_MAP_REG;             /* Ethernet Port N RX Packet Priority to Header Priority Map 0x22020h */
    uint32_t CPSW_PN_RX_MAXLEN_REG;              /* Ethernet Port N Receive Frame Maximum Length Register 0x22024h */
    uint32_t CPSW_PN_TX_BLKS_PRI_REG;            /* Ethernet Port N Transmit Block Sub Per Priority Register 0x22028h */
    uint32_t CPSW_PN_RX_FLOW_THRESH_REG;         /* Ethernet Port N Receive Flow Threshold Register 0x2202Ch */
    uint32_t CPSW_PN_IDLE2LPI_REG;               /* Ethernet Port N EEE Idle to LPI Count Register 0x22030h */
    uint32_t CPSW_PN_LPI2WAKE_REG;               /* Ethernet Port N EEE LPI to Wake Count Register 0x22034h */
    uint32_t CPSW_PN_EEE_STATUS_REG;             /* Ethernet Port N EEE Status Register 0x22038h */
    uint32_t __RESERVED13[SIZE(0x2203C, 0x22040)];
    uint32_t CPSW_PN_IET_CONTROL_REG;            /* Ethernet Port N FIFO Status Register 0x22040h */
    uint32_t CPSW_PN_IET_STATUS_REG;             /* Ethernet Port N Enhanced Scheduled Traffic (EST) Control Register 0x22044h */
    uint32_t CPSW_PN_IET_VERIFY_REG;             /* Ethernet Port N Receive IPV4/IPV6 DSCP Map 0 to Map 7 Registers 0x22048h */
    uint32_t __RESERVED14[SIZE(0x2204C, 0x22050)];
    uint32_t CPSW_PN_FIFO_STATUS_REG;            /* Ethernet Port N Rx Priority 0 to Priority 7 Committed Information Rate Registers 0x22050h */
    uint32_t __RESERVED15[SIZE(0x22054, 0x22060)];
    uint32_t CPSW_PN_EST_CONTROL_REG;            /* Ethernet Port N Rx Priority 0 to Priority 7 Excess Information Rate Registers 0x22060h */
    uint32_t __RESERVED16[SIZE(0x22064, 0x22120)];
    uint32_t CPSW_PN_RX_DSCP_MAP_REG[8];         /* Ethernet Port N Tx PFC Destination Threshold Set Low Register 0x22120h */
    uint32_t CPSW_PN_PRI_CIR_REG[8];             /* Ethernet Port N Tx PFC Destination Threshold Set High Register 0x22140h */
    uint32_t CPSW_PN_PRI_EIR_REG[8];             /* Ethernet Port N Tx PFC Destination Threshold Clear Low Register 0x22160h */
    uint32_t CPSW_PN_TX_D_THRESH_SET_L_REG;      /* Ethernet Port N Tx PFC Destination Threshold Clear High Register 0x22180h */
    uint32_t CPSW_PN_TX_D_THRESH_SET_H_REG;      /* Ethernet Port N Tx PFC Global Buffer Threshold Set Low Register 0x22184h */
    uint32_t CPSW_PN_TX_D_THRESH_CLR_L_REG;      /* Ethernet Port N Tx PFC Global Buffer Threshold Set High Register 0x22188h */
    uint32_t CPSW_PN_TX_D_THRESH_CLR_H_REG;      /* Ethernet Port N Tx PFC Global Buffer Threshold Clear Low Register 0x2218Ch */
    uint32_t CPSW_PN_TX_G_BUF_THRESH_SET_L_REG;  /* Ethernet Port N Tx PFC Global Buffer Threshold Clear High Register 0x22190h */
    uint32_t CPSW_PN_TX_G_BUF_THRESH_SET_H_REG;  /* Ethernet Port N Tx Destination Out Flow Add Values Low Register 0x22194h */
    uint32_t CPSW_PN_TX_G_BUF_THRESH_CLR_L_REG;  /* Ethernet Port N Tx Destination Out Flow Add Values High Register 0x22198h */
    uint32_t CPSW_PN_TX_G_BUF_THRESH_CLR_H_REG;  /* Ethernet Port N Tx Pause Frame Source Address Low Register 0x2219Ch */
    uint32_t __RESERVED17[SIZE(0x221A0, 0x22300)];
    uint32_t CPSW_PN_TX_D_OFLOW_ADDVAL_L_REG;    /* Ethernet Port N Tx Pause Frame Source Address High Register 0x22300h */
    uint32_t CPSW_PN_TX_D_OFLOW_ADDVAL_H_REG;    /* Ethernet Port N Time Sync Control Register 0x22304h */
    uint32_t CPSW_PN_SA_L_REG;                   /* Ethernet Port N Time Sync LTYPE Register (and SEQ_ID_OFFSET) 0x22308h */
    uint32_t CPSW_PN_SA_H_REG;                   /* Ethernet Port N Time Sync VLAN2 and VLAN2 Register 0x2230Ch */
    uint32_t CPSW_PN_TS_CTL_REG;                 /* Ethernet Port N Time Sync Control and LTYPE 2 Register 0x22310h */
    uint32_t CPSW_PN_TS_SEQ_LTYPE_REG;           /* Ethernet Port N Time Sync Control 2 Register 0x22314h */
    uint32_t CPSW_PN_TS_VLAN_LTYPE_REG;          /* Ethernet Port N Mac Control Register 0x22318h */
    uint32_t CPSW_PN_TS_CTL_LTYPE2_REG;          /* Ethernet Port N Mac Status Register 0x2231Ch */
    uint32_t CPSW_PN_TS_CTL2_REG;                /* Ethernet Port N Mac Software Reset Register 0x22320h */
    uint32_t __RESERVED18[SIZE(0x22324, 0x22330)];
    uint32_t CPSW_PN_MAC_CONTROL_REG;            /* Ethernet Port N Mac Backoff Test Register 0x22330h */
    uint32_t CPSW_PN_MAC_STATUS_REG;             /* Ethernet Port N 802.3 Receive Pause Timer Register 0x22334h */
    uint32_t CPSW_PN_MAC_SOFT_RESET_REG;         /* Ethernet Port N PFC Priority 0 to Priority 7 Rx Pause Timer Registers 0x22338h */
    uint32_t CPSW_PN_MAC_BOFFTEST_REG;           /* Ethernet Port N 802.3 Tx Pause Timer Registers 0x2233Ch */
    uint32_t CPSW_PN_MAC_RX_PAUSETIMER_REG;     /* Ethernet Port N PFC Priority 0 to Priority 7 Tx Pause Timer Registers 0x22340h */
    uint32_t __RESERVED19[SIZE(0x22344, 0x22350)];
    uint32_t CPSW_PN_MAC_RXN_PAUSETIMER_REG_y[8]; /* Ethernet Port N Emulation Control Register 0x22350h */
    uint32_t CPSW_PN_MAC_TX_PAUSETIMER_REG;     /* Ethernet Port N Tx Inter Packet Gap Register 0x22370h */
    uint32_t __RESERVED20[SIZE(0x22374, 0x22380)];
    uint32_t CPSW_PN_MAC_TXN_PAUSETIMER_REG_y[8]; /* 0x22380h */
    uint32_t CPSW_PN_MAC_EMCONTROL_REG;          /* 0x223A0h */
    uint32_t CPSW_PN_MAC_TX_GAP_REG;             /* 0x223A4h */
    uint32_t __RESERVED21[SIZE(0x223A8, 0x223AC)];
    uint32_t CPSW_PN_INTERVLAN_OPX_POINTER_REG; /* 0x223ACh */
    uint32_t CPSW_PN_INTERVLAN_OPX_A_REG;        /* 0x223B0h */
    uint32_t CPSW_PN_INTERVLAN_OPX_B_REG;        /* 0x223B4h */
    uint32_t CPSW_PN_INTERVLAN_OPX_C_REG;        /* 0x223B8h */
 };

#define CPSW_PN_MAC_CONTROL_CMD_IDLE       (1 << 11)
#define CPSW_PN_MAC_CONTROL_RX_CEF         (1 << 22)
#define CPSW_PN_MAC_CONTROL_RX_CSF         (1 << 23)
#define CPSW_PN_MAC_CONTROL_RX_CMF         (1 << 24)

#define CPSW_PN_MAC_STATUS_IDLE            (1 << 31)

#define CPSW_PN_MAC_SOFT_RESET_RES         (1 << 0)       

#define CPSW_STAT_PORT_EN_REG_P0           (1 << 0)
#define CPSW_STAT_PORT_EN_REG_P1           (1 << 1)

#define CPSW_P0_CONTROL_REG_DSCP_IPV4_EN   (1 << 1)
#define CPSW_P0_CONTROL_REG_DSCP_IPV6_EN   (1 << 2)

typedef union {
	uint32_t reg;
	struct {
		uint32_t fullduplex : 1;	// bit 0
		uint32_t loopback : 1;		// bit 1
		uint32_t mtest : 1;			// bit 2
		uint32_t rxflowen : 1;		// bit 3
		uint32_t txflowen : 1;		// bit 4
		uint32_t gmii_en : 1;		// bit 5
		uint32_t tx_pace : 1;		// bit 6
		uint32_t gig : 1;			// bit 7
		uint32_t reserved1 : 2;		// bit 8-9
		uint32_t tx_short_gap_en : 1;	// bit 10
		uint32_t cmd_idle : 1;		// bit 11
		uint32_t crc_type : 1;		// bit 12
		uint32_t reserved2 : 2;		// bit 13-14
		uint32_t ifctl_a : 1;		// bit 15
		uint32_t ifctl_b : 1;		// bit 16
		uint32_t gig_force : 1;		// bit 17
		uint32_t ctl_en : 1;		// bit 18
		uint32_t reserved3 : 13;	// bit 19-31
	};
} cpsw_mac_ctrl_t;


 struct MCU_CPSW0_NUSS_ALE {
    
    uint32_t CPSW_ALE_MOD_VER;                  /* ALE Module and Version Register 0x3E000h */
    uint32_t CPSW_ALE_STATUS;                   /* ALE Status Register 0x3E004h */
    uint32_t CPSW_ALE_CONTROL;                  /* ALE Control Register 0x3E008h */
    uint32_t CPSW_ALE_CTRL2;                    /* ALE Control 2 Register 0x3E00Ch */
    uint32_t CPSW_ALE_PRESCALE;                 /* ALE Prescale Register 0x3E010h */
    uint32_t CPSW_ALE_AGING_CTRL;               /* ALE Aging Control Register 0x3E014h */
    uint32_t __RESERVED1[SIZE(0x3e018, 0x3e01c)];
    uint32_t CPSW_ALE_NXT_HDR;                  /* ALE Next Header Register 0x3E01Ch */
    uint32_t CPSW_ALE_TBLCTL;                   /* ALE Table Control Register 0x3E020h */
    uint32_t __RESERVED2[SIZE(0x3e024, 0x3e034)];
    uint32_t CPSW_ALE_TBLW2;                    /* ALE LUT Table Word 2 Register 0x3E034h */
    uint32_t CPSW_ALE_TBLW1;                    /* ALE LUT Table Word 1 Register 0x3E038h */
    uint32_t CPSW_ALE_TBLW0;                    /* ALE LUT Table Word 0 Register 0x3E03Ch */
    uint32_t CPSW_I0_ALE_PORTCTL0_0;            /* ALE Port Control 0 Register 0x3E040h */
    uint32_t CPSW_I1_ALE_PORTCTL0_1;            /* ALE Port Control 1 Register 0x3E044h */
    uint32_t __RESERVED3[SIZE(0x3e048, 0x3e090)];
    uint32_t CPSW_ALE_UVLAN_MEMBER;             /* ALE Unknown VLAN Member Mask Register 0x3E090h */
    uint32_t CPSW_ALE_UVLAN_URCAST;             /* ALE Unknown VLAN Unregistered Multicast Flood Mask Register 0x3E094h */
    uint32_t CPSW_ALE_UVLAN_RMCAST;             /* ALE Unknown VLAN Registered Multicast Flood Mask Register 0x3E098h */
    uint32_t CPSW_ALE_UVLAN_UNTAG;              /* ALE Unknown VLAN force Untagged Egress Mask Register 0x3E09Ch */
    uint32_t __RESERVED4[SIZE(0x3e0a0, 0x3e0b8)];
    uint32_t CPSW_ALE_STAT_DIAG;                /* ALE Statistic Output Diagnostic Register 0x3E0B8h */
    uint32_t CPSW_ALE_OAM_LB_CTRL;              /* ALE OAM Loopback Control Register 0x3E0BCh */
    uint32_t CPSW_ALE_MSK_MUX0;                 /* ALE Mask Mux 0 Register 0x3E0C0h */
    uint32_t CPSW_I1_ALE_MSK_MUX1;              /* ALE Mask Mux 1 Register 0x3E0C4h */
    uint32_t CPSW_I1_ALE_MSK_MUX2;              /* ALE Mask Mux 4 Register 0x3E0C8h */
    uint32_t CPSW_I1_ALE_MSK_MUX3;              /* ALE Mask Mux 3 Register 0x3E0CCh */
    uint32_t __RESERVED5[SIZE(0x3e0d0, 0x3e0fc)];
    uint32_t CPSW_ALE_EGRESSOP;                 /* ALE Egress Operation Register 0x3E0FCh */
    uint32_t CPSW_ALE_POLICECFG0;               /* ALE Policing Configuration 0 Register 0x3E100h */
    uint32_t CPSW_ALE_POLICECFG1;               /* ALE Policing Configuration 1 Register 0x3E104h */
    uint32_t CPSW_ALE_POLICECFG2;               /* ALE Policing Configuration 2 Register 0x3E108h */
    uint32_t CPSW_ALE_POLICECFG3;               /* ALE Policing Configuration 3 Register 0x3E10Ch */
    uint32_t CPSW_ALE_POLICECFG4;               /* ALE Policing Configuration 4 Register 0x3E110h */
    uint32_t __RESERVED6[SIZE(0x3e114, 0x3e118)];
    uint32_t CPSW_ALE_POLICECFG6;               /* ALE Policing Configuration 6 Register 0x3E118h */
    uint32_t CPSW_ALE_POLICECFG7;               /* ALE Policing Configuration 7 Register 0x3E11Ch */
    uint32_t CPSW_ALE_POLICETBLCTL;             /* ALE Policing Table Control Register 0x3E120h */
    uint32_t CPSW_ALE_POLICECONTROL;            /* ALE Policing Control Register 0x3E124h */
    uint32_t CPSW_ALE_POLICETESTCTL;            /* ALE Policing Test Control Register 0x3E128h */
    uint32_t CPSW_ALE_POLICEHSTAT;              /* ALE Policing Hit Status Register 0x3E12Ch */
    uint32_t __RESERVED7[SIZE(0x3e130, 0x3e134)];
    uint32_t CPSW_ALE_THREADMAPDEF;             /* ALE THREAD Mapping Default Value Register 0x3E134h */
    uint32_t CPSW_ALE_THREADMAPCTL;             /* ALE THREAD Mapping Control Register 0x3E138h */
    uint32_t CPSW_ALE_THREADMAPVAL;             /* ALE THREAD Mapping Value Register 0x3E13Ch */
 };

#define CPSW_ALE_CONTROL_EN_BYPASS        (1 << 4) 
#define CPSW_ALE_CONTROL_OUI_DENY         (1 << 5)
#define CPSW_ALE_CONTROL_UNI_HOST_FLOOD   (1 << 8)
#define CPSW_ALE_CONTROL_CLEAR_TABLE      (1 << 30)
#define CPSW_ALE_CONTROL_ENABLE_ALE       (1 << 31)

#define CPSW_ALE_CTRL2_DROP_BADLEN        (1 << 23) 


 struct MCU_CPSW0_NUSS_CPTS {

    uint32_t CPSW_CPTS_IDVER_REG;                   /* CPTS Identification and Version Register 0x3D000h */
    uint32_t CPSW_CPTS_CONTROL_REG;                 /* Time Sync Control Register 0x3D004h */
    uint32_t CPSW_CPTS_RFTCLK_SEL_REG;              /* Reference Clock Select Register 0x3D008h */
    uint32_t CPSW_CPTS_TS_PUSH_REG;                 /* Time Stamp Event Push Register 0x3D00Ch */
    uint32_t CPSW_CPTS_TS_LOAD_VAL_REG;             /* Time Stamp Load Low Value (lower 32-bits) Register 0x3D010h */
    uint32_t CPSW_CPTS_TS_LOAD_EN_REG;              /* Time Stamp Load Enable Register 0x3D014h */
    uint32_t CPSW_CPTS_TS_COMP_VAL_REG;             /* Time Stamp Comparison Low Value (lower 32-bits) Register 0x3D018h */
    uint32_t CPSW_CPTS_TS_COMP_LEN_REG;             /* Time Stamp Comparison Length Register 0x3D01Ch */
    uint32_t CPSW_CPTS_INTSTAT_RAW_REG;             /* Interrupt Status Raw Register 0x3D020h */
    uint32_t CPSW_CPTS_INTSTAT_MASKED_REG;          /* Interrupt Status Masked Register 0x3D024h */
    uint32_t CPSW_CPTS_INT_ENABLE_REG;              /* Interrupt Enable Register 0x3D028h */
    uint32_t CPSW_CPTS_TS_COMP_NUDGE_REG;           /* Time Stamp Comparison Nudge Value Register 0x3D02Ch */
    uint32_t CPSW_CPTS_EVENT_POP_REG;               /* Event Interrupt Pop Register 0x3D030h */
    uint32_t CPSW_CPTS_EVENT_0_REG;                 /* Lower 32-bits of the Event Value Register 0x3D034h */
    uint32_t CPSW_CPTS_EVENT_1_REG;                 /* Lower Middle 32-bits of the Event Value Register 0x3D038h */
    uint32_t CPSW_CPTS_EVENT_2_REG;                 /* Upper Middle 32-bits of the Event Value Register 0x3D03Ch */
    uint32_t CPSW_CPTS_EVENT_3_REG;                 /* Upper 32-bits of the Event Value Register 0x3D040h */
    uint32_t CPSW_CPTS_TS_LOAD_HIGH_VAL_REG;        /* Time Stamp Load High Value (upper 32-bits) Register 0x3D044h */
    uint32_t CPSW_CPTS_TS_COMP_HIGH_VAL_REG;        /* Time Stamp Comparison High Value (upper 32-bits) Register 0x3D048h */
    uint32_t CPSW_CPTS_TS_ADD_VAL_REG;              /* Time Stamp Add Value Register 0x3D04Ch */
    uint32_t CPSW_CPTS_TS_PPM_LOW_VAL_REG;          /* Time Stamp PPM Load Low Value (lower 32-bits) Register 0x3D050h */
    uint32_t CPSW_CPTS_TS_PPM_HIGH_VAL_REG;         /* Time Stamp PPM Load High Value (upper 32-bits) Register 0x3D054h */
    uint32_t CPSW_CPTS_TS_NUDGE_VAL_REG;            /* Time Stamp Nudge Value Register 0x3D058h */
    uint32_t __RESERVED1[SIZE(0x3d05c, 0x3d0e0)];
    uint32_t CPSW_GENF0_COMP_LOW_REG_L;             /* GENF0 time stamp Comparison Value Lower 32-bits Registers 0x3D0E0h */
    uint32_t CPSW_GENF0_COMP_HIGH_REG_L;            /* GENF0 time stamp Comparison Value Upper 32-bits Registers 0x3D0E4h */
    uint32_t CPSW_GENF0_TS_GENF_CONTROL_REG;        /* GENF0 Control Register Registers 0x3D0E8h */
    uint32_t CPSW_GENF0_LENGTH_REG_L;               /* GENF0 Length Value Registers 0x3D0ECh */
    uint32_t CPSW_GENF0_PPM_LOW_REG_L;              /* GENF0 PPM Value Lower 32-bits Registers 0x3D0F0h */
    uint32_t CPSW_GENF0_PPM_HIGH_REG_L;             /* GENF0 PPM Value Upper 32-bits Registers 0x3D0F4h */
    uint32_t CPSW_GENF0_NUDGE_REG_L;                /* GENF0 Nudge Value Registers 0x3D0F8h */
    uint32_t __RESERVED2[SIZE(0x3d0fc, 0x3d100)];
    uint32_t CPSW_GENF1_COMP_LOW_REG;               /* GENF1 time stamp Comparison Value Lower 32-bits Register 0x3D100h */
    uint32_t CPSW_GENF1_COMP_HIGH_REG;              /* GENF1 time stamp Comparison Value Upper 32-bits Register 0x3D104h */
    uint32_t CPSW_GENF1_CONTROL_REG;                /* GENF1 Control Register 0x3D108h */
    uint32_t CPSW_GENF1_LENGTH_REG;                 /* GENF1 Length Value Register 0x3D10Ch */
    uint32_t CPSW_GENF1_PPM_LOW_REG;                /* GENF1 PPM Value Lower 32-bits Register 0x3D110h */
    uint32_t CPSW_GENF1_PPM_HIGH_REG;               /* GENF1 PPM Value Upper 32-bits Register 0x3D114h */
    uint32_t CPSW_GENF1_NUDGE_REG;                  /* GENF1 Nudge Value Register 0x3D118h */
    uint32_t __RESERVED3[SIZE(0x3d11c, 0x3d200)];
    uint32_t CPSW_ESTF1_COMP_LOW_REG;               /* ESTF1 time stamp Comparison Value Lower 32-bits Register 0x3D200h */
    uint32_t CPSW_ESTF1_COMP_HIGH_REG;              /* ESTF1 time stamp Comparison Value Upper 32-bits Register 0x3D204h */
    uint32_t CPSW_ESTF1_CONTROL_REG;                /* ESTF1 Control Register 0x3D208h */
    uint32_t CPSW_ESTF1_LENGTH_REG;                 /* ESTF1 Length Value Register 0x3D20Ch */
    uint32_t CPSW_ESTF1_PPM_LOW_REG;                /* ESTF1 PPM Value Lower 32-bits Register 0x3D210h */
    uint32_t CPSW_ESTF1_PPM_HIGH_REG;               /* ESTF1 PPM Value Upper 32-bits Register 0x3D214h */
    uint32_t CPSW_ESTF1_NUDGE_REG;                  /* ESTF1 Nudge Value Register 0x3D218h */
 };

#define CPSW_CPTS_CONTROL_VLAN_AWARE         (1 << 1)
#define CPSW_CPTS_CONTROL_P0_ENABLE          (1 << 2)
#define CPSW_CPTS_CONTROL_P0_TX_CRC_REMOVE   (1 << 13)
#define CPSW_CPTS_CONTROL_P0_RX_PAD          (1 << 14)
#define CPSW_CPTS_CONTROL_P0_RX_PASS_CRC_ERR (1 << 15)
#define CPSW_CPTS_CONTROL_ECC_CRC_MODE       (1 << 31)



 struct MCU_CPSW0_ECC {

    uint32_t CPSW_ECC_REV;                       /* Aggregator Revision Register 0x00000h */
    uint32_t __RESERVED0[SIZE(0x00004, 0x00008)];
    uint32_t CPSW_ECC_VECTOR;                    /* ECC Vector Register 0x00008h */
    uint32_t CPSW_ECC_STAT;                      /* Misc Status 0x0000Ch */
    uint32_t CPSW_ECC_RESERVED_SVBUS_y[10];      /* Reserved Area for Serial VBUS Registers 0x00010h */
    uint32_t CPSW_ECC_SEC_EOI_REG;               /* EOI Register 0x0003Ch */
    uint32_t CPSW_ECC_SEC_STATUS_REG0;           /* Interrupt Status Register 0 0x00040h */
    uint32_t __RESERVED1[SIZE(0x00044, 0x00080)];
    uint32_t CPSW_ECC_SEC_ENABLE_SET_REG0;       /* Interrupt Enable Set Register 0 0x00080h */
    uint32_t __RESERVED2[SIZE(0x00084, 0x000C0)];
    uint32_t CPSW_ECC_SEC_ENABLE_CLR_REG0;       /* Interrupt Enable Clear Register 0 0x000C0h */
    uint32_t __RESERVED3[SIZE(0x000C4, 0x0013C)];
    uint32_t CPSW_ECC_DED_EOI_REG;               /* EOI Register 0x0013Ch */
    uint32_t CPSW_ECC_DED_STATUS_REG0;           /* Interrupt Status Register 0 0x00140h */
    uint32_t __RESERVED4[SIZE(0x00144, 0x00180)];
    uint32_t CPSW_ECC_DED_ENABLE_SET_REG0;       /* Interrupt Enable Set Register 0 0x00180h */
    uint32_t __RESERVED5[SIZE(0x00184, 0x001C0)];
    uint32_t CPSW_ECC_DED_ENABLE_CLR_REG0;       /* Interrupt Enable Clear Register 0 0x001C0h */
    uint32_t __RESERVED6[SIZE(0x001C4, 0x00200)];
    uint32_t CPSW_ECC_AGGR_ENABLE_SET;           /* AGGR interrupt enable set Register 0x00200h */
    uint32_t CPSW_ECC_AGGR_ENABLE_CLR;           /* AGGR interrupt enable clear Register 0x00204h */
    uint32_t CPSW_ECC_AGGR_STATUS_SET;           /* AGGR interrupt status set Register 0x00208h */
    uint32_t CPSW_ECC_AGGR_STATUS_CLR;           /* AGGR interrupt status clear Register 0x0020Ch */
 };

 struct MCU_CPSW0_NUSS_MDIO {

    uint32_t CPSW_MDIO_VERSION_REG;              /* MDIO Version Register 0x0F00h */
    uint32_t CPSW_MDIO_CONTROL_REG;              /* MDIO Control Register 0x0F04h */
    uint32_t CPSW_MDIO_ALIVE_REG;                /* MDIO Alive Register 0x0F08h */
    uint32_t CPSW_MDIO_LINK_REG;                 /* MDIO Link Register 0x0F0Ch */
    uint32_t CPSW_MDIO_LINK_INT_RAW_REG;         /* MDIO Link Interrupt Raw Register 0x0F10h */
    uint32_t CPSW_MDIO_LINK_INT_MASKED_REG;      /* MDIO Link Interrupt Masked Register 0x0F14h */
    uint32_t CPSW_MDIO_LINK_INT_MASK_SET_REG;    /* MDIO Link Interrupt Mask Set Register 0x0F18h */
    uint32_t CPSW_MDIO_LINK_INT_MASK_CLEAR_REG;  /* MDIO Link Interrupt Mask Clear Register 0x0F1Ch */
    uint32_t CPSW_MDIO_USER_INT_RAW_REG;         /* MDIO User Interrupt Raw Register 0x0F20h */
    uint32_t CPSW_MDIO_USER_INT_MASKED_REG;      /* MDIO User Interrupt Masked Register 0x0F24h */
    uint32_t CPSW_MDIO_USER_INT_MASK_SET_REG;    /* MDIO User Interrupt Mask Set Register 0x0F28h */
    uint32_t CPSW_MDIO_USER_INT_MASK_CLEAR_REG;  /* MDIO User Interrupt Mask Clear Register 0x0F2Ch */
    uint32_t CPSW_MDIO_MANUAL_IF_REG;            /* MDIO Manual Interface Register 0x0F30h */
    uint32_t CPSW_MDIO_POLL_REG;                 /* MDIO Poll Inter Register 0x0F34h */
    uint32_t CPSW_MDIO_POLL_EN_REG;              /* MDIO Poll Enable Register 0x0F38h */
    uint32_t CPSW_MDIO_CLAUS45_REG;              /* Clause 45 Enable Register 0x0F3Ch */
    uint32_t CPSW_MDIO_USER_ADDR0_REG;           /* MDIO User Address 0 Register 0x0F40h */
    uint32_t CPSW_MDIO_USER_ADDR1_REG;           /* MDIO User Address 1 Register 0x0F44h */
    uint32_t __RESERVED0[SIZE(0x0F48, 0x0F80)];
    uint32_t CPSW_MDIO_USER_ACCESS_REG_0;        /* MDIO User Access 0 Register 0x0F80h */
    uint32_t CPSW_MDIO_USER_PHY_SEL_REG_0;       /* MDIO User PHY Select 0 Register 0x0F84h */
    uint32_t CPSW_MDIO_USER_ACCESS_REG_1;        /* MDIO User Access 1 Register 0x0F88h */
    uint32_t CPSW_MDIO_USER_PHY_SEL_REG_1;       /* MDIO User PHY Select 1 Register 0x0F8Ch */
 };

#define CPSW_MDIO_CONTROL_REG_CLK_DIV(val)     (((val) & 0xFFFF) << 0) 
#define CPSW_MDIO_CONTROL_REG_EN               (1 << 30) 

#define CPSW_MDIO_USER_ACCESS_REG_DATA(val)     (((val) & 0xFFFF) << 0)
#define CPSW_MDIO_USER_ACCESS_REG_PHY_ADDR(val) (((val) & 0x1F) << 16)
#define CPSW_MDIO_USER_ACCESS_REG_REG_ADDR(val) (((val) & 0x1F) << 21)
#define CPSW_MDIO_USER_ACCESS_REG_ACK           (1 << 29)
#define CPSW_MDIO_USER_ACCESS_REG_WRITE         (1 << 30)
#define CPSW_MDIO_USER_ACCESS_REG_GO            (1 << 31)

#define CPSW_MDIO_USER_PHY_SEL_REG_LINKINT      (1 << 6)

#define CPSW_MDIO_REG_READ                      (0)
#define CPSW_MDIO_REG_WRITE                     (1)

#define CPSW_MDIO_LINK_INT_MASKED_INT0			(1 << 0)
#define CPSW_MDIO_LINK_INT_MASKED_INT1			(1 << 1)



 struct MCU_CPSW0_NUSS_STAT0 {

    uint32_t CPSW_STAT0_RXGOODFRAMES;            /* Ethernet Port N Total Number of Good Frames Received 0xA000h */
    uint32_t CPSW_STAT0_RXBROADCASTFRAMES;       /* Ethernet Port N Total Number of Good Broadcast Frames Received 0xA004h */
    uint32_t CPSW_STAT0_RXMULTICASTFRAMES;       /* Ethernet Port N Total Number of Good Multicast Frames Received 0xA008h */
    uint32_t __RESERVED0[SIZE(0xA00C, 0xA010)];
    uint32_t CPSW_STAT0_RXCRCERRORS;             /* Ethernet Port N Total Number of CRC Errors Frames Received 0xA010h */
    uint32_t __RESERVED1[SIZE(0xA014, 0xA018)];
    uint32_t CPSW_STAT0_RXOVERSIZEDFRAMES;       /* Ethernet Port N Total Number of Oversized Frames Received 0xA018h */
    uint32_t __RESERVED2[SIZE(0xA01C, 0xA020)];
    uint32_t CPSW_STAT0_RXUNDERSIZEDFRAMES;      /* Ethernet Port N Total Number of Undersized Frames Received 0xA020h */
    uint32_t CPSW_STAT0_RXFRAGMENTS;             /* Ethernet Port N Fragments Received Register 0xA024h */
    uint32_t CPSW_STAT0_ALE_DROP;                /* Ethernet Port N ALE Drop Register 0xA028h */
    uint32_t CPSW_STAT0_ALE_OVERRUN_DROP;        /* Ethernet Port N ALE Overrun Drop Register 0xA02Ch */
    uint32_t CPSW_STAT0_RXOCTETS;                /* Ethernet Port N Total Number of Received Bytes in Good Frames 0xA030h */
    uint32_t CPSW_STAT0_TXGOODFRAMES;            /* Ethernet Port N Good Transmit Frames Register 0xA034h */
    uint32_t CPSW_STAT0_TXBROADCASTFRAMES;       /* Ethernet Port N Broadcast Transmit Frames Register 0xA038h */
    uint32_t CPSW_STAT0_TXMULTICASTFRAMES;       /* Ethernet Port N Multicast Transmit Frames Register 0xA03Ch */
    uint32_t __RESERVED3[SIZE(0xA040, 0xA064)];
    uint32_t CPSW_STAT0_TXOCTETS;                /* Ethernet Port N Tx Octets Register 0xA064h */
    uint32_t CPSW_STAT0_OCTETFRAMES64;           /* Ethernet Port N 64 Octet Frames Register 0xA068h */
    uint32_t CPSW_STAT0_OCTETFRAMES65T127;       /* Ethernet Port N 65 to 127 Octet Frames Register 0xA06Ch */
    uint32_t CPSW_STAT0_OCTETFRAMES128T255;      /* Ethernet Port N 128 to 255 Octet Frames Register 0xA070h */
    uint32_t CPSW_STAT0_OCTETFRAMES256T511;      /* Ethernet Port N 256 to 511 Octet Frames Register 0xA074h */
    uint32_t CPSW_STAT0_OCTETFRAMES512T1023;     /* Ethernet Port N 512-pn_rx_maxlen Octet Frames Register 0xA078h */
    uint32_t CPSW_STAT0_OCTETFRAMES1024TUP;      /* Ethernet Port N 1023-1518 Octet Frames Register 0xA07Ch */
    uint32_t CPSW_STAT0_NETOCTETS;               /* Ethernet Port N Net Octets Register 0xA080h */
    uint32_t CPSW_STAT0_RX_BOTTOM_OF_FIFO_DROP;  /* Ethernet Port N Receive Bottom of FIFO Drop Register 0xA084h */
    uint32_t CPSW_STAT0_PORTMASK_DROP;           /* Ethernet Port N Portmask Drop Register 0xA088h */
    uint32_t CPSW_STAT0_RX_TOP_OF_FIFO_DROP;     /* Ethernet Port N Receive Top of FIFO Drop Register 0xA08Ch */
    uint32_t CPSW_STAT0_ALE_RATE_LIMIT_DROP;     /* Ethernet Port N ALE Rate Limit Drop Register 0xA090h */
    uint32_t CPSW_STAT0_ALE_VID_INGRESS_DROP;    /* Ethernet Port N ALE VID Ingress Drop Register 0xA094h */
    uint32_t CPSW_STAT0_ALE_DA_EQ_SA_DROP;       /* Ethernet Port N ALE DA equal SA Drop Register 0xA098h */
    uint32_t CPSW_STAT0_ALE_BLOCK_DROP;          /* Ethernet Port N ALE Block Drop Register 0xA09Ch */
    uint32_t CPSW_STAT0_ALE_SECURE_DROP;         /* Ethernet Port N ALE Secure Drop Register 0xA0A0h */
    uint32_t CPSW_STAT0_ALE_AUTH_DROP;           /* Ethernet Port N ALE Authentication Drop Register 0xA0A4h */
    uint32_t CPSW_STAT0_ALE_UNKN_UNI;            /* Ethernet Port N ALE Receive Unknown Unicast Register 0xA0A8h */
    uint32_t CPSW_STAT0_ALE_UNKN_UNI_BCNT;       /* Ethernet Port N ALE Receive Unknown Unicast Bytecount Register 0xA0ACh */
    uint32_t CPSW_STAT0_ALE_UNKN_MLT;            /* Ethernet Port N ALE Receive Unknown Multicast Register 0xA0B0h */
    uint32_t CPSW_STAT0_ALE_UNKN_MLT_BCNT;       /* Ethernet Port N ALE Receive Unknown Multicast Bytecount Register 0xA0B4h */
    uint32_t CPSW_STAT0_ALE_UNKN_BRD;            /* Ethernet Port N ALE Receive Unknown Broadcast Register 0xA0B8h */
    uint32_t CPSW_STAT0_ALE_UNKN_BRD_BCNT;       /* Ethernet Port N ALE Receive Unknown Broadcast Bytecount Register 0xA0BCh */
    uint32_t CPSW_STAT0_ALE_POL_MATCH;           /* Ethernet Port N ALE Policer Matched Register 0xA0C0h */
    uint32_t CPSW_STAT0_ALE_POL_MATCH_RED;       /* Ethernet Port N ALE Policer Matched and Condition Red Register 0xA0C4h */
    uint32_t CPSW_STAT0_ALE_POL_MATCH_YELLOW;    /* Ethernet Port N ALE Policer Matched and Condition Yellow Register 0xA0C8h */
    uint32_t CPSW_STAT0_ALE_MULT_SA_DROP;        /* Enet Port N ALE Multicast Source Address Drop 0xA0CCh */
    uint32_t CPSW_STAT0_ALE_DUAL_VLAN_DROP;      /* Enet Port N ALE Dual VLAN Drop 0xA0D0h */
    uint32_t CPSW_STAT0_ALE_LEN_ERROR_DROP;      /* Enet Port N ALE IEEE 802.3 Length Error Drop 0xA0D4h */
    uint32_t CPSW_STAT0_ALE_IP_NEXT_HDR_DROP;    /* Enet Port N ALE IP Next Header Limit Drop 0xA0D8h */
    uint32_t CPSW_STAT0_ALE_IPV4_FRAG_DROP;      /* Enet Port N ALE IPv4 Fragment Drop 0xA0DCh */
    uint32_t __RESERVED4[SIZE(0xA0E0, 0xA140)];
    uint32_t CPSW_STAT0_IET_RX_ASSEMBLY_ERROR_REG;  /* Enet Port N IET Received Assembly Error 0xA140h */
    uint32_t CPSW_STAT0_IET_RX_ASSEMBLY_OK_REG;     /* Enet Port N IET Received Assembly OK 0xA144h */
    uint32_t CPSW_STAT0_IET_RX_SMD_ERROR_REG;       /* Enet Port N IET Received SMD Error 0xA148h */
    uint32_t CPSW_STAT0_IET_RX_FRAG_REG;            /* Enet Port N IET Received Fragment (IET fragment) 0xA14Ch */
    uint32_t CPSW_STAT0_IET_TX_HOLD_REG;            /* Enet Port N IET Transmit Hold 0xA150h */
    uint32_t CPSW_STAT0_IET_TX_FRAG_REG;            /* Enet Port N IET Transmit Fragment (IET fragment) 0xA154h */
    uint32_t __RESERVED5[SIZE(0xA158, 0xA17C)];
    uint32_t CPSW_STAT0_TX_MEMORY_PROTECT_ERROR;    /* Ethernet Port N Transmit Memory Protect CRC Error Register 0xA17Ch */
 };

 struct MCU_CPSW0_NUSS_STAT1 {

    uint32_t CPSW_STAT1_RXGOODFRAMES;           /* Ethernet Port N Total Number of Good Frames Received 0xA200h */
    uint32_t CPSW_STAT1_RXBROADCASTFRAMES;      /* Ethernet Port N Total Number of Good Broadcast Frames Received 0xA204h */
    uint32_t CPSW_STAT1_RXMULTICASTFRAMES;      /* Ethernet Port N Total Number of Good Multicast Frames Received 0xA208h */
    uint32_t CPSW_STAT1_RXPAUSEFRAMES;          /* Ethernet Port N PauseRxFrames 0xA20Ch */
    uint32_t CPSW_STAT1_RXCRCERRORS;            /* Ethernet Port N Total Number of CRC Errors Frames Received 0xA210h */
    uint32_t CPSW_STAT1_RXALIGNCODEERRORS;      /* Ethernet Port N Total Number of Align/Code Errors Received 0xA214h */
    uint32_t CPSW_STAT1_RXOVERSIZEDFRAMES;      /* Ethernet Port N Total Number of Oversized Frames Received 0xA218h */
    uint32_t CPSW_STAT1_RXJABBERFRAMES;         /* Ethernet Port N Total Number of Jabber Frames Received 0xA21Ch */
    uint32_t CPSW_STAT1_RXUNDERSIZEDFRAMES;     /* Ethernet Port N Total Number of Undersized Frames Received 0xA220h */
    uint32_t CPSW_STAT1_RXFRAGMENTS;            /* Ethernet Port N Fragments Received Register 0xA224h */
    uint32_t CPSW_STAT1_ALE_DROP;               /* Ethernet Port N ALE Drop Register 0xA228h */
    uint32_t CPSW_STAT1_ALE_OVERRUN_DROP;       /* Ethernet Port N ALE Overrun Drop Register 0xA22Ch */
    uint32_t CPSW_STAT1_RXOCTETS;               /* Ethernet Port N Total Number of Received Bytes in Good Frames 0xA230h */
    uint32_t CPSW_STAT1_TXGOODFRAMES;           /* Ethernet Port N Good Transmit Frames Register 0xA234h */
    uint32_t CPSW_STAT1_TXBROADCASTFRAMES;      /* Ethernet Port N Broadcast Transmit Frames Register 0xA238h */
    uint32_t CPSW_STAT1_TXMULTICASTFRAMES;      /* Ethernet Port N Multicast Transmit Frames Register 0xA23Ch */
    uint32_t CPSW_STAT1_TXPAUSEFRAMES;          /* Ethernet Port N Pause Transmit Frames Register 0xA240h */
    uint32_t CPSW_STAT1_TXDEFERREDFRAMES;       /* Ethernet Port N Deferred Frames Register 0xA244h */
    uint32_t CPSW_STAT1_TXCOLLISIONFRAMES;      /* Ethernet Port N Collisions Register 0xA248h */
    uint32_t CPSW_STAT1_TXSINGLECOLLFRAMES;     /* Ethernet Port N Collision Transmit Frames Register 0xA24Ch */
    uint32_t CPSW_STAT1_TXMULTCOLLFRAMES;       /* Ethernet Port N Multiple Collision Transmit Frames Register 0xA250h */
    uint32_t CPSW_STAT1_TXEXCESSIVECOLLISIONS;  /* Ethernet Port N Excessive Collision Transmit Frames Register 0xA254h */
    uint32_t CPSW_STAT1_TXLATECOLLISIONS;       /* Ethernet Port N Late Collisions Register 0xA258h */
    uint32_t CPSW_STAT1_RXIPGERROR;             /* Ethernet Port N Receive Inter Packet Gap Error (10G only) Register 0xA25Ch */
    uint32_t CPSW_STAT1_TXCARRIERSENSEERRORS;   /* Ethernet Port N Carrier Sense Errors Register 0xA260h */
    uint32_t CPSW_STAT1_TXOCTETS;               /* Ethernet Port N Tx Octets Register 0xA264h */
    uint32_t CPSW_STAT1_OCTETFRAMES64;          /* Ethernet Port N 64 Octet Frames Register 0xA268h */
    uint32_t CPSW_STAT1_OCTETFRAMES65T127;      /* Ethernet Port N 65-127 Octet Frames Register 0xA26Ch */
    uint32_t CPSW_STAT1_OCTETFRAMES128T255;     /* Ethernet Port N 128-255 Octet Frames Register 0xA270h */
    uint32_t CPSW_STAT1_OCTETFRAMES256T511;     /* Ethernet Port N 256-511 Octet Frames Register 0xA274h */
    uint32_t CPSW_STAT1_OCTETFRAMES512T1023;    /* Ethernet Port N 512-pn_rx_maxlen Octet Frames Register 0xA278h */
    uint32_t CPSW_STAT1_OCTETFRAMES1024TUP;     /* Ethernet Port N 1023-1518 Octet Frames Register 0xA27Ch */
    uint32_t CPSW_STAT1_NETOCTETS;              /* Ethernet Port N Net Octets Register 0xA280h */
    uint32_t CPSW_STAT1_RX_BOTTOM_OF_FIFO_DROP; /* Ethernet Port N Receive Bottom of FIFO Drop Register 0xA284h */
    uint32_t CPSW_STAT1_PORTMASK_DROP;          /* Ethernet Port N Portmask Drop Register 0xA288h */
    uint32_t CPSW_STAT1_RX_TOP_OF_FIFO_DROP;    /* Ethernet Port N Receive Top of FIFO Drop Register 0xA28Ch */
    uint32_t CPSW_STAT1_ALE_RATE_LIMIT_DROP;    /* Ethernet Port N ALE Rate Limit Drop Register 0xA290h */
    uint32_t CPSW_STAT1_ALE_VID_INGRESS_DROP;   /* Ethernet Port N ALE VID Ingress Drop Register 0xA294h */
    uint32_t CPSW_STAT1_ALE_DA_EQ_SA_DROP;      /* Ethernet Port N ALE DA equal SA Drop Register 0xA298h */
    uint32_t CPSW_STAT1_ALE_BLOCK_DROP;         /* Ethernet Port N ALE Block Drop Register 0xA29Ch */
    uint32_t CPSW_STAT1_ALE_SECURE_DROP;        /* Ethernet Port N ALE Secure Drop Register 0xA2A0h */
    uint32_t CPSW_STAT1_ALE_AUTH_DROP;          /* Ethernet Port N ALE Authentication Drop Register 0xA2A4h */
    uint32_t CPSW_STAT1_ALE_UNKN_UNI;           /* Ethernet Port N ALE Receive Unknown Unicast Register 0xA2A8h */
    uint32_t CPSW_STAT1_ALE_UNKN_UNI_BCNT;      /* Ethernet Port N Receive Unknown Unicast Bytecount Register 0xA2ACh */
    uint32_t CPSW_STAT1_ALE_UNKN_MLT;           /* Ethernet Port N ALE Receive Unknown Multicast Register 0xA2B0h */
    uint32_t CPSW_STAT1_ALE_UNKN_MLT_BCNT;      /* Ethernet Port N ALE Receive Unknown Multicast Bytecount Register 0xA2B4h */
    uint32_t CPSW_STAT1_ALE_UNKN_BRD;           /* Ethernet Port N ALE Receive Unknown Broadcast Register 0xA2B8h */
    uint32_t CPSW_STAT1_ALE_UNKN_BRD_BCNT;      /* Ethernet Port N ALE Receive Unknown Broadcast Bytecount Register 0xA2BCh */
    uint32_t CPSW_STAT1_ALE_POL_MATCH;          /* Ethernet Port N ALE Policer Matched Register 0xA2C0h */
    uint32_t CPSW_STAT1_ALE_POL_MATCH_RED;      /* Ethernet Port N ALE Policer Matched and Condition Red Register 0xA2C4h */
    uint32_t CPSW_STAT1_ALE_POL_MATCH_YELLOW;   /* Ethernet Port N ALE Policer Matched and Condition Yellow Register 0xA2C8h */
    uint32_t CPSW_STAT1_ALE_MULT_SA_DROP;       /* Enet Port N ALE Multicast Source Address Drop 0xA2CCh */
    uint32_t CPSW_STAT1_ALE_DUAL_VLAN_DROP;     /* Enet Port N ALE Dual VLAN Drop 0xA2D0h */
    uint32_t CPSW_STAT1_ALE_LEN_ERROR_DROP;     /* Enet Port N ALE IEEE 802.3 Length Error Drop 0xA2D4h */
    uint32_t CPSW_STAT1_ALE_IP_NEXT_HDR_DROP;   /* Enet Port N ALE IP Next Header Limit Drop 0xA2D8h */
    uint32_t CPSW_STAT1_ALE_IPV4_FRAG_DROP;     /* Enet Port N ALE IPv4 Fragment Drop 0xA2DCh */
    uint32_t __RESERVED0[SIZE(0xA2E0, 0xA340)];
    uint32_t CPSW_STAT1_IET_RX_ASSEMBLY_ERROR_REG; /* Enet Port N IET Received Assembly Error 0xA340h */
    uint32_t CPSW_STAT1_IET_RX_ASSEMBLY_OK_REG; /* Enet Port N IET Received Assembly OK 0xA344h */
    uint32_t CPSW_STAT1_IET_RX_SMD_ERROR_REG;   /* Enet Port N IET Received SMD Error 0xA348h */
 };




struct MCU_PLL0_CFG {

   uint32_t MCU_PLL0_PID;                       /* Peripheral Identification Register 0000h */
   uint32_t __RESERVED0[SIZE(0x0004, 0x0008)];
   uint32_t MCU_PLL0_CFG;                       /* PLL Configuration 0008h */
   uint32_t __RESERVED1[SIZE(0x000C, 0x0010)];
   uint32_t MCU_PLL0_LOCKKEY0;                  /* PLL0 Lock Key 0 Register 0010h */
   uint32_t MCU_PLL0_LOCKKEY1;                  /* PLL0 Lock Key 1 RegisterAddr 0014h */
   uint32_t __RESERVED2[SIZE(0x0018, 0x0020)];
   uint32_t MCU_PLL0_CTRL;                      /* PLL0 Control 0020h */
   uint32_t MCU_PLL0_STAT;                      /* PLL0 Status 0024h */
   uint32_t __RESERVED3[SIZE(0x0028, 0x0030)];
   uint32_t MCU_PLL0_FREQ_CTRL0;                /* PLL0 Frequency Control 0 Register 0030h */
   uint32_t MCU_PLL0_FREQ_CTRL1;                /* PLL0 Frequency Control 1 Register 0034h */
   uint32_t MCU_PLL0_DIV_CTRL;                  /* PLL0 Output Clock Divider Register 0038h */
   uint32_t __RESERVED4[SIZE(0x003C, 0x0040)];
   uint32_t MCU_PLL0_SS_CTRL;                   /* PLL_SS_CTRL register for pll0 0040h */
   uint32_t MCU_PLL0_SS_SPREAD;                 /* PLL_SS_SPREAD register for pll0 0044h */
   uint32_t __RESERVED5[SIZE(0x0048, 0x0080)];
   uint32_t MCU_PLL0_HSDIV_CTRL0;               /* HSDIV_CTRL0 register for pll0 0080h */
   uint32_t MCU_PLL0_HSDIV_CTRL1;               /* HSDIV_CTRL1 register for pll0 0084h */
   uint32_t __RESERVED6[SIZE(0x0088, 0x1000)];
   uint32_t MCU_PLL1_PID;                       /* Peripheral Identification Register 1000h */
   uint32_t __RESERVED7[SIZE(0x1004, 0x1008)];
   uint32_t MCU_PLL1_CFG;                       /* PLL Configuration 1008h */
   uint32_t __RESERVED8[SIZE(0x100C, 0x1010)];
   uint32_t MCU_PLL1_LOCKKEY0;                  /* PLL1 Lock Key 0 Register 1010h */
   uint32_t MCU_PLL1_LOCKKEY1;                  /* PLL1 Lock Key 1 RegisterAddr 1014h */
   uint32_t __RESERVED9[SIZE(0x1018, 0x1020)];
   uint32_t MCU_PLL1_CTRL;                      /* PLL1 Control 1020h */
   uint32_t MCU_PLL1_STAT;                      /* PLL1 Status 1024h */
   uint32_t __RESERVED10[SIZE(0x1028, 0x1030)];
   uint32_t MCU_PLL1_FREQ_CTRL0;                /* PLL1 Frequency Control 1 Register 1030h */
   uint32_t MCU_PLL1_FREQ_CTRL1;                /* PLL0 Frequency Control 1 Register 1034h */
   uint32_t MCU_PLL1_DIV_CTRL;                  /* PLL1 Output Clock Divider Register 1038h */
   uint32_t __RESERVED11[SIZE(0x103C, 0x1040)];
   uint32_t MCU_PLL1_SS_CTRL;                   /* PLL_SS_CTRL register for pll1 1040h */
   uint32_t MCU_PLL1_SS_SPREAD;                 /* PLL_SS_SPREAD register for pll1 1044h */
   uint32_t __RESERVED12[SIZE(0x1048, 0x1080)];
   uint32_t MCU_PLL1_HSDIV_CTRL0;               /* HSDIV_CTRL0 register for pll1 1080h */
   uint32_t MCU_PLL1_HSDIV_CTRL1;               /* HSDIV_CTRL1 register for pll1 1084h */
   uint32_t MCU_PLL1_HSDIV_CTRL2;               /* HSDIV_CTRL2 register for pll1 1088h */
   uint32_t MCU_PLL1_HSDIV_CTRL3;               /* HSDIV_CTRL3 register for pll1 108Ch */
   uint32_t MCU_PLL1_HSDIV_CTRL4;               /* HSDIV_CTRL4 register for pll1 1090h */
   uint32_t __RESERVED13[SIZE(0x1094, 0x2000)];
   uint32_t MCU_PLL2_PID;                       /* Peripheral Identification Register 2000h */
   uint32_t __RESERVED14[SIZE(0x2004, 0x2008)];
   uint32_t MCU_PLL2_CFG;                       /* PLL Configuration 2008h */
   uint32_t __RESERVED15[SIZE(0x200C, 0x2010)];
   uint32_t MCU_PLL2_LOCKKEY0;                  /* PLL2 Lock Key 0 Register 2010h */
   uint32_t MCU_PLL2_LOCKKEY1;                  /* PLL2 Lock Key 1 RegisterAddr 2014h */
   uint32_t __RESERVED16[SIZE(0x2018, 0x2020)];
   uint32_t MCU_PLL2_CTRL;                      /* PLL2 Control 2020h */
   uint32_t MCU_PLL2_STAT;                      /* PLL2 Status 2024h */
   uint32_t __RESERVED17[SIZE(0x2028, 0x2030)];
   uint32_t MCU_PLL2_FREQ_CTRL0;                /* PLL2 Frequency Control 2 Register 2030h */
   uint32_t MCU_PLL2_FREQ_CTRL1;                /* PLL0 Frequency Control 1 Register 2034h */
   uint32_t MCU_PLL2_DIV_CTRL;                  /* PLL2 Output Clock Divider Register 2038h */
   uint32_t __RESERVED18[SIZE(0x203C, 0x2040)];
   uint32_t MCU_PLL2_SS_CTRL;                   /* PLL_SS_CTRL register for pll2 2040h */
   uint32_t MCU_PLL2_SS_SPREAD;                 /* PLL_SS_SPREAD register for pll2 2044h */
   uint32_t __RESERVED19[SIZE(0x2048, 0x2080)];
   uint32_t MCU_PLL2_HSDIV_CTRL0;               /* HSDIV_CTRL0 register for pll2 2080h */
   uint32_t MCU_PLL2_HSDIV_CTRL1;               /* HSDIV_CTRL1 register for pll2 2084h */
   uint32_t MCU_PLL2_HSDIV_CTRL2;               /* HSDIV_CTRL2 register for pll2 2088h */
   uint32_t MCU_PLL2_HSDIV_CTRL3;               /* HSDIV_CTRL3 register for pll2 208Ch */
   uint32_t MCU_PLL2_HSDIV_CTRL4;               /* HSDIV_CTRL4 register for pll2 2090h */
};

#define MCU_PLL_HSDIV_CTRL_EN          (1 << 15)
#define MCU_PLL_HSDIV_CTRL_SYNC_DIS    (1 << 8)
#define MCU_PLL_HSDIV_CTRL_HDIV        (0x7f << 0)

#endif /* NET_TDM4VA_REGS */
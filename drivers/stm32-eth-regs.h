/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module register definitions
 *
 * Based on RM0486 STM32N647/657xx Reference manual by STMicroelectronics
 * Register offsets and bit positions cross-checked with ETH_TypeDef and ETH_* bit definitions
 * in cmsis-device-n6 (stm32n657xx.h @ 81fe2fe8d576ec4c55be308ac4504bd580e498e6).
 *
 * Copyright 2026 Phoenix Systems
 * Author: Jacek Maksymowicz
 *
 * %LICENSE%
 */


#ifndef _STM32_ETH_REGS_H_
#define _STM32_ETH_REGS_H_

enum eth_regs {
	eth_maccr = 0x0,
	eth_macecr,
	eth_macpfr,
	eth_macwtr,
	eth_macht0r,
	eth_macht1r,
	eth_macvtcr = 0x14,
	eth_macvtdr,
	eth_macvhtr,
	eth_macvir = 0x18,
	eth_macvir_alternate = 0x18,
	eth_macivir,
	eth_macq0txfcr = 0x1c,
	eth_macrxfcr = 0x24,
	eth_macrxqcr,
	eth_macrxqc0r = 0x28,
	eth_macrxqc1r,
	eth_macrxqc2r,
	eth_macisr = 0x2c,
	eth_macier,
	eth_macrxtxsr,
	eth_macpcsr = 0x30,
	eth_macrwkpfr,
	eth_maclcsr = 0x34,
	eth_macltcr,
	eth_macletr,
	eth_mac1ustcr,
	eth_macphycsr = 0x3e,
	eth_macvr = 0x44,
	eth_macdr,
	eth_machwf0r = 0x47,
	eth_machwf1r,
	eth_machwf2r,
	eth_machwf3r,
	eth_macmdioar = 0x80,
	eth_macmdiodr,
	eth_macarpar = 0x84,
	eth_maccsrswcr = 0x8c,
	eth_macfpecsr,
	eth_macprstimr = 0x90,
	eth_macprstimur,
	eth_maca0hr = 0xc0,
	eth_maca0lr,
	eth_maca1hr,
	eth_maca1lr,
	eth_maca2hr,
	eth_maca2lr,
	eth_maca3hr,
	eth_maca3lr,

	eth_mmc_control = 0x1c0,
	eth_mmc_rx_interrupt,
	eth_mmc_tx_interrupt,
	eth_mmc_rx_interrupt_mask,
	eth_mmc_tx_interrupt_mask,
	eth_tx_single_collision_good_packets = 0x1d3,
	eth_tx_multiple_collision_good_packets,
	eth_tx_packet_count_good = 0x1da,
	eth_rx_crc_error_packets = 0x1e5,
	eth_rx_alignment_error_packets,
	eth_rx_unicast_packets_good = 0x1f1,
	eth_tx_lpi_usec_cntr = 0x1fb,
	eth_tx_lpi_tran_cntr,
	eth_rx_lpi_usec_cntr,
	eth_rx_lpi_tran_cntr,
	eth_mmc_fpe_tx_isr = 0x228,
	eth_mmc_fpe_tx_imr,
	eth_mmc_fpe_tx_fcr,
	eth_mmc_tx_hrcr,
	eth_mmc_fpe_rx_isr = 0x230,
	eth_mmc_fpe_rx_imr,
	eth_rx_packet_asm_err,
	eth_rx_packet_smd_err,
	eth_rx_packet_asm_okr,
	eth_rx_fpe_frag_cr,

	eth_macl3l4c0r = 0x240,
	eth_macl4a0r,
	eth_macl3a00r = 0x244,
	eth_macl3a10r,
	eth_macl3a20r,
	eth_macl3a30r,
	eth_macl3l4c1r = 0x24c,
	eth_macl4a1r,
	eth_macl3a01r = 0x250,
	eth_macl3a11r,
	eth_macl3a21r,
	eth_macl3a31r,
	eth_mac_iacr = 0x29c,
	eth_mac_tmrqr,
	eth_mactscr = 0x2c0,
	eth_macssir,
	eth_macstsr,
	eth_macstnr,
	eth_macstsur,
	eth_macstnur,
	eth_mactsar,
	eth_mactssr = 0x2c8,
	eth_mactxtssnr = 0x2cc,
	eth_mactxtsssr,
	eth_macacr = 0x2d0,
	eth_macatsnr = 0x2d2,
	eth_macatssr,
	eth_mactsiacr,
	eth_mactseacr,
	eth_mactsicnr,
	eth_mactsecnr,
	eth_mactsilr = 0x2da,
	eth_mactselr,
	eth_macppscr,
	eth_macppscr_alternate = 0x2dc,
	eth_macppstts0r = 0x2e0,
	eth_macppsttn0r,
	eth_macppsi0r,
	eth_macppsw0r,
	eth_macppstts1r,
	eth_macppsttn1r,
	eth_macppsi1r,
	eth_macppsw1r,
	eth_macpocr = 0x2f0,
	eth_macspi0r,
	eth_macspi1r,
	eth_macspi2r,
	eth_maclmir,

	eth_mtlomr = 0x300,
	eth_mtlisr = 0x308,
	eth_mtlrxqdmamr = 0x30c,
	eth_mtltbscr = 0x310,
	eth_mtlestcr = 0x314,
	eth_mtlestecr,
	eth_mtlestsr,
	eth_mtlestscher = 0x318,
	eth_mtlestfser,
	eth_mtlestfscr,
	eth_mtlestier = 0x31c,
	eth_mtlestgclcr = 0x320,
	eth_mtlestgcldr,
	eth_mtlfpecsr = 0x324,
	eth_mtlfpear,
	eth_mtltxq0omr = 0x340,
	eth_mtltxq0ur,
	eth_mtltxq0dr,
	eth_mtltxq0esr = 0x345,
	eth_mtltxq0qwr,
	eth_mtlq0icsr = 0x34b,
	eth_mtlrxq0omr,
	eth_mtlrxq0mpocr,
	eth_mtlrxq0dr,
	eth_mtlrxq0cr,
	eth_mtltxq1omr,
	eth_mtltxq1ur,
	eth_mtltxq1dr,
	eth_mtltxq1ecr = 0x354,
	eth_mtltxq1esr,
	eth_mtltxq1qwr,
	eth_mtltxq1sscr,
	eth_mtltxq1hcr,
	eth_mtltxq1lcr,
	eth_mtlq1icsr = 0x35b,
	eth_mtlrxq1omr,
	eth_mtlrxq1mpocr,
	eth_mtlrxq1dr,
	eth_mtlrxq1cr,

	eth_dmamr = 0x400,
	eth_dmasbmr,
	eth_dmaisr,
	eth_dmadsr,
	eth_dmaa4txacr = 0x408,
	eth_dmaa4rxacr,
	eth_dmaa4dacr,
	eth_dmalpiei = 0x410,
	eth_dmatbsctrl0r = 0x414,
	eth_dmac0cr = 0x440,
	eth_dmac0txcr,
	eth_dmac0rxcr,
	eth_dmac0txdlar = 0x445,
	eth_dmac0rxdlar = 0x447,
	eth_dmac0txdtpr,
	eth_dmac0rxdtpr = 0x44a,
	eth_dmac0txrlr,
	eth_dmac0rxrlr,
	eth_dmac0ier,
	eth_dmac0rxiwtr,
	eth_dmac0sfcsr,
	eth_dmac0catxdr = 0x451,
	eth_dmac0carxdr = 0x453,
	eth_dmac0catxbr = 0x455,
	eth_dmac0carxbr = 0x457,
	eth_dmac0sr,
	eth_dmac0mfcr,
	eth_dmac1cr = 0x460,
	eth_dmac1txcr,
	eth_dmac1rxcr,
	eth_dmac1txdlar = 0x465,
	eth_dmac1txdtpr = 0x468,
	eth_dmac1rxdtpr = 0x46a,
	eth_dmac1txrlr,
	eth_dmac1rxrlr,
	eth_dmac1ier,
	eth_dmac1rxiwtr,
	eth_dmac1sfcsr,
	eth_dmac1catxdr = 0x471,
	eth_dmac1carxdr = 0x473,
	eth_dmac1catxbr = 0x475,
	eth_dmac1carxbr = 0x477,
	eth_dmac1sr,
	eth_dmac1mfcr,
};


#define ETH_MACCR_RE           (1UL << 0) /* Receive enable */
#define ETH_MACCR_TE           (1UL << 1) /* Transmit enable */
#define ETH_MACCR_PRELEN_SHIFT 2          /* Preamble length */
#define ETH_MACCR_PRELEN_MASK  (0x3UL << ETH_MACCR_PRELEN_SHIFT)
#define ETH_MACCR_DC           (1UL << 4)
#define ETH_MACCR_BL_SHIFT     5 /* Back-off limit */
#define ETH_MACCR_BL_MASK      (0x3UL << ETH_MACCR_BL_SHIFT)
#define ETH_MACCR_DR           (1UL << 8)  /* Disable retry */
#define ETH_MACCR_DCRS         (1UL << 9)  /* Disable carrier sense during TX */
#define ETH_MACCR_DO           (1UL << 10) /* Disable receive own in half-duplex mode */
#define ETH_MACCR_ECRSFD       (1UL << 11) /* Enable carrier sense before TX in full-duplex mode */
#define ETH_MACCR_LM           (1UL << 12) /* Loopback mode */
#define ETH_MACCR_DM           (1UL << 13) /* Duplex mode */
#define ETH_MACCR_FES          (1UL << 14) /* 0 = 10 Mbps,  1 = 100 Mbps */
#define ETH_MACCR_PS           (1UL << 15) /* 0 = 1 Gbps, 1 = 10/100 Mbps */
#define ETH_MACCR_JE           (1UL << 16) /* Enable jumbo packet */
#define ETH_MACCR_JD           (1UL << 17) /* Disable jabber timer  */
#define ETH_MACCR_BE           (1UL << 18) /* Enable packet burst */
#define ETH_MACCR_WD           (1UL << 19) /* Disable watchdog */
#define ETH_MACCR_ACS          (1UL << 20) /* Automatically strip padding or CRC */
#define ETH_MACCR_CST          (1UL << 21) /* Strip CRC for Type packets */
#define ETH_MACCR_S2KP         (1UL << 22) /* Support 2K packet */
#define ETH_MACCR_GPSLCE       (1UL << 23) /* Enable giant packet size limit control */
#define ETH_MACCR_IPG_SHIFT    24          /* Inter-packet gap */
#define ETH_MACCR_IPG_MASK     (0x7UL << ETH_MACCR_IPG_SHIFT)
#define ETH_MACCR_IPC          (1UL << 27) /* Checksum offload */
#define ETH_MACCR_SARC_SHIFT   28          /* Source address insertion/replacement */
#define ETH_MACCR_SARC_MASK    (0x7UL << ETH_MACCR_SARC_SHIFT)
#define ETH_MACCR_ARPEN        (1UL << 31) /* Enable ARP offload */

#define ETH_MACECR_GPSL_SHIFT 0
#define ETH_MACECR_GPSL_MASK  (0x3fffUL << ETH_MACECR_GPSL_SHIFT)
#define ETH_MACECR_DCRCC      (1UL << 16)
#define ETH_MACECR_SPEN       (1UL << 17)
#define ETH_MACECR_USP        (1UL << 18)
#define ETH_MACECR_EIPGEN     (1UL << 24)
#define ETH_MACECR_EIPG_SHIFT 25
#define ETH_MACECR_EIPG_MASK  (0x1fUL << ETH_MACECR_EIPG_SHIFT)
#define ETH_MACECR_APDIM      (1UL << 30)

#define ETH_MACWTR_WTO_SHIFT 0
#define ETH_MACWTR_WTO_MASK  (0xfUL << ETH_MACWTR_WTO_SHIFT)
#define ETH_MACWTR_PWE       (1UL << 8)

#define ETH_MACPFR_PR        (1UL << 0)
#define ETH_MACPFR_HUC       (1UL << 1)
#define ETH_MACPFR_HMC       (1UL << 2)
#define ETH_MACPFR_DAIF      (1UL << 3)
#define ETH_MACPFR_PM        (1UL << 4)
#define ETH_MACPFR_DBF       (1UL << 5)
#define ETH_MACPFR_PCF_SHIFT 6
#define ETH_MACPFR_PCF_MASK  (0x3UL << ETH_MACPFR_PCF_SHIFT)
#define ETH_MACPFR_SAIF      (1UL << 8)
#define ETH_MACPFR_SAF       (1UL << 9)
#define ETH_MACPFR_HPF       (1UL << 10)
#define ETH_MACPFR_VTFE      (1UL << 16)
#define ETH_MACPFR_IPFE      (1UL << 20)
#define ETH_MACPFR_DNTU      (1UL << 21)
#define ETH_MACPFR_RA        (1UL << 31)

#define ETH_MACQ0TXFCR_FCB_BPA   (1UL << 0)
#define ETH_MACQ0TXFCR_TFE       (1UL << 1)
#define ETH_MACQ0TXFCR_PLT_SHIFT 4
#define ETH_MACQ0TXFCR_PLT_MASK  (0x7UL << ETH_MACQ0TXFCR_PLT_SHIFT)
#define ETH_MACQ0TXFCR_DZPQ      (1UL << 7)
#define ETH_MACQ0TXFCR_PT_SHIFT  16
#define ETH_MACQ0TXFCR_PT_MASK   (0xffffUL << ETH_MACQ0TXFCR_PT_SHIFT)

#define ETH_MACRXFCR_RFE (1UL << 0)
#define ETH_MACRXFCR_UP  (1UL << 1)

#define ETH_DMAMR_SWR        (1UL << 0)
#define ETH_DMAMR_TAA_SHIFT  2
#define ETH_DMAMR_TAA_MASK   (0x7UL << ETH_DMAMR_TAA_SHIFT)
#define ETH_DMAMR_DSPW       (1UL << 8)
#define ETH_DMAMR_TXPR       (1UL << 11)
#define ETH_DMAMR_INTM_SHIFT 16
#define ETH_DMAMR_INTM_MASK  (0x3UL << ETH_DMAMR_INTM_SHIFT)

#define ETH_MACMDIOAR_GB        (1UL << 0)
#define ETH_MACMDIOAR_C45E      (1UL << 1)
#define ETH_MACMDIOAR_GOC       (3UL << 2)
#define ETH_MACMDIOAR_GOC_WRITE (1UL << 2)
#define ETH_MACMDIOAR_GOC_READ  (3UL << 2)
#define ETH_MACMDIOAR_RDA_SHIFT 16
#define ETH_MACMDIOAR_RDA_MASK  (0x1fUL << ETH_MACMDIOAR_RDA_SHIFT)
#define ETH_MACMDIOAR_PA_SHIFT  21
#define ETH_MACMDIOAR_PA_MASK   (0x1fUL << ETH_MACMDIOAR_PA_SHIFT)
#define ETH_MACMDIOAR_PSE       (1UL << 27) /* Preamble suppression enable */

/* HW feature registers (read-only) */
#define ETH_MACHWF0R_ACTPHYSEL_SHIFT 28 /* Active PHY interface: 0 = MII, 1 = RGMII, 4 = RMII */
#define ETH_MACHWF0R_ACTPHYSEL_MASK  (0x7UL << ETH_MACHWF0R_ACTPHYSEL_SHIFT)

#define ETH_MACHWF1R_RXFIFOSIZE_SHIFT 0 /* RX FIFO size: 128 B << n */
#define ETH_MACHWF1R_RXFIFOSIZE_MASK  (0x1fUL << ETH_MACHWF1R_RXFIFOSIZE_SHIFT)
#define ETH_MACHWF1R_TXFIFOSIZE_SHIFT 6 /* TX FIFO size: 128 B << n */
#define ETH_MACHWF1R_TXFIFOSIZE_MASK  (0x1fUL << ETH_MACHWF1R_TXFIFOSIZE_SHIFT)
#define ETH_MACHWF1R_ADDR64_SHIFT     14 /* Address width: 0 = 32-bit, 1 = 40-bit, 2 = 48-bit */
#define ETH_MACHWF1R_ADDR64_MASK      (0x3UL << ETH_MACHWF1R_ADDR64_SHIFT)

#define ETH_MACHWF2R_RXQCNT_SHIFT  0 /* Number of MTL RX queues - 1 */
#define ETH_MACHWF2R_RXQCNT_MASK   (0xfUL << ETH_MACHWF2R_RXQCNT_SHIFT)
#define ETH_MACHWF2R_TXQCNT_SHIFT  6 /* Number of MTL TX queues - 1 */
#define ETH_MACHWF2R_TXQCNT_MASK   (0xfUL << ETH_MACHWF2R_TXQCNT_SHIFT)
#define ETH_MACHWF2R_RXCHCNT_SHIFT 12 /* Number of DMA RX channels - 1 */
#define ETH_MACHWF2R_RXCHCNT_MASK  (0xfUL << ETH_MACHWF2R_RXCHCNT_SHIFT)
#define ETH_MACHWF2R_TXCHCNT_SHIFT 18 /* Number of DMA TX channels - 1 */
#define ETH_MACHWF2R_TXCHCNT_MASK  (0xfUL << ETH_MACHWF2R_TXCHCNT_SHIFT)

/* MTL TX queue operating mode (MTLTXQxOMR) */
#define ETH_MTLTXQOMR_FTQ        (1UL << 0) /* Flush TX queue */
#define ETH_MTLTXQOMR_TSF        (1UL << 1) /* TX store and forward */
#define ETH_MTLTXQOMR_TXQEN_MASK (0x3UL << 2)
#define ETH_MTLTXQOMR_TXQEN_EN   (0x2UL << 2) /* TX queue enabled */
#define ETH_MTLTXQOMR_TTC_MASK   (0x7UL << 4)
#define ETH_MTLTXQOMR_TQS_SHIFT  16 /* TX queue size: 256 B * (n + 1) */
#define ETH_MTLTXQOMR_TQS_MASK   (0xfUL << ETH_MTLTXQOMR_TQS_SHIFT)

/* DMA system bus mode (DMASBMR) */
#define ETH_DMASBMR_FB               (1UL << 0)  /* Fixed burst length */
#define ETH_DMASBMR_BLEN4            (1UL << 1)  /* AXI burst length 4 */
#define ETH_DMASBMR_AAL              (1UL << 12) /* Address-aligned beats */
#define ETH_DMASBMR_RD_OSR_LMT_SHIFT 16          /* AXI maximum read outstanding request limit - 1 */
#define ETH_DMASBMR_RD_OSR_LMT_MASK  (0x3UL << ETH_DMASBMR_RD_OSR_LMT_SHIFT)
#define ETH_DMASBMR_WR_OSR_LMT_SHIFT 24 /* AXI maximum write outstanding request limit - 1 */
#define ETH_DMASBMR_WR_OSR_LMT_MASK  (0x3UL << ETH_DMASBMR_WR_OSR_LMT_SHIFT)
#define ETH_DMASBMR_CFG_MASK         0xc30334ffUL /* Fields configured by HAL (stm32n6xx_hal_eth.c: ETH_DMASBMR_MASK) */

/* DMA debug status (DMADSR) */
#define ETH_DMADSR_RPS0_SHIFT 8 /* RX process state, channel 0 */
#define ETH_DMADSR_RPS0_MASK  (0xfUL << ETH_DMADSR_RPS0_SHIFT)
#define ETH_DMADSR_TPS0_SHIFT 12 /* TX process state, channel 0: 0 = stopped, 6 = suspended */
#define ETH_DMADSR_TPS0_MASK  (0xfUL << ETH_DMADSR_TPS0_SHIFT)

#define ETH_DMADSR_TPS_STOPPED   0x0U
#define ETH_DMADSR_TPS_SUSPENDED 0x6U

/* DMA channel control (DMACxCR) */
#define ETH_DMACCR_MSS_MASK  (0x3fffUL << 0) /* Maximum segment size (TSO) */
#define ETH_DMACCR_PBLX8     (1UL << 16)     /* 8xPBL mode */
#define ETH_DMACCR_DSL_SHIFT 18              /* Descriptor skip length (in bus width units) */
#define ETH_DMACCR_DSL_MASK  (0x7UL << ETH_DMACCR_DSL_SHIFT)
#define ETH_DMACCR_CFG_MASK  0x001d3fffUL /* Fields configured by HAL (stm32n6xx_hal_eth.c: ETH_DMACxCR_MASK) */

/* DMA channel TX control (DMACxTXCR) */
#define ETH_DMACTXCR_ST          (1UL << 0)  /* Start or stop transmission */
#define ETH_DMACTXCR_OSF         (1UL << 4)  /* Operate on second packet */
#define ETH_DMACTXCR_TSE         (1UL << 12) /* TCP segmentation enable */
#define ETH_DMACTXCR_TXPBL_SHIFT 16          /* TX programmable burst length */
#define ETH_DMACTXCR_TXPBL_MASK  (0x3fUL << ETH_DMACTXCR_TXPBL_SHIFT)

/* DMA channel RX control (DMACxRXCR) */
#define ETH_DMACRXCR_SR          (1UL << 0) /* Start or stop receive */
#define ETH_DMACRXCR_RBSZ_SHIFT  1          /* RX buffer size in bytes (multiple of 4), register value = size << 1 */
#define ETH_DMACRXCR_RBSZ_MASK   (0x1fffUL << ETH_DMACRXCR_RBSZ_SHIFT)
#define ETH_DMACRXCR_RXPBL_SHIFT 16 /* RX programmable burst length */
#define ETH_DMACRXCR_RXPBL_MASK  (0x3fUL << ETH_DMACRXCR_RXPBL_SHIFT)
#define ETH_DMACRXCR_RPF         (1UL << 31) /* DMA RX packet flush */

/* DMA channel status (DMACxSR), write 1 to clear */
#define ETH_DMACSR_TI        (1UL << 0)  /* Transmit interrupt */
#define ETH_DMACSR_TPS       (1UL << 1)  /* Transmit process stopped */
#define ETH_DMACSR_TBU       (1UL << 2)  /* Transmit buffer unavailable */
#define ETH_DMACSR_RI        (1UL << 6)  /* Receive interrupt */
#define ETH_DMACSR_RBU       (1UL << 7)  /* Receive buffer unavailable */
#define ETH_DMACSR_RPS       (1UL << 8)  /* Receive process stopped */
#define ETH_DMACSR_ETI       (1UL << 10) /* Early transmit interrupt */
#define ETH_DMACSR_FBE       (1UL << 12) /* Fatal bus error */
#define ETH_DMACSR_CDE       (1UL << 13) /* Context descriptor error */
#define ETH_DMACSR_AIS       (1UL << 14) /* Abnormal interrupt summary */
#define ETH_DMACSR_NIS       (1UL << 15) /* Normal interrupt summary */
#define ETH_DMACSR_TEB_SHIFT 16          /* TX DMA error bits (valid with FBE) */
#define ETH_DMACSR_TEB_MASK  (0x7UL << ETH_DMACSR_TEB_SHIFT)
#define ETH_DMACSR_REB_SHIFT 19 /* RX DMA error bits (valid with FBE) */
#define ETH_DMACSR_REB_MASK  (0x7UL << ETH_DMACSR_REB_SHIFT)
#define ETH_DMACSR_W1C_MASK  0x0000ffffUL

/* TX normal descriptor, read format (stm32n6xx_hal_eth.h: ETH_DMATXNDESCRF_*) */
#define ETH_TDES2_B1L_MASK  0x3fffUL    /* Buffer 1 length */
#define ETH_TDES2_IOC       (1UL << 31) /* Interrupt on completion */
#define ETH_TDES3_FL_MASK   0x7fffUL    /* Packet length */
#define ETH_TDES3_CPC_SHIFT 26          /* CRC/pad control: 0 = insert CRC and pad */
#define ETH_TDES3_CPC_MASK  (0x3UL << ETH_TDES3_CPC_SHIFT)
#define ETH_TDES3_LD        (1UL << 28) /* Last descriptor */
#define ETH_TDES3_FD        (1UL << 29) /* First descriptor */
#define ETH_TDES3_CTXT      (1UL << 30) /* Context type */
#define ETH_TDES3_OWN       (1UL << 31) /* Owned by DMA */

/*
 * TX normal descriptor, write-back format, TDES3 status (valid in the last descriptor of a packet):
 * stm32n6xx_hal_eth.h ETH_DMATXNDESCWBF_* and Linux stmmac dwmac4_descs.h TDES3_*.
 * NOTE: HAL defines ETH_DMATXNDESCWBF_IHE as 0x4 (= UF) - IHE is bit 0 (stmmac TDES3_IP_HDR_ERROR).
 * OWN, CTXT, FD and LD have the same positions as in the read format.
 */
#define ETH_TDES3_WB_IHE      (1UL << 0) /* IP header error */
#define ETH_TDES3_WB_DB       (1UL << 1) /* Deferred bit */
#define ETH_TDES3_WB_UF       (1UL << 2) /* Underflow error */
#define ETH_TDES3_WB_ED       (1UL << 3) /* Excessive deferral */
#define ETH_TDES3_WB_CC_SHIFT 4          /* Collision count */
#define ETH_TDES3_WB_CC_MASK  (0xfUL << ETH_TDES3_WB_CC_SHIFT)
#define ETH_TDES3_WB_EC       (1UL << 8)  /* Excessive collision */
#define ETH_TDES3_WB_LC       (1UL << 9)  /* Late collision */
#define ETH_TDES3_WB_NC       (1UL << 10) /* No carrier */
#define ETH_TDES3_WB_LOC      (1UL << 11) /* Loss of carrier */
#define ETH_TDES3_WB_PCE      (1UL << 12) /* Payload checksum error */
#define ETH_TDES3_WB_FF       (1UL << 13) /* Packet flushed */
#define ETH_TDES3_WB_JT       (1UL << 14) /* Jabber timeout */
#define ETH_TDES3_WB_ES       (1UL << 15) /* Error summary */
#define ETH_TDES3_WB_ERR_MASK \
	(ETH_TDES3_WB_IHE | ETH_TDES3_WB_UF | ETH_TDES3_WB_ED | ETH_TDES3_WB_EC | ETH_TDES3_WB_LC | ETH_TDES3_WB_NC | \
			ETH_TDES3_WB_LOC | ETH_TDES3_WB_PCE | ETH_TDES3_WB_FF | ETH_TDES3_WB_JT | ETH_TDES3_WB_ES)

/*
 * RX normal descriptor, read format (stm32n6xx_hal_eth.h ETH_DMARXNDESCRF_*, Linux stmmac RDES3_*):
 * RDES0 = buffer 1 address, RDES1 reserved, RDES2 = buffer 2 address
 */
#define ETH_RDES3_BUF1V (1UL << 24) /* Buffer 1 address valid */
#define ETH_RDES3_BUF2V (1UL << 25) /* Buffer 2 address valid */
#define ETH_RDES3_IOC   (1UL << 30) /* Interrupt on completion */
#define ETH_RDES3_OWN   (1UL << 31) /* Owned by DMA */

/* RX normal descriptor, write-back format, RDES3 (ETH_DMARXNDESCWBF_*, stmmac RDES3_*) */
#define ETH_RDES3_WB_PL_MASK  0x7fffUL    /* Packet length (valid with LD) */
#define ETH_RDES3_WB_ES       (1UL << 15) /* Error summary */
#define ETH_RDES3_WB_LT_SHIFT 16          /* Length/type field */
#define ETH_RDES3_WB_LT_MASK  (0x7UL << ETH_RDES3_WB_LT_SHIFT)
#define ETH_RDES3_WB_DE       (1UL << 19) /* Dribble bit error */
#define ETH_RDES3_WB_RE       (1UL << 20) /* Receive error */
#define ETH_RDES3_WB_OE       (1UL << 21) /* Overflow error */
#define ETH_RDES3_WB_RWT      (1UL << 22) /* Receive watchdog timeout */
#define ETH_RDES3_WB_GP       (1UL << 23) /* Giant packet */
#define ETH_RDES3_WB_CE       (1UL << 24) /* CRC error */
#define ETH_RDES3_WB_RS0V     (1UL << 25) /* RDES0 status valid */
#define ETH_RDES3_WB_RS1V     (1UL << 26) /* RDES1 status valid */
#define ETH_RDES3_WB_RS2V     (1UL << 27) /* RDES2 status valid */
#define ETH_RDES3_WB_LD       (1UL << 28) /* Last descriptor */
#define ETH_RDES3_WB_FD       (1UL << 29) /* First descriptor */
#define ETH_RDES3_WB_CTXT     (1UL << 30) /* Context descriptor */
#define ETH_RDES3_WB_OWN      (1UL << 31) /* Owned by DMA */
#define ETH_RDES3_WB_ERR_MASK \
	(ETH_RDES3_WB_ES | ETH_RDES3_WB_DE | ETH_RDES3_WB_RE | ETH_RDES3_WB_OE | ETH_RDES3_WB_RWT | ETH_RDES3_WB_GP | ETH_RDES3_WB_CE)

/* MTL RX queue operating mode (MTLRXQxOMR) */
#define ETH_MTLRXQOMR_RTC_MASK  (0x3UL << 0)
#define ETH_MTLRXQOMR_FUP       (1UL << 3) /* Forward undersized good packets */
#define ETH_MTLRXQOMR_FEP       (1UL << 4) /* Forward error packets */
#define ETH_MTLRXQOMR_RSF       (1UL << 5) /* RX store and forward */
#define ETH_MTLRXQOMR_DISTCPEF  (1UL << 6) /* Disable dropping of TCP/IP checksum error packets */
#define ETH_MTLRXQOMR_EHFC      (1UL << 7) /* Enable hardware flow control */
#define ETH_MTLRXQOMR_RFA_MASK  (0x7UL << 8)
#define ETH_MTLRXQOMR_RFD_MASK  (0x7UL << 14)
#define ETH_MTLRXQOMR_RQS_SHIFT 20 /* RX queue size: 256 B * (n + 1) */
#define ETH_MTLRXQOMR_RQS_MASK  (0xfUL << ETH_MTLRXQOMR_RQS_SHIFT)

/* MTL RX queue missed packet and overflow counter (MTLRXQxMPOCR), cleared on read */
#define ETH_MTLRXQMPOCR_OVFPKTCNT_MASK  0x7ffUL
#define ETH_MTLRXQMPOCR_OVFCNTOVF       (1UL << 11) /* overflow counter crossed its maximum */
#define ETH_MTLRXQMPOCR_MISPKTCNT_SHIFT 16
#define ETH_MTLRXQMPOCR_MISPKTCNT_MASK  (0x7ffUL << ETH_MTLRXQMPOCR_MISPKTCNT_SHIFT)
#define ETH_MTLRXQMPOCR_MISCNTOVF       (1UL << 27) /* missed counter crossed its maximum */

/* DMA channel missed frame count (DMACxMFCR), cleared on read */
#define ETH_DMACMFCR_MFC_MASK 0x7ffUL
#define ETH_DMACMFCR_MFCO     (1UL << 15) /* counter crossed its maximum */

/* MAC RX queue control 0 (MACRXQC0R) */
#define ETH_MACRXQC0R_RXQ0EN_MASK (0x3UL << 0)
#define ETH_MACRXQC0R_RXQ0EN_GT   (0x2UL << 0) /* RX queue 0 enabled for generic traffic (HAL ETH_RX_QUEUE0_ENABLED) */

/* DMA channel interrupt enable (DMACxIER), same layout as DMACxSR */
#define ETH_DMACIER_TIE  (1UL << 0)
#define ETH_DMACIER_TXSE (1UL << 1)
#define ETH_DMACIER_TBUE (1UL << 2)
#define ETH_DMACIER_RIE  (1UL << 6)
#define ETH_DMACIER_RBUE (1UL << 7)
#define ETH_DMACIER_RSE  (1UL << 8)
#define ETH_DMACIER_RWTE (1UL << 9)
#define ETH_DMACIER_ETIE (1UL << 10)
#define ETH_DMACIER_ERIE (1UL << 11)
#define ETH_DMACIER_FBEE (1UL << 12)
#define ETH_DMACIER_CDEE (1UL << 13)
#define ETH_DMACIER_AIE  (1UL << 14)
#define ETH_DMACIER_NIE  (1UL << 15)

/* DMA channel status (DMACxSR), RX bits not defined above */
#define ETH_DMACSR_RWT (1UL << 9)  /* Receive watchdog timeout */
#define ETH_DMACSR_ERI (1UL << 11) /* Early receive interrupt */

/* DMA interrupt status (DMAISR) */
#define ETH_DMAISR_DC0IS (1UL << 0)
#define ETH_DMAISR_DC1IS (1UL << 1)
#define ETH_DMAISR_MTLIS (1UL << 16)
#define ETH_DMAISR_MACIS (1UL << 17)

/* DMA debug status (DMADSR): RX process state stopped */
#define ETH_DMADSR_RPS_STOPPED 0x0U

/* MMC interrupt masks (HAL_ETH_Init(): stm32n6xx_hal_eth.c:427-432) */
#define ETH_MMCRIMR_RXCRCERPIM  (1UL << 5)
#define ETH_MMCRIMR_RXALGNERPIM (1UL << 6)
#define ETH_MMCRIMR_RXUCGPIM    (1UL << 17)
#define ETH_MMCRIMR_RXLPIUSCIM  (1UL << 26)
#define ETH_MMCRIMR_RXLPITRCIM  (1UL << 27)
#define ETH_MMCRIMR_ALL \
	(ETH_MMCRIMR_RXCRCERPIM | ETH_MMCRIMR_RXALGNERPIM | ETH_MMCRIMR_RXUCGPIM | ETH_MMCRIMR_RXLPIUSCIM | ETH_MMCRIMR_RXLPITRCIM)
#define ETH_MMCTIMR_TXSCOLGPIM (1UL << 14)
#define ETH_MMCTIMR_TXMCOLGPIM (1UL << 15)
#define ETH_MMCTIMR_TXGPKTIM   (1UL << 21)
#define ETH_MMCTIMR_TXLPIUSCIM (1UL << 26)
#define ETH_MMCTIMR_TXLPITRCIM (1UL << 27)
#define ETH_MMCTIMR_ALL \
	(ETH_MMCTIMR_TXSCOLGPIM | ETH_MMCTIMR_TXMCOLGPIM | ETH_MMCTIMR_TXGPKTIM | ETH_MMCTIMR_TXLPIUSCIM | ETH_MMCTIMR_TXLPITRCIM)

#define ETH_MACISR_RGSMIIIS (1UL << 0)
#define ETH_MACISR_PHYIS    (1UL << 3)
#define ETH_MACISR_PMTIS    (1UL << 4)
#define ETH_MACISR_LPIIS    (1UL << 5)
#define ETH_MACISR_MMCIS    (1UL << 8)
#define ETH_MACISR_MMCRXIS  (1UL << 9)
#define ETH_MACISR_MMCTXIS  (1UL << 10)
#define ETH_MACISR_TSIS     (1UL << 12)
#define ETH_MACISR_TXSTSIS  (1UL << 13)
#define ETH_MACISR_RXSTSIS  (1UL << 14)
#define ETH_MACISR_FPEIS    (1UL << 17)
#define ETH_MACISR_MDIOIS   (1UL << 18)
#define ETH_MACISR_MFTIS    (1UL << 19)
#define ETH_MACISR_MFRIS    (1UL << 20)


#endif /* _STM32_ETH_REGS_H_ */

/*
 * Phoenix-RTOS --- networking stack
 *
 * STM32 ETH network module register definitions
 *
 * Based on RM0486 STM32N647/657xx Reference manual by STMicroelectronics
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

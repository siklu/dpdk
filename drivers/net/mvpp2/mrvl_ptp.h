#ifndef _MRVL_PTP_H_
#define _MRVL_PTP_H_

#include <sys/types.h>

#include "mrvl_ethdev.h"

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

/**
 * Open Linux PHC clock descriptor
 *
 * @param phc_dev_name PHC device path (e.g. /dev/ptp0)
 * @returns either valid id of clock or CLOCK_INVALID
 */
clockid_t
phc_open(const char *phc_dev_name);

/**
 * Close Linux PHC clock descriptor
 *
 * @param clkid id of clock
 */
void
phc_close(clockid_t clkid);

/**
 * Get PHC id by network device name
 *
 * @param name of network device
 * @param phc out for opened PHC clock id descriptor
 * @returns 0 on success, -1 on error
 */
int
sk_get_dev_phc(const char *name, clockid_t *phc);

/**
 * Emplaces timestamp into mbuf dynfield
 *
 * Before emplace converts u32 packet ts into full u64 nsec
 *
 * @param tai PHC opened descriptor
 * @param pkt_ts timestamp from packet in host byte order
 * @param full_ts pointer to mbuf dynfield where to put full u64 nsec
 */
int
mvpp22_tai_tstamp(clockid_t tai, u32 pkt_ts, rte_mbuf_timestamp_t *full_ts);

/**
 * Schedules periodic alarm to get time from Linux PHC
 *
 * @param priv mvpp2 driver's private data
 * @returns 0 on success
 */
int mvpp2_schedule_phc_alarm(struct mrvl_priv *priv);

/**
 * Cancels periodic alarm to stop get time from Linux PHC
 *
 * @param priv mvpp2 driver's private data
 */
void mvpp2_cancel_phc_alarm(struct mrvl_priv *priv);

/* PTPAction */
enum mvpp22_ptp_action {
	MVPP22_PTP_ACTION_NONE = 0,
	MVPP22_PTP_ACTION_FORWARD = 1,
	MVPP22_PTP_ACTION_CAPTURE = 3,
	/* The following have not been verified */
	MVPP22_PTP_ACTION_ADDTIME = 4,
	MVPP22_PTP_ACTION_ADDCORRECTEDTIME = 5,
	MVPP22_PTP_ACTION_CAPTUREADDTIME = 6,
	MVPP22_PTP_ACTION_CAPTUREADDCORRECTEDTIME = 7,
	MVPP22_PTP_ACTION_ADDINGRESSTIME = 8,
	MVPP22_PTP_ACTION_CAPTUREADDINGRESSTIME = 9,
	MVPP22_PTP_ACTION_CAPTUREINGRESSTIME = 10,
};

/* PTPPacketFormat */
enum mvpp22_ptp_packet_format {
	MVPP22_PTP_PKT_FMT_PTPV2 = 0,
	MVPP22_PTP_PKT_FMT_PTPV1 = 1,
	MVPP22_PTP_PKT_FMT_Y1731 = 2,
	MVPP22_PTP_PKT_FMT_NTPTS = 3,
	MVPP22_PTP_PKT_FMT_NTPRX = 4,
	MVPP22_PTP_PKT_FMT_NTPTX = 5,
	MVPP22_PTP_PKT_FMT_TWAMP = 6,
};

#define MVPP22_PTP_ACTION(x)		(((x) & 15) << 0)
#define MVPP22_PTP_PACKETFORMAT(x)	(((x) & 7) << 4)
#define MVPP22_PTP_MACTIMESTAMPINGEN	BIT(11)
#define MVPP22_PTP_TIMESTAMPENTRYID(x)	(((x) & 31) << 12)
#define MVPP22_PTP_TIMESTAMPQUEUESELECT	BIT(18)

#define PTP_CLASS_V1    0x01 /* protocol version 1 */
#define PTP_CLASS_V2    0x02 /* protocol version 2 */
#define PTP_CLASS_VMASK 0x0f /* max protocol version is 15 */

#define MVPP22_PTP_DESC_MASK_LOW  0xfff

inline void mvpp2_txdesc_clear_ptp(u32 *ptp_desc)
{
	*ptp_desc &= rte_cpu_to_le_32(~MVPP22_PTP_DESC_MASK_LOW);
}

/**
 * Sets TX descriptor for timestamping and rembers assosiated packet buf
 *
 * @param[in] priv mvpp2 driver's private data
 * @param[in] mbuf buffer assosioated with packet
 * @param[out] tx_desc packet TX descriptor
 * @returns true if timestamp was enabled for packet
 */
inline bool mvpp2_tx_hw_tstamp(
    struct mrvl_priv *priv,
    struct rte_mbuf *mbuf,
    struct pp2_ppio_desc *tx_desc)
{
	struct mvpp2_hwtstamp_queue *queue;
	unsigned int type, it;
	u32 *ptp_desc = &tx_desc->cmds[2];
	u64 *buf_dma_addr_ptp = (u64 *)&tx_desc->cmds[4];
	u64 desc_val;

#if 0
	unsigned int mtype;
	struct ptp_header *hdr;
	// TODO: add classifier support
	type = ptp_classify_raw(mbuf);
	if (!type)
		return false;

	hdr = ptp_parse_header(mbuf, type);
	if (!hdr)
		return false;

	skb_shinfo(mbuf)->tx_flags |= SKBTX_IN_PROGRESS;
#endif

	type = PTP_CLASS_V2;

	desc_val = MVPP22_PTP_MACTIMESTAMPINGEN | MVPP22_PTP_ACTION_CAPTURE;
	queue = &priv->tx_hwtstamp_queue[0];

	switch (type & PTP_CLASS_VMASK) {
	case PTP_CLASS_V1:
		desc_val |= MVPP22_PTP_PACKETFORMAT(MVPP22_PTP_PKT_FMT_PTPV1);
		break;

	case PTP_CLASS_V2:
		desc_val |= MVPP22_PTP_PACKETFORMAT(MVPP22_PTP_PKT_FMT_PTPV2);
#if 0
		mtype = hdr->msg_type & 15;
		/* Direct PTP Sync messages to queue 1 */
		if (mtype == 0) {
			desc_val |= MVPP22_PTP_TIMESTAMPQUEUESELECT;
			queue = &priv->tx_hwtstamp_queue[1];
		}
#endif
		break;
	}

	rte_spinlock_lock(&queue->lock);
	/* Iterate over 0..31 */
	it = queue->next;
	/* Take a reference on the mbuf and insert into our queue */
	rte_pktmbuf_free(queue->mbuf[it]);
	queue->mbuf[it] = rte_pktmbuf_clone(mbuf, mbuf->pool);
	queue->next = (it + 1) & 31;
	rte_spinlock_unlock(&queue->lock);

	desc_val |= MVPP22_PTP_TIMESTAMPENTRYID(it);

	/*
	 * 3:0		- PTPAction
	 * 6:4		- PTPPacketFormat
	 * 7		- PTP_CF_WraparoundCheckEn
	 * 9:8		- IngressTimestampSeconds[1:0]
	 * 10		- Reserved
	 * 11		- MACTimestampingEn
	 * 17:12	- PTP_TimestampQueueEntryID[5:0]
	 * 18		- PTPTimestampQueueSelect
	 * 19		- UDPChecksumUpdateEn
	 * 27:20	- TimestampOffset
	 *		  PTP, NTPTransmit, OWAMP/TWAMP - L3 to PTP header
	 *		  NTPTs, Y.1731 - L3 to timestamp entry
	 * 35:28	- UDP Checksum Offset
	 *
	 * stored in tx descriptor bits 75:64 (11:0) and 191:168 (35:12)
	 */

	*ptp_desc |= rte_cpu_to_le_32(desc_val & MVPP22_PTP_DESC_MASK_LOW);
	*buf_dma_addr_ptp &= rte_cpu_to_le_64(~0xffffff0000000000ULL);
	*buf_dma_addr_ptp |= rte_cpu_to_le_64((desc_val >> 12) << 40);

	MRVL_LOG(DEBUG,
		 "%u-%u TX TS[%u]: ptp_desc=0x%.8x dma_desc=0x%.16lx\n",
		 priv->ppio->pp2_id, priv->ppio->port_id,
		 it, *ptp_desc, *buf_dma_addr_ptp);

	return true;
}

/**
 * Schedules periodic alarm to get timestamps from TX queue
 *
 * @param priv mvpp2 driver's private data
 * @returns 0 on success
 */
int mvpp2_schedule_tx_ts_alarm(struct mrvl_priv *priv);

/**
 * Cancels periodic alarm to stop get timestamps from TX queue
 *
 * @param priv mvpp2 driver's private data
 */
void mvpp2_cancel_tx_ts_alarm(struct mrvl_priv *priv);

/**
 * Enables RX timestamping on port
 *
 * @param port_id
 * @returns true on success
 */
bool mvpp2_enable_rx_ts(uint16_t port_id);

extern bool mrvl_enable_ts[RTE_MAX_ETHPORTS];
extern uint64_t mrvl_timestamp_rx_dynflag;
extern int mrvl_timestamp_dynfield_offset;
/**
 * Checks if RX timestamping is enabled on current port
 *
 * @param q  ingress queue assigned to port
 * @return true if enabled
 */
inline bool mvpp2_is_rx_ts_enabled(struct mrvl_rxq *q)
{
	return
	  unlikely(mrvl_enable_ts[q->port_id] && q->priv->tai != CLOCK_INVALID);
}

inline rte_mbuf_timestamp_t *
mrvl_timestamp_dynfield(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
		mrvl_timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

/**
 * Reads RX timestamp to packet MBuf
 *
 * @param[in] priv  mvpp2 driver's private data
 * @param[in] desc  mvpp2 PPIO descriptors
 * @param[out] mbuf  packet mbuf
 */
inline void mvpp2_read_rx_ts(
    struct mrvl_priv *priv,
    struct pp2_ppio_desc *desc,
    struct rte_mbuf *mbuf)
{
	u32 ts = rte_le_to_cpu_32(pp2_ppio_inq_desc_get_timestamp(desc));
	if (!ts)
		return;

	if (mvpp22_tai_tstamp(priv->tai, ts, mrvl_timestamp_dynfield(mbuf))) {
		MRVL_LOG(ERR, "%u-%u RX TS=0x%.8x: failed to convert",
				priv->ppio->pp2_id, priv->ppio->port_id, ts);
	} else {
		mbuf->ol_flags |= mrvl_timestamp_rx_dynflag;
		MRVL_LOG(DEBUG, "%u-%u RX TS=%u: convert to %lu nsec\n",
			 priv->ppio->pp2_id, priv->ppio->port_id,
			 ts, *mrvl_timestamp_dynfield(mbuf));
	}
}

#endif // _MRVL_PTP_H_

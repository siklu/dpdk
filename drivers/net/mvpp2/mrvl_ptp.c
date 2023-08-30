#include "mrvl_ptp.h"

#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <rte_cycles.h>
#include <rte_alarm.h>

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

/* enable timestamp in mbuf */
static bool mrvl_enable_ts[RTE_MAX_ETHPORTS];
static uint64_t mrvl_timestamp_rx_dynflag;
static int mrvl_timestamp_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
mrvl_timestamp_dynfield(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
		mrvl_timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

bool mvpp2_enable_rx_ts(uint16_t port_id)
{
	if (mrvl_timestamp_dynfield_offset < 0 &&
	    rte_mbuf_dyn_rx_timestamp_register(&mrvl_timestamp_dynfield_offset,
					       &mrvl_timestamp_rx_dynflag)) {
		MRVL_LOG(ERR, "Failed to register Rx timestamp field/flag");
		return false;
	}
	mrvl_enable_ts[port_id] = true;
	return true;
}

bool mvpp2_is_rx_ts_enabled(struct mrvl_rxq *q)
{
	return mrvl_enable_ts[q->port_id] && q->priv->tai != CLOCK_INVALID;
}

clockid_t phc_open(const char *phc_dev_name)
{
	clockid_t clkid;
	struct timespec ts;
	struct timex tx;
	int fd;

	memset(&tx, 0, sizeof(tx));

	fd = open(phc_dev_name, O_RDWR);
	if (fd < 0)
		return CLOCK_INVALID;

	clkid = FD_TO_CLOCKID(fd);
	/* check if clkid is valid */
	if (clock_gettime(clkid, &ts)) {
		close(fd);
		return CLOCK_INVALID;
	}
	if (clock_adjtime(clkid, &tx)) {
		close(fd);
		return CLOCK_INVALID;
	}

	return clkid;
}

void phc_close(clockid_t clkid)
{
	if (clkid == CLOCK_INVALID)
		return;

	close(CLOCKID_TO_FD(clkid));
}

int
sk_get_dev_phc(const char *name, clockid_t *phc)
{
	char phc_dev_name[32];
	struct ethtool_ts_info info;
	struct ifreq ifr;
	int fd, err;

	memset(&ifr, 0, sizeof(ifr));
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GET_TS_INFO;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_data = (char *) &info;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err < 0) {
		close(fd);
		return -1;
	}

	close(fd);

	if (info.phc_index < 0)
		return -1;

	snprintf(phc_dev_name, sizeof(phc_dev_name),
			"/dev/ptp%d", info.phc_index);
	*phc = phc_open(phc_dev_name);
	if (*phc == CLOCK_INVALID)
		return -1;

	return 0;
}

int
mvpp22_tai_tstamp(clockid_t tai, u32 pkt_ts, rte_mbuf_timestamp_t *full_ts)
{
	struct timespec ts;
	int delta;

	/* The packet timestamp consists of 2 bits of seconds and 30 bits of
	 * nanoseconds.  We use our stored timestamp (tai->ts) to form a full
	 * timestamp, and we must read the seconds exactly once.
	 */
	if (clock_gettime(tai, &ts)) {
		return -1;
	}

	/* Calculate the delta in seconds between our stored timestamp and
	 * the value read from the queue. Allow timestamps one second in the
	 * past, otherwise consider them to be in the future.
	 */
	delta = ((pkt_ts >> 30) - (ts.tv_sec & 3)) & 3;
	if (delta == 3)
		delta -= 4;
	ts.tv_sec += delta;

	*full_ts = (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;

	return 0;
}

static void mvpp2_phc_get_current_time(void *arg)
{
	struct mrvl_priv *priv = arg;
	struct timespec ts;
	int rc;

	if (priv->tai == CLOCK_INVALID)
		return;

	clock_gettime(priv->tai, &ts);

	rc = rte_eal_alarm_set(2*US_PER_S, mvpp2_phc_get_current_time,
			(void *)priv);
	if (rc != 0) {
		MRVL_LOG(ERR, "Failed to re-schedule PTP alarm\n");
		priv->scheduled_get_time_alarm = false;
	}
}

int mvpp2_schedule_phc_alarm(struct mrvl_priv *priv)
{
	if (priv->scheduled_get_time_alarm)
		return 0;

	int ret = rte_eal_alarm_set(2*US_PER_S, mvpp2_phc_get_current_time,
			(void *)priv);
	if (ret == 0) {
		priv->scheduled_get_time_alarm = true;
	}
	return ret;
}

void mvpp2_cancel_phc_alarm(struct mrvl_priv *priv)
{
	if (priv->scheduled_get_time_alarm) {
		rte_eal_alarm_cancel(mvpp2_phc_get_current_time, (void *)priv);
		priv->scheduled_get_time_alarm = false;
	}
}

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

#define MVPP22_PTP_DESC_MASK_LOW  0xfff
#define PTP_CLASS_V1    0x01 /* protocol version 1 */
#define PTP_CLASS_V2    0x02 /* protocol version 2 */
#define PTP_CLASS_VMASK 0x0f /* max protocol version is 15 */

static inline void mvpp2_txdesc_clear_ptp(u32 *ptp_desc)
{
	*ptp_desc &= rte_cpu_to_le_32(~MVPP22_PTP_DESC_MASK_LOW);
}

bool mvpp2_tx_hw_tstamp(
    struct mrvl_priv *priv,
    struct rte_mbuf *mbuf,
    struct pp2_ppio_desc *tx_desc)
{
	struct mvpp2_hwtstamp_queue *queue;
	unsigned int type, it;
	u32 *ptp_desc = &tx_desc->cmds[2];
	u64 *buf_dma_addr_ptp = &tx_desc->cmds[4];
	u64 desc_val;

	if (likely(!(mbuf->ol_flags & PKT_TX_IEEE1588_TMST))) {
		mvpp2_txdesc_clear_ptp(ptp_desc);
		return false;
	}

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
	 *			PTP, NTPTransmit, OWAMP/TWAMP - L3 to PTP header
	 *			NTPTs, Y.1731 - L3 to timestamp entry
	 * 35:28	- UDP Checksum Offset
	 *
	 * stored in tx descriptor bits 75:64 (11:0) and 191:168 (35:12)
	 */

	mvpp2_txdesc_clear_ptp(ptp_desc);
	*ptp_desc |= rte_cpu_to_le_32(desc_val & MVPP22_PTP_DESC_MASK_LOW);
	*buf_dma_addr_ptp &= rte_cpu_to_le_64(~0xffffff0000000000ULL);
	*buf_dma_addr_ptp |= rte_cpu_to_le_64((desc_val >> 12) << 40);

	MRVL_LOG(DEBUG,
			"%u-%u TX TS[%u]: ptp_desc=0x%.8x dma_desc=0x%.16llx\n",
			priv->ppio->pp2_id, priv->ppio->port_id,
			it, *ptp_desc, *buf_dma_addr_ptp);

	return true;
}

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
		MRVL_LOG(DEBUG, "%u-%u RX TS=%lu: convert to %llu nsec\n",
			 priv->ppio->pp2_id, priv->ppio->port_id,
			 ts, *mrvl_timestamp_dynfield(mbuf));
	}
}

static void mvpp2_isr_handle_ptp_queue(void *arg)
{
	struct mrvl_priv *priv = arg;
	struct mvpp2_hwtstamp_queue *queue;
	struct rte_mbuf *mbuf;

	// FIXME: only Queue0 is supported
	u8 nq = 0;
	queue = &priv->tx_hwtstamp_queue[nq];

	while (1) {
		bool lock_next = false;
		u32 it;
		u32 ts;
		if (0 != pp2_ppio_get_outq_ts(priv->ppio, nq, &it, &ts))
			break;

		// synchronize only when working with next
		if (it == queue->next) {
			if (rte_spinlock_trylock(&queue->lock) == 0) {
				rte_spinlock_lock(&queue->lock);
				lock_next = true;
			} else {
				MRVL_LOG(ERR, "%u-%u TX TS[%lu]=%lu: queue overrun!\n",
						priv->ppio->pp2_id, priv->ppio->port_id, it, ts);
				continue;
			}
		}
		// pull-out from queue and unlock next
		mbuf = queue->mbuf[it];
		queue->mbuf[it] = NULL;
		if (lock_next) {
			rte_spinlock_unlock(&queue->lock);
		}
		if (!mbuf) {
			MRVL_LOG(ERR, "%u-%u TX TS[%lu]=%lu: queue slot is not valid!\n",
					priv->ppio->pp2_id, priv->ppio->port_id, it, ts);
			continue;
		} else if (mvpp22_tai_tstamp(priv->tai, ts,
					mrvl_timestamp_dynfield(mbuf))) {
			MRVL_LOG(ERR, "%u-%u TX TS[%lu]=0x%.8x: failed to convert!",
					priv->ppio->pp2_id, priv->ppio->port_id, it, ts);
		} else {
			MRVL_LOG(DEBUG,
					"%u-%u TX TS[%lu]=%lu: convert to %llu nsec\n",
					priv->ppio->pp2_id, priv->ppio->port_id,
					it, ts, *mrvl_timestamp_dynfield(mbuf));
		}

		// TODO: send TS to socket
		rte_pktmbuf_free(mbuf);
	}

	if (rte_eal_alarm_set(MS_PER_S, mvpp2_isr_handle_ptp_queue,
			(void *)priv)) {
		MRVL_LOG(ERR, "%u-%u TX TS: failed to re-schedule poll alarm\n",
				priv->ppio->pp2_id, priv->ppio->port_id);
		priv->scheduled_get_tx_ts_alarm = false;
	}
}

int mvpp2_schedule_tx_ts_alarm(struct mrvl_priv *priv)
{
	if (priv->scheduled_get_tx_ts_alarm)
		return 0;

	if (pp2_ppio_set_outq_ts_conf(priv->ppio)) {
		MRVL_LOG(ERR, "%u-%u TX TS: not starting poll, TSU is disabled\n",
				priv->ppio->pp2_id, priv->ppio->port_id);
		return -1;
	}
	int ret = rte_eal_alarm_set(MS_PER_S, mvpp2_isr_handle_ptp_queue,
			(void *)priv);
	if (ret == 0) {
		priv->scheduled_get_time_alarm = true;
	}
	return ret;
}

void mvpp2_cancel_tx_ts_alarm(struct mrvl_priv *priv)
{
	if (priv->scheduled_get_tx_ts_alarm) {
		rte_eal_alarm_cancel(mvpp2_isr_handle_ptp_queue, (void *)priv);
		priv->scheduled_get_tx_ts_alarm = false;
	}
}

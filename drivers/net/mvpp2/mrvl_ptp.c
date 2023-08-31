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
bool mrvl_enable_ts[RTE_MAX_ETHPORTS];
uint64_t mrvl_timestamp_rx_dynflag;
int mrvl_timestamp_dynfield_offset = -1;

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

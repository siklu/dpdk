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
mvpp22_tai_tstamp(clockid_t tai, u32 tstamp,
		rte_mbuf_timestamp_t *hwtstamp)
{
	struct timespec ts;
	int delta;

	/* The tstamp consists of 2 bits of seconds and 30 bits of nanoseconds.
	 * We use our stored timestamp (tai->stamp) to form a full timestamp,
	 * and we must read the seconds exactly once.
	 */
	if (clock_gettime(tai, &ts)) {
		return -1;
	}

	/* Calculate the delta in seconds between our stored timestamp and
	 * the value read from the queue. Allow timestamps one second in the
	 * past, otherwise consider them to be in the future.
	 */
	delta = ((tstamp >> 30) - (ts.tv_sec & 3)) & 3;
	if (delta == 3)
		delta -= 4;
	ts.tv_sec += delta;

	*hwtstamp = (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;

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
	MRVL_LOG(DEBUG, "TAI time: %"PRIu64 " nsec\n",
			(uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec);

	rc = rte_eal_alarm_set(2*US_PER_S, mvpp2_phc_get_current_time,
			(void *)priv);
	if (rc != 0) {
		MRVL_LOG(ERR, "Failed to re-schedule PTP alarm\n");
		priv->scheduled_get_time_alarm = false;
	}
}

int mvpp2_schedule_phc_alarm(struct mrvl_priv *priv)
{
	int rc;

	if (priv->scheduled_get_time_alarm)
		return 0;

	rc = rte_eal_alarm_set(2*US_PER_S, mvpp2_phc_get_current_time,
			(void *)priv);
	return rc;
}

void mvpp2_cancel_phc_alarm(struct mrvl_priv *priv)
{
	if (priv->scheduled_get_time_alarm) {
		rte_eal_alarm_cancel(mvpp2_phc_get_current_time, (void *)priv);
		priv->scheduled_get_time_alarm = false;
	}
}

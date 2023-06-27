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
 * @param tstamp timestamp from packet in host byte order
 * @param hwtstamp pointer to mbuf dynfield where to put u64 nsec
 */
int
mvpp22_tai_tstamp(clockid_t tai, u32 tstamp,
		rte_mbuf_timestamp_t *hwtstamp);

/**
 * Schedules periodic alarm to get time from Linux PHC
 *
 * @param priv mvpp2 driver's private data
 * @returns on success 0, on failure negative
 */
int mvpp2_schedule_phc_alarm(struct mrvl_priv *priv);

/**
 * Cancels periodic alarm to stop get time from Linux PHC
 *
 * @param priv mvpp2 driver's private data
 */
void mvpp2_cancel_phc_alarm(struct mrvl_priv *priv);

#endif // _MRVL_PTP_H_

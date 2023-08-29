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

/**
 * Sets TX descriptor for timestamping and rembers assosiated packet buf
 *
 * @param[in] priv mvpp2 driver's private data
 * @param[in] mbuf buffer assosioated with packet
 * @param[out] tx_desc packet TX descriptor
 * @returns true if timestamp was enabled for packet
 */
bool mvpp2_tx_hw_tstamp(
		struct mrvl_priv *priv,
		struct rte_mbuf *mbuf,
		struct pp2_ppio_desc *tx_desc);

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

/**
 * Checks if RX timestamping is enabled on current port
 *
 * @param q  ingress queue assigned to port
 * @return true if enabled
 */
bool mvpp2_is_rx_ts_enabled(struct mrvl_rxq *q);

/**
 * Reads RX timestamp to packet MBuf
 *
 * @param[in] priv  mvpp2 driver's private data
 * @param[in] desc  mvpp2 PPIO descriptors
 * @param[out] mbuf  packet mbuf
 */
void mvpp2_read_rx_ts(
		struct mrvl_priv *priv,
		struct pp2_ppio_desc *desc,
		struct rte_mbuf *mbuf);

#endif // _MRVL_PTP_H_

#ifndef PACKETIO_H
#define PACKETIO_H

#include <netinet/ether.h>

/**
 * @file packetio.h
 * @brief Library supporting sending/receiving Ethernet II frames.
 */

/**
 * Encapsulate payload data in an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac Destination MAC address (6 bytes).
 * @param id Device ID returned by addDevice().
 * @return 0 on success, -1 on error.
 */
int sendFrame(const void *buf, int len, int ethtype, const void *destmac, int id);

/** Callback invoked when an Ethernet II frame is received. */
typedef int (*frameReceiveCallback)(const void *buf, int len, int id);

/**
 * Register the callback invoked for each received Ethernet II frame.
 *
 * @param callback Callback function.
 * @return 0 on success, -1 on error.
 */
int setFrameReceiveCallback(frameReceiveCallback callback);

#endif /* PACKETIO_H */

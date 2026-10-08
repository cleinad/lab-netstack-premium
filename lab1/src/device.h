#include <pcap/pcap.h>

/**
 * @file device.h
 * @brief Library supporting network device management
 */

/**
 * Add a device to the library for sending/receiving packets.
 *
 * @param device Name of network device to send/receive packet on
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
 int addDevice(const char* device);

 /**
  * Find a device added by 'addDevice'.
  *
  * @param device Name of the network device.
  * @return A non-negative _device-ID_ on success, 
  * -1 if no such device was found.
  */
int findDevice(const char* device);

/**
 * Get the pcap_t object associated with a device ID
 */
pcap_t *getDeviceHandle(int device_id);

/**
 * Copy the MAC address associated with a device ID into mac.
 *
 * @param device_id ID returned by addDevice().
 * @param mac Output buffer for the six-byte MAC address.
 * @return 0 on success, -1 on error.
 */
int getDeviceMac(int device_id, unsigned char mac[6]);

#include "packetio.h"
#include "device.h"
#include <pcap/pcap.h>
#include <arpa/inet.h> // declares htons

#include <stddef.h>
#include <stdlib.h> // malloc and free
#include <string.h> // memcpy

/* PT2 implementation notes:
 * - Use the pcap handle associated with id to transmit captured frame bytes.
 * - Build Ethernet headers with network byte order for EtherType.
 * - Capture frames from registered devices and pass them to the callback.
 */

static frameReceiveCallback receive_callback;

/* notes
char is 1 byte = 8 bits
unsigned char stores values from 0 to 255
signed char stores values from -128 to 127

short is at least 16 bits (usually it is 16)
unsigned short stores from 0 to 65,535

EtherType if:
>= 0x0600 (1536) represents an ethertype
<= 1500 represents the payload length
*/

/**
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by addDevice()) to send on.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int sendFrame(const void *buf, int len, int ethtype, const void *destmac, int id)
{
    pcap_t* handle = getDeviceHandle(id);
    if (handle == NULL) {
        return -1;
    }

    unsigned char source_mac[6] // allocate space to write source mac address
    if (getDeviceMac(id, source_mac) != 0) {
        return -1;
    }

    if (len < 0) {
        return -1; // it is cast to size_t which is an unsigned int, so if it's negative it becomes a massive positive number
    }

    size_t frame_size = sizeof(struct ether_header) + (size_t)len;
    unsigned char *frame = malloc(frame_size);
    if (frame == NULL) {
        return -1; // if malloc fails...
    }

    struct ether_header *eth_header = (struct ether_header *)frame;
    // memcpy(destination, source, number of bytes))
    // fill out frame information
    memcpy(eth_header->ether_dhost, destmac, 6);
    memcpy(eth_header->ether_shost, source_mac, 6);
    eth_header->ether_type = htons(ethtype); // convert to big endian (network byte order) from machine byte order
    memcpy(frame + sizeof(struct eth_header), buf, (size_t)len);

    int result = pcap_sendpacket(handle, frame, (int)frame_size);
    free(frame);

    if (result == 0) {
        return 0;
    }
    return -1;
}

/* 
for reference

struct ether_header {
    unsigned char ether_dhost[6];  // destination MAC
    unsigned char ether_shost[6];  // source MAC
    unsigned short ether_type;     // EtherType
};

*/

int setFrameReceiveCallback(frameReceiveCallback callback)
{
    if (callback == NULL) {
        return -1;
    }

    receive_callback = callback;
    return 0;
}

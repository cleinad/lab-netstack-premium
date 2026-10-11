#include "packetio.h"
#include "device.h"
#include <pcap/pcap.h>
#include <arpa/inet.h> // declares htons
#include <pthread.h>

#include <stddef.h>
#include <stdlib.h> // malloc and free
#include <string.h> // memcpy

/* PT2 implementation notes:
 * - Use the pcap handle associated with id to transmit captured frame bytes.
 * - Build Ethernet headers with network byte order for EtherType.
 * - Capture frames from registered devices and pass them to the callback.
 */

typedef struct {
    int device_id;
    pthread_t thread;
    int started;
} CaptureContext;

static frameReceiveCallback receive_callback;
static pthread_mutex_t callback_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t capture_mutex = PTHREAD_MUTEX_INITIALIZER;
static CaptureContext **capture_contexts;
static int capture_context_capacity;

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
    if (buf == NULL || len < 0 || destmac == NULL ||
        ethtype < 0x0600 || ethtype > 0xffff) {
        return -1;
    }

    pcap_t* handle = getDeviceHandle(id);
    if (handle == NULL) {
        return -1;
    }

    unsigned char source_mac[6]; // allocate space to write source mac address
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
    memcpy(frame + sizeof(struct ether_header), buf, (size_t)len);

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

/*
typedef int (*frameReceiveCallback)(const void *buf, int len, int id);
buf: pointer to frame
len: length of the frame
id: id of the device (returned by addDevice) receiving current frame
*/

static void handleCapturedFrame(
    u_char *user,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet)
{
    CaptureContext *context = (CaptureContext *)user;
    if (context == NULL || packet_header == NULL || packet == NULL) {
        return;
    }

    if (packet_header->caplen < sizeof(struct ether_header)) {
        return;
    }

    const struct ether_header *ethernet_header = (const struct ether_header *)packet;

    if (ntohs(ethernet_header->ether_type) < 0x0600) {
        return; // values below 0x0600 are Ethernet length fields
    }

    pthread_mutex_lock(&callback_mutex);
    frameReceiveCallback callback = receive_callback;
    pthread_mutex_unlock(&callback_mutex);

    if (callback != NULL) {
        callback(packet, (int)packet_header->caplen, context->device_id);
    }
}

static void *captureFrames(void *arg)
{
    CaptureContext *context = arg;
    pcap_t *handle = getDeviceHandle(context->device_id);

    if (handle != NULL) {
        pcap_loop(handle, -1, handleCapturedFrame, (u_char *)context);
    }

    return NULL;
}

static int ensureCaptureContextCapacity(int device_count)
{
    if (device_count <= capture_context_capacity) {
        return 0;
    }

    CaptureContext **resized_contexts = realloc(
        capture_contexts, (size_t)device_count * sizeof(*capture_contexts)
    );
    if (resized_contexts == NULL) {
        return -1;
    }

    for (int id = capture_context_capacity; id < device_count; id++) {
        resized_contexts[id] = NULL;
    }

    capture_contexts = resized_contexts;
    capture_context_capacity = device_count;
    return 0;
}

static int startCaptureThreads(void)
{
    int device_count = getDeviceCount();

    pthread_mutex_lock(&capture_mutex);

    if (ensureCaptureContextCapacity(device_count) != 0) {
        pthread_mutex_unlock(&capture_mutex);
        return -1;
    }

    for (int id = 0; id < device_count; id++) {
        if (capture_contexts[id] != NULL && capture_contexts[id]->started) {
            continue;
        }

        CaptureContext *context = malloc(sizeof(*context));
        if (context == NULL) {
            pthread_mutex_unlock(&capture_mutex);
            return -1;
        }

        context->device_id = id;
        context->started = 0;

        if (pthread_create(&context->thread, NULL, captureFrames, context) != 0) {
            free(context);
            pthread_mutex_unlock(&capture_mutex);
            return -1;
        }

        context->started = 1;
        capture_contexts[id] = context;
        pthread_detach(context->thread);
    }

    pthread_mutex_unlock(&capture_mutex);
    return 0;
}

int setFrameReceiveCallback(frameReceiveCallback callback)
{
    if (callback == NULL) {
        return -1;
    }

    pthread_mutex_lock(&callback_mutex);
    receive_callback = callback;
    pthread_mutex_unlock(&callback_mutex);

    return startCaptureThreads();
}

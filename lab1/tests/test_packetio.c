#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "device.h"
#include "packetio.h"

#define TEST_ETHERTYPE 0x88B5
#define RECEIVE_TIMEOUT_SECONDS 2

static const char test_payload[] = "packetio PT2 test";
static pthread_mutex_t receive_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t receive_condition = PTHREAD_COND_INITIALIZER;
static int received_test_frame;

static int handleIncomingFrame(const void *frame, int len, int device_id)
{
    if (len < (int)sizeof(struct ether_header)) {
        return -1;
    }

    const struct ether_header *header = frame;
    int payload_len = len - (int)sizeof(*header);

    if (ntohs(header->ether_type) != TEST_ETHERTYPE ||
        payload_len < (int)(sizeof(test_payload) - 1) ||
        memcmp((const unsigned char *)frame + sizeof(*header),
               test_payload, sizeof(test_payload) - 1) != 0) {
        return 0;
    }

    printf("Captured the test frame on device ID %d.\n", device_id);

    pthread_mutex_lock(&receive_mutex);
    received_test_frame = 1;
    pthread_cond_signal(&receive_condition);
    pthread_mutex_unlock(&receive_mutex);
    return 0;
}

static int waitForTestFrame(void)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += RECEIVE_TIMEOUT_SECONDS;

    pthread_mutex_lock(&receive_mutex);
    while (!received_test_frame) {
        int result = pthread_cond_timedwait(
            &receive_condition, &receive_mutex, &deadline
        );
        if (result != 0) {
            pthread_mutex_unlock(&receive_mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&receive_mutex);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network-interface>\n", argv[0]);
        return 1;
    }

    const unsigned char broadcast_mac[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    int device_id = addDevice(argv[1]);
    if (device_id < 0) {
        fprintf(stderr, "Could not open device: %s\n", argv[1]);
        return 1;
    }

    if (setFrameReceiveCallback(handleIncomingFrame) != 0) {
        fprintf(stderr, "Could not start frame capture\n");
        return 1;
    }

    if (sendFrame(test_payload, sizeof(test_payload) - 1, TEST_ETHERTYPE,
                  broadcast_mac, device_id) != 0) {
        fprintf(stderr, "sendFrame failed\n");
        return 1;
    }

    printf("Sent a test frame on %s with EtherType 0x%04X.\n",
           argv[1], TEST_ETHERTYPE);

    if (waitForTestFrame() != 0) {
        fprintf(stderr, "Did not capture the test frame within %d seconds\n",
                RECEIVE_TIMEOUT_SECONDS);
        return 1;
    }

    return 0;
}


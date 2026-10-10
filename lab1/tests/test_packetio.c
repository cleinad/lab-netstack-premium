#include <stdio.h>

#include "device.h"
#include "packetio.h"

#define TEST_ETHERTYPE 0x88B5

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network-interface>\n", argv[0]);
        return 1;
    }

    const unsigned char broadcast_mac[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    const char payload[] = "packetio PT2 test";

    int device_id = addDevice(argv[1]);
    if (device_id < 0) {
        fprintf(stderr, "Could not open device: %s\n", argv[1]);
        return 1;
    }

    if (sendFrame(payload, sizeof(payload) - 1, TEST_ETHERTYPE,
                  broadcast_mac, device_id) != 0) {
        fprintf(stderr, "sendFrame failed\n");
        return 1;
    }

    printf("Sent a test frame on %s with EtherType 0x%04X.\n",
           argv[1], TEST_ETHERTYPE);
    return 0;
}

/* test instructions:

terminal one:
sudo tcpdump -i en0 -e -XX ether proto 0x88b5

terminal two:
cd lab1
sudo ./testpacketio en0

*/
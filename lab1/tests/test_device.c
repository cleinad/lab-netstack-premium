#include <pcap/pcap.h>
#include <stdio.h>

#include "device.h"

/*
test instructions
make test_device
sudo ./test_device en0

you can replace en0 with any other device
*/

static int listDevices(void)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;

    if (pcap_findalldevs(&interfaces, error_buffer) != 0) {
        fprintf(stderr, "Could not list interfaces: %s\n", error_buffer);
        return -1;
    }

    printf("Detected interfaces:\n");
    for (pcap_if_t *interface = interfaces;
         interface != NULL;
         interface = interface->next) {
        printf("- %s", interface->name);
        if (interface->description != NULL) {
            printf(" (%s)", interface->description);
        }
        putchar('\n');
    }

    pcap_freealldevs(interfaces);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network-interface>\n", argv[0]);
        return 1;
    }

    if (listDevices() != 0) {
        return 1;
    }

    int device_id = addDevice(argv[1]);
    if (device_id < 0) {
        fprintf(stderr, "Could not add device: %s\n", argv[1]);
        return 1;
    }

    int found_id = findDevice(argv[1]);
    if (found_id != device_id) {
        fprintf(stderr, "findDevice returned %d; expected %d\n",
                found_id, device_id);
        return 1;
    }

    int duplicate_id = addDevice(argv[1]);
    if (duplicate_id != device_id) {
        fprintf(stderr, "Duplicate add returned %d; expected %d\n",
                duplicate_id, device_id);
        return 1;
    }

    printf("Added %s as device ID %d.\n", argv[1], device_id);
    printf("findDevice and duplicate add both returned %d.\n", device_id);
    return 0;
}

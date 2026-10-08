#include <pcap/pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <string.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <net/if_dl.h>
#elif defined(__linux__)
#include <netpacket/packet.h>
#endif

#define MAX_DEVICES 16
#define NAME_MAX_SIZE 64

typedef struct {
    char name[NAME_MAX_SIZE];
    pcap_t *handle;
    unsigned char mac[6];
} Device;

static Device devices[MAX_DEVICES]; // array of Device
static int device_counter = 0;

static int lookupDeviceMac(const char *device, unsigned char mac[6]) {
    struct ifaddrs *interfaces = NULL;

    if (getifaddrs(&interfaces) != 0) {
        return -1;
    }

    for (struct ifaddrs *interface = interfaces;
         interface != NULL;
         interface = interface->ifa_next) {
        if (interface->ifa_addr == NULL || strcmp(interface->ifa_name, device) != 0) {
            continue;
        }

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
        if (interface->ifa_addr->sa_family == AF_LINK) {
            const struct sockaddr_dl *link_address =
                (const struct sockaddr_dl *)interface->ifa_addr;

            if (link_address->sdl_alen == 6) {
                memcpy(mac, LLADDR(link_address), 6);
                freeifaddrs(interfaces);
                return 0;
            }
        }
#elif defined(__linux__)
        if (interface->ifa_addr->sa_family == AF_PACKET) {
            const struct sockaddr_ll *link_address =
                (const struct sockaddr_ll *)interface->ifa_addr;

            if (link_address->sll_halen == 6) {
                memcpy(mac, link_address->sll_addr, 6);
                freeifaddrs(interfaces);
                return 0;
            }
        }
#endif
    }

    freeifaddrs(interfaces);
    return -1;
}

/**
 * Add a device to the library for sending/receiving packets.
 *
 * @param device Name of network device to send/receive packet on
 * @return A non-negative _device-ID_ on success, -1 on error.
 */
 int addDevice(const char* device) {
    if (device == NULL) {
        return -1;
    } else if (device_counter >= MAX_DEVICES) {
        return -1;
    } else {
        // process device name
        size_t len = strlen(device);
        if (len >= NAME_MAX_SIZE) { // because the null termination takes size
            return -1;
        }

        unsigned char mac[6];
        if (lookupDeviceMac(device, mac) != 0) {
            return -1;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        // pcap_t is context used to capture packets from interface; an opened capture session
        pcap_t* handle = pcap_open_live(
            device, 65535, 1, 1000, errbuf
        );
        if (handle == NULL) {
            return -1;
        }

        strcpy(devices[device_counter].name, device); // move it directly into the space already allocated
        devices[device_counter].handle = handle;
        memcpy(devices[device_counter].mac, mac, sizeof(mac));

        return device_counter++;
    }
 }

 /**
  * Find a device added by 'addDevice'.
  *
  * @param device Name of the network device.
  * @return A non-negative _device-ID_ on success, 
  * -1 if no such device was found.
  */
int findDevice(const char* device) {
    if (device == NULL) {
        return -1;
    }
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (strcmp(devices[i].name, device) == 0) {
            return i;
        }
    }
    return -1;
}

/*
note that right now each device is associated with only one session (pcap), could totally be more
*/

/**
 * Find a pcap_t handle for a particular device_id
 *
 * @param device_id ID of the device.
 * @return A pcap_t* on success, 
 * NULL on error
 */
pcap_t *getDeviceHandle(int device_id) {
    if (device_id < 0 || device_id >= device_counter) {
        return NULL;
    }

    return devices[device_id].handle;
}

int getDeviceMac(int device_id, unsigned char mac[6]) {
    if (device_id < 0 || device_id >= device_counter || mac == NULL) {
        return -1;
    }

    memcpy(mac, devices[device_id].mac, sizeof(devices[device_id].mac));
    return 0;
}

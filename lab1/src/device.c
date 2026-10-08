#include <pcap/pcap.h>
#include <string.h>

#define MAX_DEVICES 16
#define NAME_MAX_SIZE 64

typedef struct {
    char name[NAME_MAX_SIZE];
    pcap_t *handle;
} Device;

static Device devices[MAX_DEVICES]; // array of Device
static int device_counter = 0;

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

        // process 
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
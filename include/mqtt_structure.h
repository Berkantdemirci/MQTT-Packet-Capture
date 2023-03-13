#ifndef __MQTT_STRUCTURE_H_
#define __MQTT_STRUCTURE_H_

#include <stdio.h>
#include <pcap.h>

struct handler_struct{

    /*output data*/
    unsigned char *device_name; 
    pcap_t *handle;
    void (*stop)(pcap_t *);
    void (*start)(pcap_t *);

}; 

/*

This header file includes needed data structures to be used. 

*/
#endif
#ifndef __MQTT_STRUCTURE_H_
#define __MQTT_STRUCTURE_H_

#include <stdio.h>
#include <pcap.h>

struct handler_struct{

    /*input data*/
    int read_timeout;
    
    /*output data*/
    unsigned char *device_name; 
    unsigned char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

}; 

/*

This header file includes needed data structures to be used. 

*/
#endif
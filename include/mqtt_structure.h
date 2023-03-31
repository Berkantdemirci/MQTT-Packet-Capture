#ifndef __MQTT_STRUCTURE_H_
#define __MQTT_STRUCTURE_H_

#include <stdio.h>
#include <pcap.h>
#include <pthread.h>

/**/

#define MQTT_PORT 1883

struct handler_struct{

    /*output data*/
    unsigned char *device_name; 
    pcap_t *handle;
    //pthread_barrier_t barr;
    void (*stop)(pcap_t *);
    void (*start)(pcap_t *);

}; 

struct mqtt_struct {
    
};

/*

This header file includes needed data structures to be used. 

*/
#endif
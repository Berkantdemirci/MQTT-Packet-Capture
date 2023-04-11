#ifndef __MQTT_STRUCTURE_H_
#define __MQTT_STRUCTURE_H_

#include <stdio.h>
#include <pcap.h>

#include "mqtt_structure.h"

#define MQTT_PORT 1883
#define IP_BUF_SIZE 256
#define ID_BUF_SIZE 128

struct handler_struct{

    uint8_t *device_name; 
    pcap_t *handle;
    void (*stop)(pcap_t *);
    void (*start)(pcap_t *);

}; 

struct mqtt_fix_header{

    uint8_t ip_src[IP_BUF_SIZE], ip_dst[IP_BUF_SIZE];
    uint16_t s_port ,d_port;	/* source/destination port */
    uint8_t tcp_flag;
    uint32_t caplen;
    uint16_t checksum;

};
/*
    ip.src
    ip.dst
    tcp.srcport
    tcp.dstport
    tcp.flag
    frame.len
    tcp.checksum
*/

struct mqtt_connect {

    struct mqtt_fix_header fix_header;
    uint8_t mqtt_version; 
    uint8_t connect_flag;
    uint16_t keep_alive;
    uint16_t client_id_length;
    uint8_t client_id[ID_BUF_SIZE];
    
};

struct mqtt_connect_ack {

    struct mqtt_fix_header fix_header;
    uint8_t session_present;
    uint8_t connack_code;

};

struct mqtt_subscribe_or_ack {

    struct mqtt_fix_header fix_header;
    uint16_t packet_id;
    uint8_t qos;
    
};

/*
    This header file includes needed data structures to be used. 
*/

#endif
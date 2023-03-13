#ifndef __LISTENER_H_
#define __LISTENER_H_

#include <stdio.h>
#include "mqtt_structure.h"

/*
    This header file includes listener functions signs
*/
struct handler_struct *listener_init();
void stop_mqtt_capture(pcap_t *handle);

#endif


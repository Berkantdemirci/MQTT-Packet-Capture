#ifndef __LISTENER_H_
#define __LISTENER_H_

#include <stdio.h>
#include "mqtt_structure.h"

/*
    This header file includes listener functions signs
*/

unsigned char *get_device_name();
void listener_init(struct handler_struct *handler);

#endif


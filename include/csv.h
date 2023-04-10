#ifndef __CSV_H_
#define __CSV_H_

#include <stdio.h>

#include "mqtt_structure.h"

void open_csv();

void save_mqtt_data(struct mqtt_fix_header *fix_header,
                    struct mqtt_connect *connect,
                    struct mqtt_connect_ack *con_ack,
                    struct mqtt_subscribe_or_ack *sub,
                    struct mqtt_subscribe_or_ack *sub_ack);


#endif
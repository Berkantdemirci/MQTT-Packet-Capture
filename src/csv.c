#include <stdio.h>

#include "mqtt_structure.h"
#include "csv.h"
#include "log.h"

FILE *fpt = NULL;

void open_csv(){

    fpt = fopen("mqtt.csv", "a+");
    if(fpt == NULL){
            log_err("FUNCTION : %s\tLINE %d\nCsv file couldn't open"
            ,__FUNCTION__,__LINE__);
            goto exit;
    }

    fprintf(fpt,"ID, Name, Email, Phone Number\n");

    exit:
        return;
};

void save_mqtt_data(struct mqtt_fix_header *fix_header,
                    struct mqtt_connect *connect,
                    struct mqtt_connect_ack *con_ack,
                    struct mqtt_subscribe_or_ack *sub,
                    struct mqtt_subscribe_or_ack *sub_ack){



}
#include <stdio.h>
#include <stdlib.h>

#include "mqtt_structure.h"
#include "csv.h"
#include "log.h"

FILE *fpt = NULL;

void open_csv(){

    fpt = fopen("mqtt.csv", "a");
    if(fpt == NULL){
            log_err("FUNCTION : %s\tLINE %d\nCsv file couldn't open"
            ,__FUNCTION__,__LINE__);
            exit(-1);
    }
};

void save_mqtt_data(struct mqtt_fix_header *fix_header,
                    struct mqtt_connect *connect,
                    struct mqtt_connect_ack *con_ack,
                    struct mqtt_subscribe_or_ack *sub,
                    struct mqtt_subscribe_or_ack *sub_ack){

    open_csv();

    if(connect != NULL){

        fprintf(fpt,"%s, %s, %u, %u, 0x%x, 0x%x, %d, %u, 0x%x, %u, %u, %s, , , , , , \n", 
                    fix_header->ip_src, fix_header->ip_dst, fix_header->s_port,fix_header->d_port,
                    fix_header->tcp_flag, fix_header->checksum, fix_header->caplen,
                    connect->mqtt_version, connect->connect_flag, connect->keep_alive, connect->client_id_length, connect->client_id
                );
    
        free(connect);
    }
    else if(con_ack != NULL){
        fprintf(fpt,"%s, %s, %u, %u, 0x%x, 0x%x, %d, , , , , , %d, %d, , , , \n", 
                    fix_header->ip_src, fix_header->ip_dst, fix_header->s_port,fix_header->d_port,
                    fix_header->tcp_flag, fix_header->checksum, fix_header->caplen,
                    con_ack->session_present, con_ack->connack_code
                );
        
        free(con_ack);
    }
    else if(sub != NULL){

        fprintf(fpt,"%s, %s, %u, %u, 0x%x, 0x%x, %d, , , , , , , , %d, %d, , \n", 
                    fix_header->ip_src, fix_header->ip_dst, fix_header->s_port,fix_header->d_port,
                    fix_header->tcp_flag, fix_header->checksum, fix_header->caplen,
                    sub->packet_id, sub->qos
        );

        free(sub);
    }
    else if(sub_ack != NULL){

        fprintf(fpt,"%s, %s, %u, %u, 0x%x, 0x%x, %d, , , , , , , , , , %d, %d\n", 
                    fix_header->ip_src, fix_header->ip_dst, fix_header->s_port,fix_header->d_port,
                    fix_header->tcp_flag, fix_header->checksum, fix_header->caplen,
                    sub_ack->packet_id, sub_ack->qos
        );

        free(sub_ack);
    }
    
    free(fix_header);
    fclose(fpt);
}
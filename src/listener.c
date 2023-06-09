/*
    Listener funcs source codes will be here
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "listener.h"
#include "log.h"
#include "mqtt_structure.h"
#include "csv.h"

uint8_t errbuf[PCAP_ERRBUF_SIZE];

struct mqtt_fix_header *fix_header = NULL;
struct mqtt_connect *conn = NULL;
struct mqtt_connect_ack *conn_ack = NULL;
struct mqtt_subscribe_or_ack *sub = NULL;
struct mqtt_subscribe_or_ack *sub_ack = NULL;


static void hexdump(void *_data, size_t byte_count) {
    log_info("\nhexdump(%p, 0x%lx)\n", _data, (unsigned long)byte_count);
    for (unsigned long byte_offset = 0; byte_offset < byte_count; byte_offset += 16) {
        uint8_t *bytes = ((uint8_t*)_data) + byte_offset;
        unsigned long line_bytes = (byte_count - byte_offset > 16) ? 16 : (byte_count - byte_offset);
        char line[1000];
        char *linep = line;
        linep += sprintf(linep, "%08lx  ", byte_offset);
        for (int i=0; i<16; i++) {
            if (i >= line_bytes) {
                linep += sprintf(linep, "   ");
            } 
            else {
                linep += sprintf(linep, "%02hhx ", bytes[i]);
            }
        }
    
        linep += sprintf(linep, " |");
        for (int i=0; i<line_bytes; i++) {
            if (isalnum(bytes[i]) || ispunct(bytes[i]) || bytes[i] == ' ') {
                *(linep++) = bytes[i];
            } 
            else {
                *(linep++) = '.';
            }
        }
        linep += sprintf(linep, "|");
        puts(line);
    }
    log_info("###############\n");
}

uint8_t *get_device_name(){

    uint8_t *dev = NULL;

    dev = pcap_lookupdev(errbuf);
    // returns the network name where packets will be captured

    if (dev == NULL) goto lookup_error;
    
    //log_info("%s",dev);
    return dev;

    lookup_error:
        log_err("FUNCTION : %s\tLINE %d\nCouldn't find default device : %s"
        ,__FUNCTION__,__LINE__,errbuf);
        return NULL;
    /*
        Gets device name to use 
    */
}

pcap_t *get_handle(uint8_t *dev){

    if(getuid() != 0) goto root_error;
    // packet capturing works only under root privileges

    pcap_t *handle = pcap_open_live(dev,BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 100, errbuf);

    /*
    handle = pcap_open_live("wlan0mon",     // iface (example : wlan0mon)
            100,                            // specifies the snapshot length to be set on the handle.
            PCAP_OPENFLAG_PROMISCUOUS,      // specifies if the interface is to be put into promiscuous mode.
            1000,                           // read timeout
            errbuf                          // error buffer
        );

    */

    if (handle == NULL) goto get_handle_error;

    return handle;

    get_handle_error:
        log_err("FUNCTION : %s\tLINE %d\nCouldn't open device : %s"
        ,__FUNCTION__,__LINE__,pcap_geterr(handle));
	    return NULL;

    root_error:
        log_err("FUNCTION : %s\tLINE %d\nYou have to be root%s"
        ,__FUNCTION__,__LINE__,pcap_geterr(handle));
	    return NULL;

}

void parse_mqtt(const uint8_t *payload, int payload_length) {
    // MQTT Fixed header
    uint8_t mqtt_message_type = (payload[0] & 0xF0) >> 4;

    int pos = 1; // Position in payload (skipping fixed header byte)
    int multiplier = 1;
    int remaining_length = 0;
    uint8_t encoded_byte;

    do {
        encoded_byte = payload[pos++];
        remaining_length += (encoded_byte & 0x7F) * multiplier;
        multiplier *= 0x80;
    } while ((encoded_byte & 0x80) != 0);

    // Parsing variable header based on the MQTT message type
    switch (mqtt_message_type) {
        case 1: { // CONNECT
            // Protocol Name

            printf("MQTT Message Type: CONNECT\n");

            conn = (struct mqtt_connect *)malloc(sizeof(struct mqtt_connect));
            
            if (conn == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                break;
            }

            uint16_t protocol_name_length = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            char *protocol_name = malloc(protocol_name_length + 1);

            if (protocol_name == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                break;
            }

            memcpy(protocol_name, payload + pos, protocol_name_length);
            protocol_name[protocol_name_length] = '\0';
            pos += protocol_name_length;

            printf("Protocol Name: %s\n", protocol_name);

            // Protocol Level
            uint8_t protocol_level = payload[pos++];
            conn->mqtt_version = protocol_level;
            printf("Protocol Level: %u\n", protocol_level);

            // Connect Flags
            uint8_t connect_flags = payload[pos++];
            conn->connect_flag = connect_flags;
            printf("Connect Flags: %02X\n", connect_flags);

            // Keep Alive
            uint16_t keep_alive = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            conn->keep_alive = keep_alive;
            printf("Keep Alive: %u\n", keep_alive);

            // Client ID
            uint16_t client_id_length = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            conn->client_id_length = client_id_length;

            char *client_id = malloc(client_id_length + 1);

            if (client_id == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                goto free;
            }
            memcpy(client_id, payload + pos, client_id_length);
            client_id[client_id_length] = '\0';
            pos += client_id_length;
            
            memcpy(conn->client_id, client_id, client_id_length + 1);

            printf("Client ID: %s\n\n", client_id);

            save_mqtt_data(fix_header,conn,NULL,NULL,NULL);

            free(client_id);
            free:
                free(protocol_name);

            break;
        }
        case 2: { // CONNACK

            printf("MQTT Message Type: CONNACK\n");

            conn_ack = (struct mqtt_connect_ack *)malloc(sizeof(struct mqtt_connect_ack));

            if (conn_ack == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                break;
            }

            uint8_t session_present = payload[pos++] & 0x01;
            conn_ack->session_present = session_present;

            uint8_t connack_code = payload[pos++];
            conn_ack->connack_code = connack_code;

            printf("Session Present: %u\n", session_present);
            printf("CONNACK Code: %u\n\n", connack_code);

            save_mqtt_data(fix_header,NULL, conn_ack,NULL,NULL);

            break;
        }
        case 3: { // PUBLISH

            printf("MQTT Message Type: PUBLISH\n");

            // Topic Length
            uint16_t topic_length = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;

            // Topic
            char *topic = malloc(topic_length + 1);

            if (topic == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                break;
            }
            memcpy(topic, payload + pos, topic_length);
            topic[topic_length] = '\0';
            pos += topic_length;

            printf("Topic: %s\n\n", topic);

            free(topic);
            break;
        }

        case 4: // PUBACK
        case 5: // PUBREC
        case 6: // PUBREL
        case 7: // PUBCOMP
        case 11:{ // UNSUBACK

            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            printf("Packet ID: %u\n", packet_id);
            break;
        }
        
        case 8: { // SUBSCRIBE

            printf("MQTT Message Type: SUBSCRIBE\n");

            sub = (struct mqtt_subscribe_or_ack *)malloc(sizeof(struct mqtt_subscribe_or_ack));
        
            if (sub == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                break;
            }

            // Packet Identifier
            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            sub->packet_id = packet_id;

            printf("Packet Identifier: %u\n", packet_id);

            while (pos < payload_length) {
                // Topic Length
                uint16_t topic_length = ntohs(*((uint16_t *)(payload + pos)));
                pos += 2;

                // Topic
                char *topic = malloc((topic_length + 1));

                if (topic == NULL) {
                    log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                    ,__FUNCTION__,__LINE__);
                    goto exit;
                }
                memcpy(topic, payload + pos, topic_length);
                topic[topic_length] = '\0';
                pos += topic_length;

                printf("Topic: %s\n", topic);

                // QoS
                uint8_t qos = payload[pos++];
                printf("QoS: %u\n\n", qos);

                sub->qos = qos;

                free(topic);
            }

            save_mqtt_data(fix_header,NULL, NULL,sub,NULL);

            exit:
                break;
        }
        case 9: { // SUBACK

            printf("MQTT Message Type: SUBACK\n");

            sub_ack = (struct mqtt_subscribe_or_ack *)malloc(sizeof(struct mqtt_subscribe_or_ack));

            if (sub_ack == NULL) {
                    log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                    ,__FUNCTION__,__LINE__);
                    break;
            }
            // Packet Identifier
            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            sub->packet_id = packet_id;

            printf("Packet Identifier: %u\n", packet_id);

            while (pos < payload_length) {
                // QoS
                uint8_t qos = payload[pos++];
                
                printf("QoS: %u\n", qos);
            }

            sub->packet_id = packet_id;

            save_mqtt_data(fix_header,NULL, NULL,NULL,sub_ack);

            break;
        }

        case 10: { // UNSUBSCRIBE

            printf("MQTT Message Type: UNSUBSCRIBE\n");
        
            // Packet Identifier
            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;

            printf("Packet Identifier: %u\n", packet_id);

            while (pos < payload_length) {
                // Topic Length
                uint16_t topic_length = ntohs(*((uint16_t *)(payload + pos)));
                pos += 2;

                // Topic
                char *topic = malloc(topic_length + 1);
                memcpy(topic, payload + pos, topic_length);
                topic[topic_length] = '\0';
                pos += topic_length;

                printf("Topic: %s\n", topic);

                free(topic);
        }
            break;
        }

        case 12: { // PINGREQ
            printf("PINGREQ\n\n");
            break;
        }
        case 13: { // PINGRESP
            printf("PINGRESP\n\n");
            break;
        }
        case 14: { // DISCONNECT
            printf("DISCONNECT\n\n");
            break;
        }

        default: {
            log_err("Unsupported MQTT packet type\n");
            break;
        }
    }
}

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
){
    struct ip *ip_header = (struct ip *)(packet + 14); // +14 means skip ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

    fix_header = (struct mqtt_fix_header *)malloc(sizeof(struct mqtt_fix_header));

    if(fix_header == NULL){
            log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
            ,__FUNCTION__,__LINE__);
            exit(-1);
    }

    if (ip_header->ip_p == IPPROTO_TCP && (ntohs(tcp_header->th_sport) == MQTT_PORT || ntohs(tcp_header->th_dport) == MQTT_PORT)) {
        int payload_offset = 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
        int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4 + tcp_header->th_off * 4);
        if (payload_length > 0) {

            memcpy(fix_header->ip_src,inet_ntoa(ip_header->ip_src),16);
            memcpy(fix_header->ip_dst,inet_ntoa(ip_header->ip_dst),16);

            fix_header->s_port = ntohs(tcp_header->th_sport);
            fix_header->d_port = ntohs(tcp_header->th_dport);
            fix_header->tcp_flag = tcp_header->th_flags;
            fix_header->caplen = header->caplen;
            fix_header->checksum = ntohs(tcp_header->th_sum);
            
            parse_mqtt(packet + payload_offset, payload_length);
        }
    }

/*
    This func parses Ethernet header of captured packets.
    If a MQTT packet does not have Ethernet header, This func will ignore it.
    The packets that generated through mosquitto_pub by using localhost as host to connect
    (e.g mosquitto_pub -h localhost -t "topic" -m "led on")
    will not have proper ethernet header for this parsing algorithm. So you can't capture that type of packets by using this project.

    Also, the packets will be invisible for pcap_lookupdev's return value. (e.g wlp0s20f3 (wifi interface))
    You should switch the capturing device to "any" if you are strictly insistent about capturing that type of packet.
    But changing capturing device has consecuenses. You can't see the packet which has ethernet header.
*/
}

void *set_filter(pcap_t *handle){

    struct bpf_program filter = {0};
    uint8_t filter_exp[] = "tcp port 1883";
    bpf_u_int32 tmp;

    if (pcap_compile(handle, &filter, filter_exp, 0, tmp) == -1) {
        log_err("FUNCTION : %s\tLINE %d\nBad filter - %s"
        ,__FUNCTION__,__LINE__,pcap_geterr(handle));
        return NULL;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        log_err("FUNCTION : %s\tLINE %d\nError setting filter - %s"
        ,__FUNCTION__,__LINE__,pcap_geterr(handle));
        return NULL;
    }

    log_info("### FILTER HAS BEEN SETTED ###");

/*
  just capture mqtt packets 
*/
}

void start_mqtt_capture(pcap_t *handle){

    log_info("### LISTENING HAS BEEN STARTED ###");

    if ( NULL == set_filter(handle)) goto terminate;
  
    if (pcap_loop(handle,0,packet_handler,NULL) < 0) {
        log_err("FUNCTION : %s\tLINE %d\npcap_loop failed: %s"
        ,__FUNCTION__,__LINE__,pcap_geterr(handle));
        goto terminate;
    }

    terminate:
        exit(-1);
}

void stop_mqtt_capture(pcap_t *handle){

    log_info("### STOP CAPTURE HAS BEEN STARTED ###");

    struct pcap_stat stats = {0};
    pcap_breakloop(handle);
    // stop capture loop

    if (pcap_stats(handle, &stats) >= 0) {
        //printf("\n%d packets captured\n", packets);
        log_info("%d packets received", stats.ps_recv);
        log_info("%d packets dropped", stats.ps_drop);
    }

    pcap_close(handle);

    log_info("### HANDLER CLOSED ###");
    exit(0);
    /*
        closes handler if stop_mqtt_capture have been called 
        or process be interrupted
    */

}

struct handler_struct *listener_init(){

    log_info("### STARTED TO BUILD HANDLER ###");

    struct handler_struct *data = NULL;

    data = (struct handler_struct *)malloc(sizeof(struct handler_struct));
    
    if (data == NULL) {
        log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
        ,__FUNCTION__,__LINE__);
        goto exit;
    }

    data->device_name = get_device_name();
    if(data->device_name == NULL) goto free;
    
    // // checks whether device is in monitor mode or not
    // if(strcmp((strrchr(data->device_name, '\0')) -3, "mon")){
    //     log_err("FUNCTION : %s\tLINE %d\nDevice is not promiscuous"
    //     ,__FUNCTION__,__LINE__);
    //     goto free;
    // }
    
    data->handle = get_handle(data->device_name);
    if(data->handle == NULL) goto free;

    data->start = start_mqtt_capture;
    data->stop = stop_mqtt_capture;

    log_info("### HANDLER HAS BEEN INITIALIZED SUCCESSFULLY ###");
    return data;

    free:
        free(data);
    exit:
        exit(-1);
    
}
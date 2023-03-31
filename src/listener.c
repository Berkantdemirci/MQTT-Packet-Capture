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

unsigned char errbuf[PCAP_ERRBUF_SIZE];

static void hexdump(void *_data, size_t byte_count) {
  log_info("\nhexdump(%p, 0x%lx)\n", _data, (unsigned long)byte_count);
  for (unsigned long byte_offset = 0; byte_offset < byte_count; byte_offset += 16) {
    unsigned char *bytes = ((unsigned char*)_data) + byte_offset;
    unsigned long line_bytes = (byte_count - byte_offset > 16) ?
	    16 : (byte_count - byte_offset);
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      if (i >= line_bytes) {
        linep += sprintf(linep, "   ");
      } else {
        linep += sprintf(linep, "%02hhx ", bytes[i]);
      }
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<line_bytes; i++) {
      if (isalnum(bytes[i]) || ispunct(bytes[i]) || bytes[i] == ' ') {
        *(linep++) = bytes[i];
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
  log_info("###############\n");

}

unsigned char *get_device_name(){

    unsigned char *dev = NULL;

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

pcap_t *get_handle(unsigned char *dev){

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
        ,__FUNCTION__,__LINE__,errbuf);
	    return NULL;

    root_error:
        log_err("FUNCTION : %s\tLINE %d\nYou have to be root%s"
        ,__FUNCTION__,__LINE__,errbuf);
	    return NULL;

}

void parse_mqtt(const unsigned char *payload, int payload_length) {
    // MQTT Fixed header
    unsigned char mqtt_message_type = (payload[0] & 0xF0) >> 4;

    int pos = 1; // Position in payload (skipping fixed header byte)
    int multiplier = 1;
    int remaining_length = 0;
    unsigned char encoded_byte;

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
            printf("Protocol Level: %u\n", protocol_level);

            // Connect Flags
            uint8_t connect_flags = payload[pos++];
            printf("Connect Flags: %02X\n", connect_flags);

            // Keep Alive
            uint16_t keep_alive = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            printf("Keep Alive: %u\n", keep_alive);

            // Client ID
            uint16_t client_id_length = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;
            char *client_id = malloc(client_id_length + 1);

            if (client_id == NULL) {
                log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
                ,__FUNCTION__,__LINE__);
                goto free;
            }
            memcpy(client_id, payload + pos, client_id_length);
            client_id[client_id_length] = '\0';
            pos += client_id_length;

            printf("Client ID: %s\n\n", client_id);

            free(client_id);
            free:
                free(protocol_name);

            break;
        }
        case 2: { // CONNACK

            printf("MQTT Message Type: CONNACK\n");
        
            uint8_t session_present = payload[pos++] & 0x01;
            uint8_t connack_code = payload[pos++];

            printf("Session Present: %u\n", session_present);
            printf("CONNACK Code: %u\n\n", connack_code);
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
        
            // Packet Identifier
            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;

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

                free(topic);
            }
            exit:
                break;
        }
        case 9: { // SUBACK

            printf("MQTT Message Type: SUBACK\n");

            // Packet Identifier
            uint16_t packet_id = ntohs(*((uint16_t *)(payload + pos)));
            pos += 2;

            printf("Packet Identifier: %u\n", packet_id);

            while (pos < payload_length) {
                // QoS
                uint8_t qos = payload[pos++];

                printf("QoS: %u\n", qos);
                }

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
            printf("PINGREQ\n");
            break;
        }
        case 13: { // PINGRESP
            printf("PINGRESP\n");
            break;
        }
        case 14: { // DISCONNECT
            printf("DISCONNECT\n");
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
/*
This func will send raw mqtt packets to database
*/
    //hexdump((void *)packet,header->caplen);
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

    if (ip_header->ip_p == IPPROTO_TCP && (ntohs(tcp_header->th_sport) == MQTT_PORT || ntohs(tcp_header->th_dport) == MQTT_PORT)) {
        int payload_offset = 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
        int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4 + tcp_header->th_off * 4);
        if (payload_length > 0) {
            parse_mqtt(packet + payload_offset, payload_length);
        }
    }

}

void *set_filter(pcap_t *handle){

    struct bpf_program filter = {0};
    unsigned char filter_exp[] = "tcp port 1883";
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
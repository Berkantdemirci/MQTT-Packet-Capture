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

void send_packets_to_db(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
){
/*
This func will send raw mqtt packets to database
*/
    hexdump((void *)packet,header->caplen);

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
  
    if (pcap_loop(handle,0,send_packets_to_db,NULL) < 0) {
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
        exit(-1);
    }

    data->device_name = "any";

    // data->device_name = get_device_name();
    // if(data->device_name == NULL) goto free;

    // // checks whether device is in monitor mode or not
    // if(strcmp((strrchr(data->device_name, '\0')) -3, "mon")){
    //     log_err("FUNCTION : %s\tLINE %d\nDevice is not promiscuous"
    //     ,__FUNCTION__,__LINE__);
    //     goto free;
    // }
    
    //  I realized that the mqtt protocol packets is only visible for device named "any" 

    data->handle = get_handle(data->device_name);
    if(data->handle == NULL) goto free;

    data->start = start_mqtt_capture;
    data->stop = stop_mqtt_capture;

    log_info("### HANDLER HAS BEEN INITIALIZED SUCCESSFULLY ###");
    return data;

    free:
        free(data);
        exit(-1);
    
}
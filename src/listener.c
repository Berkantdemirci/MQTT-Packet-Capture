/*
    Listener funcs source codes will be here
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "listener.h"
#include "log.h"
#include "mqtt_structure.h"

unsigned char errbuf[PCAP_ERRBUF_SIZE];

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
    // packet capturing works under root privileges

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

void stop_mqtt_capture(pcap_t *handle){

    struct pcap_stat stats;

    if (pcap_stats(handle, &stats) >= 0) {
        //printf("\n%d packets captured\n", packets);
        log_info("%d packets received", stats.ps_recv);
        log_info("%d packets dropped", stats.ps_drop);
    }

    pcap_close(handle);

    log_info("### Handler Closed ###");

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

    data->device_name = get_device_name();
    if(data->device_name == NULL) goto free;

    // checks whether device is in monitor mode or not
    if(strcmp((strrchr(data->device_name, '\0')) -3, "mon")){
        log_err("FUNCTION : %s\tLINE %d\nDevice is not promiscuous"
        ,__FUNCTION__,__LINE__);
        goto free;
    }

    data->handle = get_handle(data->device_name);
    if(data->handle == NULL) goto free;

    data->stop = stop_mqtt_capture;

    log_info("### Handler has been initialized succesfully ###");
    return data;

    free:
        free(data);
        exit(-1);
    
}
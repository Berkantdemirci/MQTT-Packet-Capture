/*
    Listener funcs source codes will be here
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#include "listener.h"
#include "log.h"
#include "mqtt_structure.h"

pcap_t *handle = NULL;
unsigned char errbuf[PCAP_ERRBUF_SIZE];
// exp node gibi yap

unsigned char *get_device_name(){

    unsigned char *dev = NULL;

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) goto lookup_error;
    
    //log_info("%s",dev);
    return dev;

    lookup_error:
        log_err("FUNCTION : %s\tLINE %d\nCouldn't find default device : %s"
        ,__FUNCTION__,__LINE__,errbuf);
        exit(-1);
    /*
        Gets device name to use 
    */
}

pcap_t *get_handle(unsigned char *dev,int read_timeout,unsigned char *errbuf){

    handle = pcap_open_live(dev,BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, read_timeout, errbuf);

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
	    exit(-1);

}

void listener_init(struct handler_struct *handler){

    struct handler_struct *data = (struct handler_struct *)malloc(sizeof(struct handler_struct));

    if (data == NULL) {
        log_err("FUNCTION : %s\tLINE %d\nMalloc returned null"
        ,__FUNCTION__,__LINE__);
        exit(-1);
    }

    data->device_name = get_device_name();

    // checks whether device is in monitor mode or not
    if(strcmp((char *)(strrchr(data->device_name, '\0')) -3, "mon")){
        
        log_err("FUNCTION : %s\tLINE %d\nDevice is not promiscuous"
        ,__FUNCTION__,__LINE__);
        goto free;
    }

    return;

    free:
        free(data);
        exit(-1);
    
}
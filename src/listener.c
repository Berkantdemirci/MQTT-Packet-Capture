/*
    Listener funcs source codes will be here
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "listener.h"
#include "log.h"

unsigned char *get_device_name(){

    unsigned char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
		log_err("Couldn't find default device : %s",errbuf);
        return NULL;
	}

    log_info("%s",dev);
    return dev;

    /*
        Gets device name to use 
    */
}
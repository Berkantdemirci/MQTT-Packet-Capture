#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "log.h"
#include "listener.h"
#include "mqtt_structure.h"

struct handler_struct *handler;

void stop_process(int signo){

    handler->stop(handler->handle);
}

int main(){

    signal(SIGINT, stop_process);
    signal(SIGTERM, stop_process);
    signal(SIGQUIT, stop_process);
    signal(SIGKILL, stop_process);
    /* call stop_mqtt_capture func if process get these signals*/

    handler = listener_init();
    log_info("Device name : %s",handler->device_name);
    
    handler->start(handler->handle);
    
    handler->stop(handler->handle);
    return 0;
}

/*
There is 2 way to stop execution

- Sending signal to process such as SIGINT, SIGKILL
- Calling handler->stop(handler->handle) function 
*/
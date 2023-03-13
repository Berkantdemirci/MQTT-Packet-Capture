#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include "listener.h"
#include "mqtt_structure.h"

int main(){

    struct handler_struct *handler;
    handler = listener_init();

    handler->stop(handler->handle);
    return 0;
}

/*
There is 2 way to stop execution

- Sending signal to process such as SIGINT, SIGKILL
- Calling handler->stop(handler->handle) function 
*/
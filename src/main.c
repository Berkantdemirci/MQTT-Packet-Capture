#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include "listener.h"
#include "mqtt_structure.h"

int main(){
    struct handler_struct *handler;
    listener_init(handler);
    return 0;
}
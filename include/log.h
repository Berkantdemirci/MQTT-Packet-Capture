#ifndef __LOG_H_
#define __LOG_H_

#include <stdio.h>

#define RED_COLOR "\033[22;31m"
#define GREEN_COLOR  "\033[22;32m"
#define END_COLOR  "\033[0m"

ssize_t log_info(const char *format, ...);
ssize_t log_err(const char *format, ...);

#endif
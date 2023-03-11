#ifndef __LOG_H_
#define __LOG_H_

#include <stdio.h>

ssize_t log_info(const char *format, ...);
ssize_t log_err(const char *format, ...);

#endif
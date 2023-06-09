/*
    Log message functions 
*/

#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

#include "log.h"

ssize_t log_info(const char *format, ...)
{
	va_list args;
	ssize_t len = 0;
	uint8_t buf[0x1000];

	memset(buf, 0, 0x1000);
	va_start(args, format);
	len = vsnprintf(buf, INT_MAX, format, args);
	va_end(args);
	
	fprintf(stdout, "%s[+] %s%s\n", GREEN_COLOR, buf,END_COLOR);

	return len;
}

ssize_t log_err(const char *format, ...)
{
	va_list args;
	ssize_t len = 0;
	uint8_t buf[0x1000];
	memset(buf, 0, 0x1000);
	va_start(args, format);
	len = vsnprintf(buf, INT_MAX, format, args);
	va_end(args);

	fprintf(stderr, "%s[-] %s%s\n", RED_COLOR,buf,END_COLOR);

	return len;
}
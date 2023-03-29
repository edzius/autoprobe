
#include <stdio.h>
#include <stdarg.h>

#include "logger.h"

int log_level = LOG_NOTICE;

void log_write(int level, char *format, ...)
{
	va_list ap;

	if (log_level < level)
		return;

	va_start(ap, format);
	vfprintf(level < LOG_NOTICE ? stderr : stdout, format, ap);
	va_end(ap);
}

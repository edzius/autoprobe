
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

const char *arr2str(char *arr[], int cnt)
{
	int i;
	char *tmpbuf;
	size_t tmplen = 0;
	static char *buffer;
	static size_t buflen;

	if (!cnt)
		return "none";

	for (i = 0; i < cnt; i++)
		tmplen += strlen(arr[i]);
	tmplen += cnt;

	if (tmplen >= buflen) {
		tmpbuf = realloc(buffer, tmplen);
		if (!tmpbuf)
			return "<e>";
		buflen = tmplen;
		buffer = tmpbuf;
	}

	tmpbuf = buffer;
	for (i = 0; i < cnt; i++)
		tmpbuf += sprintf(tmpbuf, "%s,", arr[i]);
	*--tmpbuf = '\0';

	return buffer;
}

#ifndef _LOGGER_H
#define _LOGGER_H

#ifdef DEBUG
#define log_debug printf
#else
#define log_debug(...)
#endif
#define log_info printf
#define log_notice printf
#define log_warn printf
#define log_error printf

#endif // _LOGGER_H

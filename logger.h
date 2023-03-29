#ifndef _LOGGER_H
#define _LOGGER_H

#define LOG_OFF 0
#define LOG_ERROR 1
#define LOG_WARN 2
#define LOG_NOTICE 3
#define LOG_INFO 4
#define LOG_DEBUG 5
#define LOG_ALL 6

#ifndef DEBUG
#define log_verbose(...)
#else
#define log_verbose(format, ...) log_write(LOG_ALL, format, ##__VA_ARGS__)
#endif
#define log_debug(format, ...) log_write(LOG_DEBUG, format, ##__VA_ARGS__)
#define log_info(format, ...) log_write(LOG_INFO, format, ##__VA_ARGS__)
#define log_notice(format, ...) log_write(LOG_NOTICE, format, ##__VA_ARGS__)
#define log_warn(format, ...) log_write(LOG_WARN, format, ##__VA_ARGS__)
#define log_error(format, ...) log_write(LOG_ERROR, format, ##__VA_ARGS__)

extern int log_level;

void log_write(int level, char *fmt, ...);
const char *arr2str(char *arr[], int cnt);

#endif // _LOGGER_H

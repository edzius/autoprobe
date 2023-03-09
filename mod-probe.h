#ifndef _MOD_PROBE_H
#define _MOD_PROBE_H

int modline_parse(const char *line, char ***arr, int *len);
int modprb_init(void);
int modprb_loaded(const char *name);
int modprb_insert(const char *name, const char *path, const char *opts);

#endif // _MOD_PROBE_H

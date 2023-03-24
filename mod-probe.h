#ifndef _MOD_PROBE_H
#define _MOD_PROBE_H

struct mod_info;

int modline_parse(const char *line, char ***arr, int *len);
int modprb_init(void);
void modprb_iterate(int (*cb)(const char *name, void *ctx), void *ctx);
int modprb_search(const char *name, struct mod_info *info);
int modprb_loaded(const char *name);
int modprb_insert(const char *name, const char *path, const char *opts);
int modprb_remove(const char *name);

#endif // _MOD_PROBE_H

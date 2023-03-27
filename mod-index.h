#ifndef _MOD_INDEX_H
#define _MOD_INDEX_H

int mod_init(const char *moddir);
int mod_search(const char *modname, struct mod_info *info);
void mod_iterate(int (*cb)(const char *name, void *ctx), void *ctx);
void modidx_free(struct mod_info *info);

#endif // _MOD_INDEX_H

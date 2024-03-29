#ifndef _LIBMODULES_H
#define _LIBMODULES_H

#include "list.h"

struct mod_item {
	struct mod_item *next;
	char value[0];
};

struct mod_file {
	struct list_head list;
	char *mod_path;
	char *mod_file;
	char *mod_name;
	char **mod_deps;
	int mod_depcnt;
	int mod_inspect;
};

int libmod_init(const char *moddir);
struct mod_file *libmod_search(const char *modname);
struct mod_item *libmod_all(void);

#endif // _LIBMODULES_H

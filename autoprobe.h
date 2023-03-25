#ifndef _AUTOPROBE_H
#define _AUTOPROBE_H

#include "list.h"

extern int opt_dry;
extern int opt_force;

struct mod_info {
	struct list_head list;
	char *name;
	char *opts;
	char *path;
	char **deps;
	int depcnt;
};

#endif // _AUTOPROBE_H

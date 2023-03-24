#ifndef _AUTOPROBE_H
#define _AUTOPROBE_H

#include "list.h"

struct mod_info {
	struct list_head list;
	char *name;
	char *opts;
	char *path;
};

#endif // _AUTOPROBE_H

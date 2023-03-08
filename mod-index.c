
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libkmod-index.h"
#include "libmodules.h"
#include "autoprobe.h"

static struct index_mm *idx;
static char *mod_dir;

static char *
modname_normalize(const char *modname, char buf[PATH_MAX], size_t *len)
{
	size_t s;

	for (s = 0; s < PATH_MAX - 1; s++) {
		const char c = modname[s];
		if (c == '-')
			buf[s] = '_';
		else if (c == '\0' || c == '.')
			break;
		else
			buf[s] = c;
	}

	buf[s] = '\0';

	if (len)
		*len = s;

	return buf;
}

static int
modidx_parse(struct mod_info *info, const char *name, const char *line)
{
	char buf[PATH_MAX];
	char *p;
	char **newdeps;
	int newdepcnt;

	if (!name || !line)
		return -1;

	p = strchr(line, ':');
	if (p == NULL)
		return -1;
	*p++ = '\0';

	memset(info, 0, sizeof(*info));

	info->name = strdup(name);
	if (!info->name)
		return -1;

	if (asprintf(&info->path, "%s/%s", mod_dir, line) <= 0)
		return -1;

	for (p = strtok(p, " \t"); p != NULL;
	     p = strtok(NULL, " \t")) {
		if (p == NULL || p[0] == '\0')
			continue;

		newdepcnt = info->depcnt + 1;
		newdeps = realloc(info->deps, sizeof(*newdeps) * newdepcnt);
		if (!newdeps)
			return -1;

		info->deps = newdeps;
		info->deps[info->depcnt] = strdup(modname_normalize(basename(p), buf, NULL));
		info->depcnt = newdepcnt;
	}

	return 0;
}

static int
modidx_free(struct mod_info *info)
{
	int i;

	free(info->name);
	free(info->path);
	for (i = 0; i < info->depcnt; i++)
		free(info->deps[i]);
	free(info->deps);
}

int mod_init(const char *moddir)
{
	static char modfile[PATH_MAX];

	if (mod_dir)
		return 1;

	mod_dir = strdup(moddir);
	snprintf(modfile, sizeof(modfile), "%s/modules.dep.bin", moddir);

	if (!index_mm_open(modfile, &idx))
		return 0;
	if (!libmod_init(moddir))
		return 0;
	return 1;
}

int mod_search(const char *name, struct mod_info *info)
{
	int ret, i;
	char *line;
	struct mod_file *km;

	if (idx) {
		line = index_mm_search(idx, name);
		ret = modidx_parse(info, name, line);
		if (line)
			free(line);

		return ret;
	} else {
		km = libmod_search(name);
		if (!km)
			return -1;

		info->name = km->mod_name;
		info->path = km->mod_path;
		info->depcnt = km->mod_depcnt;
		if (info->depcnt) {
			info->deps = calloc(info->depcnt, sizeof(*info->deps));
			for (i = 0; i < info->depcnt; i++)
				info->deps[i] = strdup(km->mod_deps[i]);
		}

		return 0;
	}

	return -1;
}

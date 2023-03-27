
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

void
modidx_free(struct mod_info *info)
{
	int i;

	if (info->name)
		free(info->name);
	if (info->path)
		free(info->path);
	if (info->deps) {
		for (i = 0; i < info->depcnt; i++)
			free(info->deps[i]);
		free(info->deps);
	}
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
		goto err;

	if (asprintf(&info->path, "%s/%s", mod_dir, line) <= 0)
		goto err;

	for (p = strtok(p, " \t"); p != NULL;
	     p = strtok(NULL, " \t")) {
		if (p == NULL || p[0] == '\0')
			continue;

		newdepcnt = info->depcnt + 1;
		newdeps = realloc(info->deps, sizeof(*newdeps) * newdepcnt);
		if (!newdeps)
			goto err;

		info->deps = newdeps;
		info->deps[info->depcnt] = strdup(modname_normalize(basename(p), buf, NULL));
		info->depcnt = newdepcnt;
	}

	return 0;
err:
	modidx_free(info);
	return -1;
}

char *mod_name(const char *name)
{
	static char modname[PATH_MAX];

	return modname_normalize(name, modname, NULL);
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

	/* provided module name is expected to be sanitised */

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

		info->name = strdup(km->mod_name);
		info->path = strdup(km->mod_path);
		if (!info->name || !info->path)
			goto err;

		info->depcnt = km->mod_depcnt;
		if (info->depcnt) {
			info->deps = calloc(info->depcnt, sizeof(*info->deps));
			if (!info->deps)
				goto err;
			for (i = 0; i < info->depcnt; i++)
				info->deps[i] = strdup(km->mod_deps[i]);
		}

		return 0;
	}

err:
	modidx_free(info);
	return -1;
}

void mod_iterate(int (*cb)(const char *name, void *ctx), void *ctx)
{
	struct mod_item *im, *om;
	struct index_value *ix, *ox;
	char *sep;

	if (idx) {
		ix = index_mm_all(idx);
		if (!ix)
			return;

		while (ix) {
			sep = strchr(ix->value, ' ');
			if (sep) {
				*sep++ = '\0';
				cb(ix->value, ctx);
			}

			ox = ix;
			ix = ix->next;
			free(ox);
		}
	} else {
		im = libmod_all();
		if (!im)
			return;

		while (im) {
			cb(im->value, ctx);

			om = im;
			im = im->next;
			free(om);
		}
	}
}

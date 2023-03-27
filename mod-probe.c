
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "list.h"
#include "logger.h"
#include "autoprobe.h"

static LLIST_HEAD(probed_list);

int modline_parse(const char *line, char ***arr, int *len)
{
	int tmpcnt;
	char **tmp;
	char *p, *n;

	if (!line || !*line || !arr)
		return -1;

	n = strdup(line);
	p = strtok(n, ",");
	do {
		tmpcnt = *len + 1;
		tmp = realloc(*arr, tmpcnt * sizeof(*tmp));
		if (!tmp)
			return -1;
		*arr = tmp;
		(*arr)[*len] = p;
		*len = tmpcnt;
	} while ((p = strtok(NULL, ",")));

	return *len;
}

int modprb_init(void)
{
	size_t len = 0;
	char *buf = NULL;
	FILE *fp;
	char *name, *deps;
	int size, usage;
	struct mod_info *info;
	(void)size; /* silence unused */

	fp = fopen("/proc/modules", "r");
	if (!fp) {
		log_error("Cannot open proc modules\n");
		return -1;
	}

	while (getline(&buf, &len, fp) > 0) {
		name = strtok(buf, " ");
		size = atoi(strtok(NULL, " "));
		usage = atoi(strtok(NULL, " "));
		deps = strtok(NULL, " ");

		info = calloc(1, sizeof(*info));
		info->name = strdup(name);
		info->usage = usage;
		if (deps && strcmp(deps, "-"))
			modline_parse(deps, &info->deps, &info->depcnt);

		list_add_tail(&info->list, &probed_list);
	}
	free(buf);
	fclose(fp);

	return 0;
}

void modprb_iterate(int (*cb)(const char *name, void *ctx), void *ctx)
{
	struct mod_info *info;

	list_for_each_entry(info, &probed_list, list) {
		cb(info->name, ctx);
	}
}

int modprb_search(const char *name, struct mod_info *result)
{
	struct mod_info *info;
	int found = 0;

	list_for_each_entry(info, &probed_list, list) {
		if (!strcmp(name, info->name)) {
			found = 1;
			break;
		}
	}

	if (found && result) {
		memset(result, 0, sizeof(*result));

		result->name = info->name;
		result->deps = info->deps;
		result->depcnt = info->depcnt;
		result->usage = info->usage;
	}

	return !found;
}

int modprb_loaded(const char *name)
{
	return !modprb_search(name, NULL);
}

int modprb_insert(const char *name, const char *path, const char *opts)
{
	void *data = 0;
	struct stat s;
	int fd, ret = -1;

	if (!name || !path) {
		log_error("Path not specified\n");
		return ret;
	}

	if (opt_dry) {
		printf("Insert %s '%s' @ %s\n", name, opts, path);
		return 0;
	}

	if (stat(path, &s)) {
		log_error("missing module %s\n", path);
		return ret;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("cannot open %s\n", path);
		return ret;
	}

	data = malloc(s.st_size);
	if (!data) {
		log_error("out of memory\n");
		goto out;
	}

	if (read(fd, data, s.st_size) == s.st_size) {
		ret = syscall(__NR_init_module, data, (unsigned long)s.st_size, opts);
		if (errno == EEXIST)
			ret = 0;
		if (ret)
			log_info("failed to load module %s\n", name);
	} else {
		log_error("failed to read module %s\n", path);
	}

out:
	close(fd);
	free(data);

	return ret;
}

int modprb_remove(const char *name)
{
	int ret;

	if (opt_dry) {
		log_debug("Remove %s\n", name);
		return 0;
	}

	ret = syscall(__NR_delete_module, name, 0);
	if (ret)
		log_info("failed to unload module %s\n", name);

	return ret;
}

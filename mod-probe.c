
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "logger.h"
#include "autoprobe.h"

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

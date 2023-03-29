
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <ftw.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "list.h"
#include "logger.h"
#include "libmodules.h"
#include "mod-probe.h"

/* backwards compat with tiny libcs */
#ifndef FTW_CONTINUE
#define FTW_CONTINUE 0
#endif
#ifndef FTW_STOP
#define FTW_STOP 1
#endif

static LLIST_HEAD(kmod_list);

static int libmod_nftw_handler(const char *fpath, const struct stat *sb,
			       int typeflag, struct FTW *ftwbuf)
{
	char *pos;
	struct mod_file *km;

	if (typeflag != FTW_F && typeflag != FTW_SL)
		return FTW_CONTINUE;

	if (strcmp(fpath + strlen(fpath) - 3, ".ko"))
		return FTW_CONTINUE;

	km = calloc(1, sizeof(*km));
	if (!km) {
		log_error("calloc: %m\n");
		return FTW_STOP;
	}

	log_verbose("found '%s'\n", fpath);

	km->mod_path = strdup(fpath);
	if (!km->mod_path)
		return FTW_STOP;
	km->mod_file = strrchr(km->mod_path, '/');
	if (!km->mod_file)
		return FTW_STOP;
	km->mod_file++;
	km->mod_name = strdup(km->mod_file);
	/* Already checked */
	pos = strstr(km->mod_name, ".ko");
	*pos = '\0';

	list_add(&km->list, &kmod_list);

	return FTW_CONTINUE;
}

static int elf64_find_section(char *map, const char *section, unsigned int *offset, unsigned int *size)
{
	const char *secnames;
	Elf64_Ehdr *e;
	Elf64_Shdr *sh;
	int i;

	e = (Elf64_Ehdr *) map;
	sh = (Elf64_Shdr *) (map + e->e_shoff);

	secnames = map + sh[e->e_shstrndx].sh_offset;
	for (i = 0; i < e->e_shnum; i++) {
		if (!strcmp(section, secnames + sh[i].sh_name)) {
			*size = sh[i].sh_size;
			*offset = sh[i].sh_offset;
			return 0;
		}
	}

	return -1;
}

static int elf32_find_section(char *map, const char *section, unsigned int *offset, unsigned int *size)
{
	const char *secnames;
	Elf32_Ehdr *e;
	Elf32_Shdr *sh;
	int i;

	e = (Elf32_Ehdr *) map;
	sh = (Elf32_Shdr *) (map + e->e_shoff);

	secnames = map + sh[e->e_shstrndx].sh_offset;
	for (i = 0; i < e->e_shnum; i++) {
		if (!strcmp(section, secnames + sh[i].sh_name)) {
			*size = sh[i].sh_size;
			*offset = sh[i].sh_offset;
			return 0;
		}
	}

	return -1;
}

static int elf_find_section(char *map, const char *section, unsigned int *offset, unsigned int *size)
{
	int clazz = map[EI_CLASS];
	int endian = map[EI_DATA];

#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (endian != ELFDATA2LSB)
#elif __BYTE_ORDER == __BIG_ENDIAN
	if (endian != ELFDATA2MSB)
#else
#error "unsupported endian"
#endif
	{
		log_error("invalid endianess: %d\n", endian);
		return -1;
	}

	if (clazz == ELFCLASS32)
		return elf32_find_section(map, section, offset, size);
	else if (clazz == ELFCLASS64)
		return elf64_find_section(map, section, offset, size);

	log_error("unknown elf format %d\n", clazz);

	return -1;
}

static int libmod_fill(struct mod_file *mod)
{
	int fd, ret = -1;
	unsigned int offset, size;
	char *map = MAP_FAILED, *strings;
	struct stat s;

	if (mod->mod_inspect)
		return 0;

	if (!mod->mod_path)
		return -1;

	fd = open(mod->mod_path, O_RDONLY);
	if (fd < 0) {
		log_error("failed to open %s\n", mod->mod_name);
		goto out;
	}

	if (fstat(fd, &s) == -1) {
		log_error("failed to stat %s\n", mod->mod_name);
		goto out;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		log_error("failed to mmap %s\n", mod->mod_name);
		goto out;
	}

	if (elf_find_section(map, ".modinfo", &offset, &size)) {
		log_error("failed to load the .modinfo section from %s\n", mod->mod_name);
		goto out;
	}

	strings = map + offset;
	while (1) {
		char *sep;
		int len;

		while (!strings[0])
			strings++;
		if (strings >= map + offset + size)
			break;
		sep = strstr(strings, "=");
		if (!sep)
			break;
		len = sep - strings;
		sep++;
		if (!strncmp(strings, "depends=", len + 1))
			modline_parse(sep, &mod->mod_deps, &mod->mod_depcnt);
#if 0
		/* Disabled until imperative module inspection is enabled. */
		else if (!strncmp(strings, "name=", len + 1))
			mod->mod_name = strdup(sep);
#endif
		strings = &sep[strlen(sep)];
	}

	mod->mod_inspect = 1;

	ret = 0;
out:
	if (map != MAP_FAILED)
		munmap(map, s.st_size);

	if (fd >= 0)
		close(fd);

	return ret;
}

struct mod_file *libmod_search(const char *modname)
{
	struct mod_file *km;

	list_for_each_entry(km, &kmod_list, list) {
		if (strcmp(km->mod_name, modname))
			continue;

		if (libmod_fill(km))
			return NULL;

		return km;
	}

	return NULL;
}

struct mod_item *libmod_all(void)
{
	struct mod_item *item, *list = NULL;
	struct mod_file *km;

	list_for_each_entry(km, &kmod_list, list) {
		item = calloc(1, sizeof(*item) + strlen(km->mod_name) + 1);
		strcpy(item->value, km->mod_name);
		item->next = list;
		list = item;
	}

	return list;
}

int libmod_init(const char *moddir)
{
	log_verbose("search %s\n", moddir);

	if (nftw(moddir, libmod_nftw_handler, 10,
		 FTW_DEPTH | FTW_MOUNT | FTW_PHYS) < 0) {
		log_error("failed modules tree walk '%s'\n", moddir);
		return -1;
	}
	return 0;
}

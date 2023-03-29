
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "list.h"
#include "logger.h"
#include "autoprobe.h"
#include "mod-index.h"
#include "mod-probe.h"

#define MOD_LOAD_CONF "/etc/modules-load.d"
#define MOD_OWRT_CONF "/etc/modules.d"

#define MOD_OPT_LEN 128

int opt_dry;
int opt_force;
static int opt_reverse;
static int opt_info;

static void
modrec_add_option(struct mod_info *info, const char *modopts)
{
	if (!info->opts)
		info->opts = calloc(MOD_OPT_LEN, 1);
	else
		strcat(info->opts, " ");
	if (!info->opts)
		return;
	strcat(info->opts, modopts);
}

static void
modrec_add(struct list_head *modlist, struct mod_info *modinfo)
{
	int i;
	struct mod_info *info, *dep = NULL;
	struct list_head *pos, *head = modlist;

	/* Our goal here is to load module as early as
	 * possible but after all module dependencies
	 * are loaded.
	 * In our case items closer to the beginning of
	 * the list has less dependencies, whilst items
	 * at the end of list has more dependencies. */

	/* Search for insert position where
	 * all dependencies would be resolved. */
	for (i = 0; i < modinfo->depcnt; i++) {
		list_for_each(pos, head) {
			/* Safe guard to avoid exceeding head/last item */
			if (pos == modlist)
				break;
			info = list_entry(pos, struct mod_info, list);
			if (!strcmp(info->name, modinfo->deps[i])) {
				/* Update insert and lookup next item */
				head = pos;
				dep = info;
				break;
			}
		}
	}
	/* Place unrelated modules without deps at the end. */
	if (!modinfo->depcnt)
		head = head->prev;

	printf("stage module '%s' after '%s'\n",
		  modinfo->name, dep ? dep->name : "top");
	list_add(&modinfo->list, head);
}

static struct mod_info *
modrec_find(struct list_head *modlist, const char *modname)
{
	struct mod_info *info;

	list_for_each_entry(info, modlist, list) {
		if (!strcmp(info->name, modname)) {
			return info;
		}
	}
	return NULL;
}

static void
modrec_define_insert(struct list_head *modlist, const char *modname, const char *modopts)
{
	int i;
	struct mod_info *info;

	info = modrec_find(modlist, modname);
	if (info) {
		if (modopts)
			modrec_add_option(info, modopts);
		return;
	}

	info = malloc(sizeof(*info));
	if (!info) {
		log_error("Cannot alloc module info\n");
		return;
	}
	memset(info, 0, sizeof(*info));

	if (mod_search(modname, info)) {
		log_info("Cannot find module '%s'\n", modname);
		free(info);
		return;
	}
	if (modopts)
		modrec_add_option(info, modopts);

	for (i = 0; i < info->depcnt; i++) {
		modrec_define_insert(modlist, info->deps[i], NULL);
	}

	modrec_add(modlist, info);
}

static void
modrec_define_remove(struct list_head *modlist, const char *modname)
{
	int i;
	struct mod_info *info;

	info = modrec_find(modlist, modname);
	if (info)
		return;

	info = malloc(sizeof(*info));
	if (!info) {
		log_error("Cannot alloc module info\n");
		return;
	}
	memset(info, 0, sizeof(*info));

	if (modprb_search(modname, info)) {
		log_warn("Cannot find loaded module '%s'\n", modname);
		free(info);
		return;
	}

	for (i = 0; i < info->depcnt; i++) {
		modrec_define_remove(modlist, info->deps[i]);
	}

	modrec_add(modlist, info);
}

static char msgbuf[4096];

static int
modrec_load(struct list_head *modlist)
{
	char *p;
	int i;
	int total = 0, fails = 0;
	struct mod_info *info;

	log_notice("loading kernel modules..\n");

	list_for_each_entry(info, modlist, list) {
		if (modprb_loaded(info->name))
			continue;

		total++;
		if (modprb_insert(info->name, info->path, info->opts)) {
			fails++;
			p = msgbuf;
			p += sprintf(p, "'%s'", info->name);
			if (info->depcnt) {
				p += sprintf(p, ", requires: ");
				for (i = 0; i < info->depcnt; i++)
					p += sprintf(p, "'%s' ", info->deps[i]);
				p--;
			}
			log_info("Failed to load %s\n", msgbuf);
		}
	}

	if (fails)
		log_warn("Failed to load %i/%i modules\n", fails, total);

	return fails != 0;
}

static int
modrec_unload(struct list_head *modlist)
{
	char *p;
	int i;
	int total = 0, fails = 0;
	struct mod_info *info;

	log_notice("unloading kernel modules..\n");

	list_for_each_entry(info, modlist, list) {
		total++;
		if (modprb_remove(info->name)) {
			fails++;
			p = msgbuf;
			p += sprintf(p, "'%s'", info->name);
			if (info->depcnt) {
				p += sprintf(p, ", requires: ");
				for (i = 0; i < info->depcnt; i++)
					p += sprintf(p, "'%s' ", info->deps[i]);
				p--;
			}
			log_info("Failed to unload %s\n", msgbuf);
		}
	}

	if (fails)
		log_warn("Failed to unload %i/%i modules\n", fails, total);

	return fails != 0;
}

static int
modrec_config(struct list_head *modlist, const char *moddir)
{
	glob_t gl;
	char path[PATH_MAX];
	char *name;
	int j;

	sprintf(path, "%s/*", moddir);

	if (access(moddir, F_OK | R_OK | X_OK))
		return -1;

	log_info("configure modules list from %s\n", moddir);

	if (glob(path, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl) < 0)
		return -1;

	for (j = 0; j < gl.gl_pathc; j++) {
		FILE *fp;
		size_t mod_len = 0;
		char *mod = NULL;

		fp = fopen(gl.gl_pathv[j], "r");
		if (!fp) {
			log_debug("failed to open %s\n", gl.gl_pathv[j]);
			continue;
		}

		while (getline(&mod, &mod_len, fp) > 0) {
			char *nl, *opts;

			if (*mod == '#')
				continue;

			nl = strchr(mod, '\n');
			if (nl == mod)
				continue;
			if (nl)
				*nl = '\0';

			opts = strchr(mod, ' ');
			if (opts)
				*opts++ = '\0';

			/* sanitize module names got from external sources */
			name = mod_name(mod);
			log_debug("configure module '%s', params '%s'\n",
				  name, opts ? opts : "");
			modrec_define_insert(modlist, name, opts);
		}
		free(mod);
		fclose(fp);
	}

	globfree(&gl);

	return 0;
}

static int
modrec_print_stored(const char *name, void *ctx)
{
	struct mod_info info = {0};

	if (mod_search(name, &info)) {
		printf("* %s -- no info\n", name);
		return 0;
	}

	printf("%s %s @ %s",
	       modprb_loaded(info.name) ? "+" : "-",
	       info.name, info.path);
	if (info.depcnt) {
		int i;
		printf(" / ");
		for (i = 0; i < info.depcnt; i++)
			printf("%s, ", info.deps[i]);
	}
	printf("\n");
	modidx_free(&info);
	return 0;
}

static int
modrec_print_loaded(const char *name, void *ctx)
{
	struct mod_info info = {0};

	if (modprb_search(name, &info)) {
		printf("* %s -- no info\n", name);
		return 0;
	}

	printf("* %s (%u)", info.name, info.usage);
	if (info.depcnt) {
		int i;
		printf(" / ");
		for (i = 0; i < info.depcnt; i++)
			printf("%s, ", info.deps[i]);
	}
	printf("\n");
	return 0;
}

int modrec_collect_insert(const char *name, void *ctx)
{
	struct list_head *modlist = ctx;

	modrec_define_insert(modlist, name, NULL);

	return 0;
}

int modrec_collect_remove(const char *name, void *ctx)
{
	struct list_head *modlist = ctx;

	modrec_define_remove(modlist, name);

	return 0;
}

static void help(void)
{
	printf(
	       "Usage:\tautoprobe [-v[v..]] [-n] [-f] [-r] [-i]\n"
	       "\n"
	       "\t-v\tincrease logger verbosity level\n"
	       "\t-n\tno probe, dry-run mode\n"
	       "\t-f\tforce probe all modules\n"
	       "\t-r\treverse probe, unload modules\n"
	       "\t-i\tinspect modules\n"
	      );
	exit(1);
}

int main(int argc, char *argv[])
{
	struct list_head modlist = LIST_HEAD_INIT(modlist);
	struct utsname u;
	char dirname[PATH_MAX];
	char opt;

	while ((opt = getopt(argc, argv, "hvnfri")) != (char)-1) {
		switch (opt) {
		case 'n':
			opt_dry = 1;
			break;
		case 'f':
			opt_force = 1;
			break;
		case 'r':
			opt_reverse = 1;
			break;
		case 'i':
			opt_info = 1;
			break;
		case 'v':
			log_level++;
			break;
		case 'h':
		default: /* '?' */
			help();
			return 0;
		}
	}

	if (modprb_init()) {
		log_warn("cannot init probed modules\n");
	}

	if (opt_reverse) {
		modprb_iterate(modrec_collect_remove, &modlist);
		return modrec_unload(&modlist);
	}

	if (uname(&u) < 0) {
		log_error("cannot get kernel version\n");
		return -1;
	}
	log_debug("Loading modules for kernel %s\n", u.release);
	snprintf(dirname, sizeof(dirname), "/lib/modules/%s", u.release);

	if (mod_init(dirname)) {
		log_error("cannot find kernel modules\n");
		return -1;
	}

	if (opt_info) {
		printf("Modules stored:\n");
		mod_iterate(modrec_print_stored, NULL);
		printf("Modules loaded:\n");
		modprb_iterate(modrec_print_loaded, NULL);
		return 0;
	}

	modrec_config(&modlist, MOD_LOAD_CONF);
	modrec_config(&modlist, MOD_OWRT_CONF);
	if (getenv("MOD_CONF_DIR"))
		modrec_config(&modlist, getenv("MOD_CONF_DIR"));

	if (opt_force)
		mod_iterate(modrec_collect_insert, &modlist);

	return modrec_load(&modlist);
}

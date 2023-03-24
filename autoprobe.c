
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "list.h"
#include "logger.h"
#include "autoprobe.h"

#define MOD_LOAD_CONF "/etc/modules-load.d"
#define MOD_OWRT_CONF "/etc/modules.d"

#define MOD_OPT_LEN 128

static int opt_dry;
static int opt_force;
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
modrec_define(struct list_head *modlist, const char *modname, const char *modopts)
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

	info->name = strdup(modname);
	if (modopts)
		modrec_add_option(info, modopts);

	list_add(&info->list, modlist);
}

static int
modrec_config(struct list_head *modlist, const char *moddir)
{
	glob_t gl;
	char path[PATH_MAX];
	int j;

	sprintf(path, "%s/*", moddir);

	if (access(moddir, F_OK | R_OK | X_OK))
		return -1;

	log_info("collect kernel modules list from %s\n", moddir);

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

			log_debug("record kernel module '%s', params '%s'\n",
				  mod, opts);
			modrec_define(modlist, mod, opts);
		}
		free(mod);
		fclose(fp);
	}

	globfree(&gl);

	return 0;
}

static void help(void)
{
	printf(
	       "Usage:\tautoprobe [-n] [-f] [-r] [-i]\n"
	       "\n"
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
	char opt;

	while ((opt = getopt(argc, argv, "hnfri")) != -1) {
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
		case 'h':
		default: /* '?' */
			help();
			break;
		}
	}

	if (!opt_reverse && !opt_force &&
	    !opt_info && !opt_dry) {
		log_warn("no option given\n");
		help();
	}

	modrec_config(&modlist, MOD_LOAD_CONF);
	modrec_config(&modlist, MOD_OWRT_CONF);
	if (getenv("MOD_CONF_DIR"))
		modrec_config(&modlist, getenv("MOD_CONF_DIR"));

	return 0;
}

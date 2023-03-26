
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "logger.h"

static int opt_dry;
static int opt_force;
static int opt_reverse;
static int opt_info;

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

	return 0;
}

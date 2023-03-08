#ifndef _LIBKMOD_INDEX_H
#define _LIBKMOD_INDEX_H
/*
 * libkmod - interface to kernel module operations
 *
 * Copyright (C) 2011-2013  ProFUSION embedded systems
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

struct index_value {
	struct index_value *next;
	unsigned int priority;
	unsigned int len;
	char value[0];
};

struct index_mm;
int index_mm_open(const char *filename, struct index_mm **pidx);
void index_mm_close(struct index_mm *index);
char *index_mm_search(struct index_mm *idx, const char *key);
struct index_value *index_mm_searchwild(struct index_mm *idx, const char *key);
void index_mm_dump(struct index_mm *idx, int fd, const char *prefix);

#endif // _LIBKMOD_INDEX_H

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "logger.h"
#include "libkmod-index.h"

/* libkmod-index.c: module index file implementation
 *
 * Integers are stored as 32 bit unsigned in "network" order, i.e. MSB first.
 * All files start with a magic number.
 *
 * Magic spells "BOOTFAST". Second one used on newer versioned binary files.
 * #define INDEX_MAGIC_OLD 0xB007FA57
 *
 * We use a version string to keep track of changes to the binary format
 * This is stored in the form: INDEX_MAJOR (hi) INDEX_MINOR (lo) just in
 * case we ever decide to have minor changes that are not incompatible.
 */
#define INDEX_MAGIC 0xB007F457
#define INDEX_VERSION_MAJOR 0x0002
#define INDEX_VERSION_MINOR 0x0001
#define INDEX_VERSION ((INDEX_VERSION_MAJOR<<16)|INDEX_VERSION_MINOR)

/* The index file maps keys to values. Both keys and values are ASCII strings.
 * Each key can have multiple values. Values are sorted by an integer priority.
 *
 * The reader also implements a wildcard search (including range expressions)
 * where the keys in the index are treated as patterns.
 * This feature is required for module aliases.
 */
#define INDEX_CHILDMAX 128

/* Disk format:
 *
 *  uint32_t magic = INDEX_MAGIC;
 *  uint32_t version = INDEX_VERSION;
 *  uint32_t root_offset;
 *
 *  (node_offset & INDEX_NODE_MASK) specifies the file offset of nodes:
 *
 *       char[] prefix; // nul terminated
 *
 *       char first;
 *       char last;
 *       uint32_t children[last - first + 1];
 *
 *       uint32_t value_count;
 *       struct {
 *           uint32_t priority;
 *           char[] value; // nul terminated
 *       } values[value_count];
 *
 *  (node_offset & INDEX_NODE_FLAGS) indicates which fields are present.
 *  Empty prefixes are omitted, leaf nodes omit the three child-related fields.
 *
 *  This could be optimised further by adding a sparse child format
 *  (indicated using a new flag).
 *
 *
 * Implementation is based on a radix tree, or "trie".
 * Each arc from parent to child is labelled with a character.
 * Each path from the root represents a string.
 *
 * == Example strings ==
 *
 * ask
 * ate
 * on
 * once
 * one
 *
 * == Key ==
 *  + Normal node
 *  * Marked node, representing a key and it's values.
 *
 * +
 * |-a-+-s-+-k-*
 * |   |
 * |   `-t-+-e-*
 * |
 * `-o-+-n-*-c-+-e-*
 *         |
 *         `-e-*
 *
 * Naive implementations tend to be very space inefficient; child pointers
 * are stored in arrays indexed by character, but most child pointers are null.
 *
 * Our implementation uses a scheme described by Wikipedia as a Patrica trie,
 *
 *     "easiest to understand as a space-optimized trie where
 *      each node with only one child is merged with its child"
 *
 * +
 * |-a-+-sk-*
 * |   |
 * |   `-te-*
 * |
 * `-on-*-ce-*
 *      |
 *      `-e-*
 *
 * We still use arrays of child pointers indexed by a single character;
 * the remaining characters of the label are stored as a "prefix" in the child.
 *
 * The paper describing the original Patrica trie works on individiual bits -
 * each node has a maximum of two children, which increases space efficiency.
 * However for this application it is simpler to use the ASCII character set.
 * Since the index file is read-only, it can be compressed by omitting null
 * child pointers at the start and end of arrays.
 */

/* Format of node offsets within index file */
enum node_offset {
	INDEX_NODE_FLAGS    = 0xF0000000, /* Flags in high nibble */
	INDEX_NODE_PREFIX   = 0x80000000,
	INDEX_NODE_VALUES = 0x40000000,
	INDEX_NODE_CHILDS   = 0x20000000,

	INDEX_NODE_MASK     = 0x0FFFFFFF, /* Offset value */
};

static const char _idx_empty_str[] = "";

struct index_mm {
	void *mm;
	uint32_t root_offset;
	size_t size;
};

struct index_mm_value {
	unsigned int priority;
	unsigned int len;
	const char *value;
};

struct index_mm_value_array {
	struct index_mm_value *values;
	unsigned int len;
};

struct index_mm_node {
	struct index_mm *idx;
	const char *prefix; /* mmape'd value */
	struct index_mm_value_array values;
	unsigned char first;
	unsigned char last;
	uint32_t children[];
};

#define BUF_STEP 128

/*
 * Buffer abstract data type
 */
struct strbuf {
	char *bytes;
	unsigned size;
	unsigned used;
};

static void write_safe(int fd, const void *buf, size_t count)
{
	int rc;

	do {
		rc = write(fd, buf, count);
	} while(rc == -1 && errno == EINTR);

	if (rc == -1)
		log_warn("write: %m\n");
}

static int buf_grow(struct strbuf *buf, size_t newsize)
{
	void *tmp;
	size_t sz;

	if (newsize <= buf->size)
		return 1;

	if (newsize % BUF_STEP == 0)
		sz = newsize;
	else
		sz = ((newsize / BUF_STEP) + 1) * BUF_STEP;

	tmp = realloc(buf->bytes, sz);
	if (sz > 0 && tmp == NULL)
		return 0;
	buf->bytes = tmp;
	buf->size = sz;
	return 1;
}

void strbuf_init(struct strbuf *buf)
{
	buf->bytes = NULL;
	buf->size = 0;
	buf->used = 0;
}

void strbuf_release(struct strbuf *buf)
{
	free(buf->bytes);
}

char *strbuf_steal(struct strbuf *buf)
{
	char *bytes;

	bytes = realloc(buf->bytes, buf->used + 1);
	if (!bytes) {
		free(buf->bytes);
		return NULL;
	}
	bytes[buf->used] = '\0';
	return bytes;
}

const char *strbuf_str(struct strbuf *buf)
{
	if (!buf_grow(buf, buf->used + 1))
		return NULL;
	buf->bytes[buf->used] = '\0';
	return buf->bytes;
}

int strbuf_pushchar(struct strbuf *buf, char ch)
{
	if (!buf_grow(buf, buf->used + 1))
		return 0;
	buf->bytes[buf->used] = ch;
	buf->used++;
	return 1;
}

unsigned strbuf_pushchars(struct strbuf *buf, const char *str)
{
	unsigned int len;

	assert(str != NULL);
	assert(buf != NULL);

	len = strlen(str);

	if (!buf_grow(buf, buf->used + len))
		return 0;

	memcpy(buf->bytes + buf->used, str, len);
	buf->used += len;

	return len;
}

void strbuf_popchar(struct strbuf *buf)
{
	assert(buf->used > 0);
	buf->used--;
}

void strbuf_popchars(struct strbuf *buf, unsigned n)
{
	assert(buf->used >= n);
	buf->used -= n;
}

void strbuf_clear(struct strbuf *buf)
{
	buf->used = 0;
}

#define get_unaligned(ptr)			\
({						\
	struct __attribute__((packed)) {	\
		typeof(*(ptr)) __v;		\
	} *__p = (typeof(__p)) (ptr);		\
	__p->__v;				\
})

static inline uint32_t read_long_mm(void **p)
{
	uint8_t *addr = *(uint8_t **)p;
	uint32_t v;

	/* addr may be unalined to uint32_t */
	v = get_unaligned((uint32_t *) addr);

	*p = addr + sizeof(uint32_t);
	return ntohl(v);
}

static inline uint8_t read_char_mm(void **p)
{
	uint8_t *addr = *(uint8_t **)p;
	uint8_t v = *addr;
	*p = addr + sizeof(uint8_t);
	return v;
}

static inline char *read_chars_mm(void **p, unsigned *rlen)
{
	char *addr = *(char **)p;
	size_t len = *rlen = strlen(addr);
	*p = addr + len + 1;
	return addr;
}

static struct index_mm_node *index_mm_read_node(struct index_mm *idx,
							uint32_t offset) {
	void *p = idx->mm;
	struct index_mm_node *node;
	const char *prefix;
	int i, child_count, value_count, children_padding;
	uint32_t children[INDEX_CHILDMAX];
	char first, last;

	if ((offset & INDEX_NODE_MASK) == 0)
		return NULL;

	p = (char *)p + (offset & INDEX_NODE_MASK);

	if (offset & INDEX_NODE_PREFIX) {
		unsigned len;
		prefix = read_chars_mm(&p, &len);
	} else
		prefix = _idx_empty_str;

	if (offset & INDEX_NODE_CHILDS) {
		first = read_char_mm(&p);
		last = read_char_mm(&p);
		child_count = last - first + 1;
		for (i = 0; i < child_count; i++)
			children[i] = read_long_mm(&p);
	} else {
		first = INDEX_CHILDMAX;
		last = 0;
		child_count = 0;
	}

	children_padding = (sizeof(struct index_mm_node) +
			    (sizeof(uint32_t) * child_count)) % sizeof(void *);

	if (offset & INDEX_NODE_VALUES)
		value_count = read_long_mm(&p);
	else
		value_count = 0;

	node = malloc(sizeof(struct index_mm_node)
		      + sizeof(uint32_t) * child_count + children_padding
		      + sizeof(struct index_mm_value) * value_count);
	if (node == NULL)
		return NULL;

	node->idx = idx;
	node->prefix = prefix;
	if (value_count == 0)
		node->values.values = NULL;
	else {
		node->values.values = (struct index_mm_value *)
			((char *)node + sizeof(struct index_mm_node) +
			 sizeof(uint32_t) * child_count + children_padding);
	}
	node->values.len = value_count;
	node->first = first;
	node->last = last;
	memcpy(node->children, children, sizeof(uint32_t) * child_count);

	for (i = 0; i < value_count; i++) {
		struct index_mm_value *v = node->values.values + i;
		v->priority = read_long_mm(&p);
		v->value = read_chars_mm(&p, &v->len);
	}

	return node;
}

static void index_mm_free_node(struct index_mm_node *node)
{
	free(node);
}

int index_mm_open(const char *filename, struct index_mm **pidx)
{
	int fd, err;
	struct stat st;
	struct index_mm *idx;
	struct {
		uint32_t magic;
		uint32_t version;
		uint32_t root_offset;
	} hdr;
	void *p;

	assert(pidx != NULL);

	log_debug("file=%s\n", filename);

	idx = malloc(sizeof(*idx));
	if (idx == NULL) {
		log_error("malloc: %m\n");
		return -ENOMEM;
	}

	if ((fd = open(filename, O_RDONLY|O_CLOEXEC)) < 0) {
		log_error("open(%s, O_RDONLY|O_CLOEXEC): %m\n", filename);
		err = -errno;
		goto fail_open;
	}

	if (fstat(fd, &st) < 0 || (size_t) st.st_size < sizeof(hdr)) {
		err = -EINVAL;
		goto fail_nommap;
	}

	idx->mm = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (idx->mm == MAP_FAILED) {
		log_error("mmap(NULL, %lu, PROT_READ, %d, MAP_PRIVATE, 0): %m\n",
							st.st_size, fd);
		err = -errno;
		goto fail_nommap;
	}

	p = idx->mm;
	hdr.magic = read_long_mm(&p);
	hdr.version = read_long_mm(&p);
	hdr.root_offset = read_long_mm(&p);

	if (hdr.magic != INDEX_MAGIC) {
		log_error("magic check fail: %x instead of %x\n", hdr.magic,
								INDEX_MAGIC);
		err = -EINVAL;
		goto fail;
	}

	if (hdr.version >> 16 != INDEX_VERSION_MAJOR) {
		log_error("major version check fail: %u instead of %u\n",
					hdr.version >> 16, INDEX_VERSION_MAJOR);
		err = -EINVAL;
		goto fail;
	}

	idx->root_offset = hdr.root_offset;
	idx->size = st.st_size;
	close(fd);

	*pidx = idx;

	return 0;

fail:
	munmap(idx->mm, st.st_size);
fail_nommap:
	close(fd);
fail_open:
	free(idx);
	return err;
}

void index_mm_close(struct index_mm *idx)
{
	munmap(idx->mm, idx->size);
	free(idx);
}

static struct index_mm_node *index_mm_readroot(struct index_mm *idx)
{
	return index_mm_read_node(idx, idx->root_offset);
}

static struct index_mm_node *index_mm_readchild(const struct index_mm_node *parent,
									int ch)
{
	if (parent->first <= ch && ch <= parent->last) {
		return index_mm_read_node(parent->idx,
					parent->children[ch - parent->first]);
	}

	return NULL;
}

static void index_mm_dump_node(struct index_mm_node *node, struct strbuf *buf,
								int fd)
{
	struct index_mm_value *itr, *itr_end;
	int ch, pushed;

	pushed = strbuf_pushchars(buf, node->prefix);

	itr = node->values.values;
	itr_end = itr + node->values.len;
	for (; itr < itr_end; itr++) {
		write_safe(fd, buf->bytes, buf->used);
		write_safe(fd, " ", 1);
		write_safe(fd, itr->value, itr->len);
		write_safe(fd, "\n", 1);
	}

	for (ch = node->first; ch <= node->last; ch++) {
		struct index_mm_node *child = index_mm_readchild(node, ch);

		if (child == NULL)
			continue;

		strbuf_pushchar(buf, ch);
		index_mm_dump_node(child, buf, fd);
		strbuf_popchar(buf);
	}

	strbuf_popchars(buf, pushed);
	index_mm_free_node(node);
}

void index_mm_dump(struct index_mm *idx, int fd, const char *prefix)
{
	struct index_mm_node *root;
	struct strbuf buf;

	root = index_mm_readroot(idx);
	if (root == NULL)
		return;

	strbuf_init(&buf);
	strbuf_pushchars(&buf, prefix);
	index_mm_dump_node(root, &buf, fd);
	strbuf_release(&buf);
}

static char *index_mm_search_node(struct index_mm_node *node, const char *key,
									int i)
{
	char *value;
	struct index_mm_node *child;
	int ch;
	int j;

	while(node) {
		for (j = 0; node->prefix[j]; j++) {
			ch = node->prefix[j];

			if (ch != key[i+j]) {
				index_mm_free_node(node);
				return NULL;
			}
		}

		i += j;

		if (key[i] == '\0') {
			value = node->values.len > 0
				? strdup(node->values.values[0].value)
				: NULL;

			index_mm_free_node(node);
			return value;
		}

		child = index_mm_readchild(node, key[i]);
		index_mm_free_node(node);
		node = child;
		i++;
	}

	return NULL;
}

/*
 * Search the index for a key
 *
 * Returns the value of the first match
 *
 * The recursive functions free their node argument (using index_close).
 */
char *index_mm_search(struct index_mm *idx, const char *key)
{
// FIXME: return value by reference instead of strdup
	struct index_mm_node *root;
	char *value;

	root = index_mm_readroot(idx);
	value = index_mm_search_node(root, key, 0);

	return value;
}

static int add_value(struct index_value **values,
		     const char *value, unsigned len, unsigned int priority)
{
	struct index_value *v;

	/* find position to insert value */
	while (*values && (*values)->priority < priority)
		values = &(*values)->next;

	v = malloc(sizeof(struct index_value) + len + 1);
	if (!v)
		return -1;
	v->next = *values;
	v->priority = priority;
	v->len = len;
	memcpy(v->value, value, len);
	v->value[len] = '\0';
	*values = v;

	return 0;
}

/* Level 4: add all the values from a matching node */
static void index_mm_searchwild_allvalues(struct index_mm_node *node,
						struct index_value **out)
{
	struct index_mm_value *itr, *itr_end;

	itr = node->values.values;
	itr_end = itr + node->values.len;
	for (; itr < itr_end; itr++)
		add_value(out, itr->value, itr->len, itr->priority);

	index_mm_free_node(node);
}

/*
 * Level 3: traverse a sub-keyspace which starts with a wildcard,
 * looking for matches.
 */
static void index_mm_searchwild_all(struct index_mm_node *node, int j,
					  struct strbuf *buf,
					  const char *subkey,
					  struct index_value **out)
{
	int pushed = 0;
	int ch;

	while (node->prefix[j]) {
		ch = node->prefix[j];

		strbuf_pushchar(buf, ch);
		pushed++;
		j++;
	}

	for (ch = node->first; ch <= node->last; ch++) {
		struct index_mm_node *child = index_mm_readchild(node, ch);

		if (!child)
			continue;

		strbuf_pushchar(buf, ch);
		index_mm_searchwild_all(child, 0, buf, subkey, out);
		strbuf_popchar(buf);
	}

	if (node->values.len > 0) {
		if (fnmatch(strbuf_str(buf), subkey, 0) == 0)
			index_mm_searchwild_allvalues(node, out);
		else
			index_mm_free_node(node);
	} else {
		index_mm_free_node(node);
	}

	strbuf_popchars(buf, pushed);
}

/* Level 2: descend the tree (until we hit a wildcard) */
static void index_mm_searchwild_node(struct index_mm_node *node,
					   struct strbuf *buf,
					   const char *key, int i,
					   struct index_value **out)
{
	struct index_mm_node *child;
	int j;
	int ch;

	while(node) {
		for (j = 0; node->prefix[j]; j++) {
			ch = node->prefix[j];

			if (ch == '*' || ch == '?' || ch == '[') {
				index_mm_searchwild_all(node, j, buf,
						      &key[i+j], out);
				return;
			}

			if (ch != key[i+j]) {
				index_mm_free_node(node);
				return;
			}
		}

		i += j;

		child = index_mm_readchild(node, '*');
		if (child) {
			strbuf_pushchar(buf, '*');
			index_mm_searchwild_all(child, 0, buf, &key[i], out);
			strbuf_popchar(buf);
		}

		child = index_mm_readchild(node, '?');
		if (child) {
			strbuf_pushchar(buf, '?');
			index_mm_searchwild_all(child, 0, buf, &key[i], out);
			strbuf_popchar(buf);
		}

		child = index_mm_readchild(node, '[');
		if (child) {
			strbuf_pushchar(buf, '[');
			index_mm_searchwild_all(child, 0, buf, &key[i], out);
			strbuf_popchar(buf);
		}

		if (key[i] == '\0') {
			index_mm_searchwild_allvalues(node, out);

			return;
		}

		child = index_mm_readchild(node, key[i]);
		index_mm_free_node(node);
		node = child;
		i++;
	}
}

/*
 * Search the index for a key.  The index may contain wildcards.
 *
 * Returns a list of all the values of matching keys.
 */
struct index_value *index_mm_searchwild(struct index_mm *idx, const char *key)
{
	struct index_mm_node *root = index_mm_readroot(idx);
	struct strbuf buf;
	struct index_value *out = NULL;

	strbuf_init(&buf);
	index_mm_searchwild_node(root, &buf, key, 0, &out);
	strbuf_release(&buf);
	return out;
}

static char *str_buf;
static int str_len;

static void index_mm_all_iter(struct index_mm_node *node,
			      struct strbuf *buf, struct index_value **list)
{
	struct index_value *entry;
	struct index_mm_value *itr, *itr_end;
	int ch, pushed;

	pushed = strbuf_pushchars(buf, node->prefix);

	itr = node->values.values;
	itr_end = itr + node->values.len;
	for (; itr < itr_end; itr++) {
		int len = buf->used + itr->len + 2;
		char *tmp = str_buf;
		if (len > str_len) {
			tmp = realloc(str_buf, len);
			if (!tmp)
				return;
			str_buf = tmp;
			str_len = len;
		}
		tmp = strncpy(tmp, buf->bytes, buf->used) + buf->used;
		*tmp++ = ' ';
		tmp = strncpy(tmp, itr->value, itr->len) + itr->len;
		*tmp++ = '\0';
		add_value(list, str_buf, len, itr->priority);
	}

	for (ch = node->first; ch <= node->last; ch++) {
		struct index_mm_node *child = index_mm_readchild(node, ch);

		if (child == NULL)
			continue;

		strbuf_pushchar(buf, ch);
		index_mm_all_iter(child, buf, list);
		strbuf_popchar(buf);
	}

	strbuf_popchars(buf, pushed);
	index_mm_free_node(node);
}

struct index_value *index_mm_all(struct index_mm *idx)
{
	struct index_value *item = NULL;
	struct index_mm_node *root;
	struct strbuf buf;

	root = index_mm_readroot(idx);
	if (root == NULL)
		return NULL;

	strbuf_init(&buf);
	index_mm_all_iter(root, &buf, &item);
	strbuf_release(&buf);

	return item;
}

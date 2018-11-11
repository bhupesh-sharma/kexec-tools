#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>

#include "kexec.h"
#include "dt-ops.h"

#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#define PALIGN(p, a)	((void *)(ALIGN((unsigned long)(p), (a))))
#define GET_CELL(p)	(p += 4, *((const uint32_t *)(p - 4)))

static const char n_chosen[] = "/chosen";

static const char p_bootargs[] = "bootargs";
static const char p_initrd_start[] = "linux,initrd-start";
static const char p_initrd_end[] = "linux,initrd-end";

int dtb_set_initrd(char **dtb, off_t *dtb_size, off_t start, off_t end)
{
	int result;
	uint64_t value;

	dbgprintf("%s: start %jd, end %jd, size %jd (%jd KiB)\n",
		__func__, (intmax_t)start, (intmax_t)end,
		(intmax_t)(end - start),
		(intmax_t)(end - start) / 1024);

	value = cpu_to_fdt64(start);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_start,
		&value, sizeof(value));

	if (result)
		return result;

	value = cpu_to_fdt64(end);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_end,
		&value, sizeof(value));

	if (result) {
		dtb_delete_property(*dtb, n_chosen, p_initrd_start);
		return result;
	}

	return 0;
}

int dtb_set_bootargs(char **dtb, off_t *dtb_size, const char *command_line)
{
	return dtb_set_property(dtb, dtb_size, n_chosen, p_bootargs,
		command_line, strlen(command_line) + 1);
}

int dtb_set_property(char **dtb, off_t *dtb_size, const char *node,
	const char *prop, const void *value, int value_len)
{
	int result;
	int nodeoffset;
	void *new_dtb;
	int new_size;

	value_len = FDT_TAGALIGN(value_len);

	new_size = FDT_TAGALIGN(*dtb_size + fdt_node_len(node)
		+ fdt_prop_len(prop, value_len));

	new_dtb = malloc(new_size);

	if (!new_dtb) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	result = fdt_open_into(*dtb, new_dtb, new_size);

	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	nodeoffset = fdt_path_offset(new_dtb, node);
	
	if (nodeoffset == -FDT_ERR_NOTFOUND) {
		result = fdt_add_subnode(new_dtb, nodeoffset, node);

		if (result < 0) {
			dbgprintf("%s: fdt_add_subnode failed: %s\n", __func__,
				fdt_strerror(result));
			goto on_error;
		}
	} else if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		goto on_error;
	}

	result = fdt_setprop(new_dtb, nodeoffset, prop, value, value_len);

	if (result) {
		dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	/*
	 * Can't call free on dtb since dtb may have been mmaped by
	 * slurp_file().
	 */

	result = fdt_pack(new_dtb);

	if (result)
		dbgprintf("%s: Unable to pack device tree: %s\n", __func__,
			fdt_strerror(result));

	*dtb = new_dtb;
	*dtb_size = fdt_totalsize(*dtb);

	return 0;

on_error:
	free(new_dtb);
	return result;
}

int dtb_delete_property(char *dtb, const char *node, const char *prop)
{
	int result;
	int nodeoffset = fdt_path_offset(dtb, node);

	if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		return nodeoffset;
	}

	result = fdt_delprop(dtb, nodeoffset, prop);

	if (result)
		dbgprintf("%s: fdt_delprop failed: %s\n", __func__,
			fdt_strerror(nodeoffset));

	return result;
}

static uint64_t is_printable_string(const void* data, uint64_t len)
{
	const char *s = data;
	const char *ss;

	/* Check for zero length strings */
	if (len == 0)
		return 0;

	/* String must be terminated with a '\0' */
	if (s[len - 1] != '\0')
		return 0;

	ss = s;
	while (*s)
		s++;

	/* Traverse till we hit a '\0' or reach 'len' */
	if (*s != '\0')
		return 0;

	if ((s + 1 - ss) < len) {
		/* Handle special cases such as 'bootargs' properties
		 * in dtb which are actually strings, but they may have
		 * a format where (s + 1 - ss) < len remains true.
		 *
		 * We can catch such cases by checking if (s + 1 - ss)
		 * is greater than 1
		 */
		if ((s + 1 - ss) > 1)
			return 1;

		return 0;
	}

	return 1;
}

static void print_data(const char* data, uint64_t len)
{
	uint64_t i;
	const char *p_data = data;

	/* Check for non-zero length */
	if (len == 0)
		return;

	if (is_printable_string(data, len)) {
		dbgprintf(" = \"%s\"", (const char *)data);
	} else if ((len % 4) == 0) {
		dbgprintf(" = <");
		for (i = 0; i < len; i += 4) {
			dbgprintf("0x%08x%s",
					fdt32_to_cpu(GET_CELL(p_data)),
					i < (len - 4) ? " " : "");
		}
		dbgprintf(">");
	} else {
		dbgprintf(" = [");
		for (i = 0; i < len; i++)
			dbgprintf("%02x%s", *p_data++,
					i < len - 1 ? " " : "");
		dbgprintf("]");
	}
}

void dump_fdt(void* fdt)
{
	struct fdt_header *bph;
	const char* p_struct;
	const char* p_strings;
	const char* p_data;
	const char* s_data;
	uint32_t off_dt;
	uint32_t off_str;
	uint32_t tag;
	uint64_t sz;
	uint64_t depth;
	uint64_t shift;
	uint32_t version;

	depth = 0;
	shift = 4;

	bph = fdt;
	off_dt = fdt32_to_cpu(bph->off_dt_struct);
	off_str = fdt32_to_cpu(bph->off_dt_strings);
	p_struct = (const char*)fdt + off_dt;
	p_strings = (const char*)fdt + off_str;
	version = fdt32_to_cpu(bph->version);

	p_data = p_struct;
	while ((tag = fdt32_to_cpu(GET_CELL(p_data))) != FDT_END) {
		if (tag == FDT_BEGIN_NODE) {
			s_data = p_data;
			p_data = PALIGN(p_data + strlen(s_data) + 1, 4);

			if (*s_data == '\0')
				s_data = "/";

			dbgprintf("%*s%s {\n", (int)(depth * shift), " ", s_data);

			depth++;
			continue;
		}

		if (tag == FDT_END_NODE) {
			depth--;

			dbgprintf("%*s};\n", (int)(depth * shift), " ");
			continue;
		}

		if (tag == FDT_NOP) {
			dbgprintf("%*s// [NOP]\n", (int)(depth * shift), " ");
			continue;
		}

		if (tag != FDT_PROP) {
			dbgprintf("%*s ** Unknown tag 0x%08x\n",
					(int)(depth * shift), " ", tag);
			break;
		}

		sz = fdt32_to_cpu(GET_CELL(p_data));
		s_data = p_strings + fdt32_to_cpu(GET_CELL(p_data));
		if (version < 16 && sz >= 8)
			p_data = PALIGN(p_data, 8);

		dbgprintf("%*s%s", (int)(depth * shift), " ", s_data);
		print_data(p_data, sz);
		dbgprintf(";\n");

		p_data = PALIGN(p_data + sz, 4);
	}
}

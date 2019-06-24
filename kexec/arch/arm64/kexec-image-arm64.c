/*
 * ARM64 kexec binary image support.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "crashdump-arm64.h"
#include "image-header.h"
#include "kexec.h"
#include "kexec-arm64.h"
#include "kexec-syscall.h"
#include "arch/options.h"

int image_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	const struct arm64_image_header *h;

	dbgprintf("%s: Bhupesh is here.\n", __func__);
	if (kernel_size < sizeof(struct arm64_image_header)) {
		dbgprintf("%s: No arm64 image header.\n", __func__);
		return -1;
	}

	h = (const struct arm64_image_header *)(kernel_buf);

	if (!arm64_header_check_magic(h)) {
		dbgprintf("%s: Bad arm64 image header.\n", __func__);
		return -1;
	}
	
	dbgprintf("%s: Bhupesh is here return 0.\n", __func__);

	return 0;
}

int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, struct kexec_info *info)
{
	const struct arm64_image_header *header;
	unsigned long kernel_segment;
	int result;

	dbgprintf("%s: Bhupesh is here 0.\n", __func__);
	if (info->file_mode) {
		if (arm64_opts.initrd) {
			info->initrd_fd = open(arm64_opts.initrd, O_RDONLY);
			if (info->initrd_fd == -1) {
				fprintf(stderr,
					"Could not open initrd file %s:%s\n",
					arm64_opts.initrd, strerror(errno));
				result = EFAILED;
				goto exit;
			}
		}

		dbgprintf("%s: Bhupesh is here 1.\n", __func__);
		if (arm64_opts.command_line) {
			info->command_line = (char *)arm64_opts.command_line;
			info->command_line_len =
					strlen(arm64_opts.command_line) + 1;
		}
		
		dbgprintf("%s: Bhupesh is here 2 return 0.\n", __func__);

		return 0;
	}

	header = (const struct arm64_image_header *)(kernel_buf);

	if (arm64_process_image_header(header))
		return EFAILED;

        kernel_segment = arm64_locate_kernel_segment(info);

        if (kernel_segment == ULONG_MAX) {
                dbgprintf("%s: Kernel segment is not allocated\n", __func__);
		result = EFAILED;
                goto exit;
        }

	dbgprintf("%s: kernel_segment: %016lx\n", __func__, kernel_segment);
	dbgprintf("%s: text_offset:    %016lx\n", __func__,
		arm64_mem.text_offset);
	dbgprintf("%s: image_size:     %016lx\n", __func__,
		arm64_mem.image_size);
	dbgprintf("%s: phys_offset:    %016lx\n", __func__,
		arm64_mem.phys_offset);
	dbgprintf("%s: vp_offset:      %016lx\n", __func__,
		arm64_mem.vp_offset);
	dbgprintf("%s: PE format:      %s\n", __func__,
		(arm64_header_check_pe_sig(header) ? "yes" : "no"));

	/* create and initialize elf core header segment */
	if (info->kexec_flags & KEXEC_ON_CRASH) {
		result = load_crashdump_segments(info);
		if (result) {
			dbgprintf("%s: Creating eflcorehdr failed.\n",
								__func__);
			goto exit;
		}
	}

	/* load the kernel */
	add_segment_phys_virt(info, kernel_buf, kernel_size,
			kernel_segment + arm64_mem.text_offset,
			arm64_mem.image_size, 0);

	/* load additional data */
	result = arm64_load_other_segments(info, kernel_segment
		+ arm64_mem.text_offset);

exit:
        if (result)
                fprintf(stderr, "kexec: load failed.\n");
        return result;
}

void image_arm64_usage(void)
{
	printf(
"     An ARM64 binary image, compressed or not, big or little endian.\n"
"     Typically an Image, Image.gz or Image.lzma file.\n\n");
}

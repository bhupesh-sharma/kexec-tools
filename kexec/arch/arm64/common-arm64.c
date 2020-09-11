/*
 * ARM64 common parts for kexec and crash.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libfdt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <elf_info.h>

#include <unistd.h>
#include <syscall.h>
#include <errno.h>
#include <asm/hwcap.h>
#include <sys/auxv.h>

#include "kexec.h"
#include "kexec-arm64.h"
#include "common-arm64.h"

#define PAGE_OFFSET_36 ((0xffffffffffffffffUL) << 36)
#define PAGE_OFFSET_39 ((0xffffffffffffffffUL) << 39)
#define PAGE_OFFSET_42 ((0xffffffffffffffffUL) << 42)
#define PAGE_OFFSET_47 ((0xffffffffffffffffUL) << 47)
#define PAGE_OFFSET_48 ((0xffffffffffffffffUL) << 48)

#define SZ_64K			65536

/* ID_AA64MMFR2_EL1 related helpers: */
#define ID_AA64MMFR2_LVA_SHIFT	16
#define ID_AA64MMFR2_LVA_MASK	(0xf << ID_AA64MMFR2_LVA_SHIFT)

/* CPU feature ID registers */
#define get_cpu_ftr(id) ({							\
		unsigned long __val;						\
		asm volatile("mrs %0, " __stringify(id) : "=r" (__val));	\
		__val;								\
})

/* Machine specific details. */
static int va_bits;

/* Global flag which indicates that we have tried reading
 * TCR_EL1_T1SZ from 'kcore' already.
 */
static bool try_read_tcr_el1_t1sz_from_kcore = false;

/**
 * get_va_bits - Helper for getting VA_BITS
 */

static int get_va_bits(void)
{
	unsigned long long stext_sym_addr = get_kernel_sym("_stext");

	if (stext_sym_addr == 0) {
		fprintf(stderr, "Can't get the symbol of _stext.\n");
		return -1;
	}

	/* Derive va_bits as per arch/arm64/Kconfig. Note that this is a
	 * best case approximation at the moment, as there can be
	 * inconsistencies in this calculation (for e.g., for
	 * 52-bit kernel VA case, the 48th bit is set in
	 * the _stext symbol).
	 *
	 * So, we need to read an architecture system register for a
	 * accurate value of the virtual addressing supported by
	 * the underlying kernel.
	 */
	if ((stext_sym_addr & PAGE_OFFSET_48) == PAGE_OFFSET_48) {
		va_bits = 48;
	} else if ((stext_sym_addr & PAGE_OFFSET_47) == PAGE_OFFSET_47) {
		va_bits = 47;
	} else if ((stext_sym_addr & PAGE_OFFSET_42) == PAGE_OFFSET_42) {
		va_bits = 42;
	} else if ((stext_sym_addr & PAGE_OFFSET_39) == PAGE_OFFSET_39) {
		va_bits = 39;
	} else if ((stext_sym_addr & PAGE_OFFSET_36) == PAGE_OFFSET_36) {
		va_bits = 36;
	} else {
		fprintf(stderr,
			"Cannot find a proper _stext for calculating VA_BITS\n");
		return -1;
	}

	dbgprintf("va_bits : %d\n", va_bits);

	return 0;
}

/** Note that its important to note that the
 * ID_AA64MMFR2_EL1 architecture register can be read
 * only when we give an .arch hint to the gcc/binutils,
 * so we use the gcc construct '__attribute__ ((target ("arch=armv8.2-a")))'
 * here which is an .arch directive (see AArch64-Target-selection-directives
 * documentation from ARM for details). This is required only for
 * this function to make sure it compiles well with gcc/binutils.
 */

__attribute__ ((target ("arch=armv8.2-a")))
static unsigned long read_id_aa64mmfr2_el1(void)
{
	return get_cpu_ftr(ID_AA64MMFR2_EL1);
}

static int get_vabits_actual_from_id_aa64mmfr2_el1(void)
{
	int l_vabits_actual;
	unsigned long val;

	/* Check if ID_AA64MMFR2_EL1 CPU-ID register indicates
	 * ARMv8.2/LVA support:
	 * VARange, bits [19:16]
	 *   From ARMv8.2:
	 *   Indicates support for a larger virtual address.
	 *   Defined values are:
	 *     0b0000 VMSAv8-64 supports 48-bit VAs.
	 *     0b0001 VMSAv8-64 supports 52-bit VAs when using the 64KB
	 *            page size. The other translation granules support
	 *            48-bit VAs.
	 *
	 * See ARMv8 ARM for more details.
	 */
	if (!(getauxval(AT_HWCAP) & HWCAP_CPUID)) {
		fprintf(stderr, "arm64 CPUID registers unavailable.\n");
		return EFAILED;
	}

	val = read_id_aa64mmfr2_el1();
	val = (val & ID_AA64MMFR2_LVA_MASK) > ID_AA64MMFR2_LVA_SHIFT;

	if ((val == 0x1) && (getpagesize() == SZ_64K))
		l_vabits_actual = 52;
	else
		l_vabits_actual = 48;

	return l_vabits_actual;
}

/**
 * get_vabits_actual - Helper for getting vabits_actual
 */

static void get_vabits_actual(int *vabits_actual)
{
	int l_vabits_actual;

	/* Try to read ID_AA64MMFR2_EL1 CPU-ID register,
	 * to calculate the vabits_actual.
	 */
	l_vabits_actual = get_vabits_actual_from_id_aa64mmfr2_el1();
	if ((l_vabits_actual == EFAILED) || (l_vabits_actual != 52)) {
		/* If we cannot read ID_AA64MMFR2_EL1 arch
		 * register or if this register does not indicate
		 * support for a larger virtual address, our last
		 * option is to use the VA_BITS to calculate the
		 * PAGE_OFFSET value, i.e. vabits_actual = VA_BITS.
		 */
		l_vabits_actual = va_bits;
		dbgprintf("vabits_actual : %d (approximation via va_bits)\n",
				l_vabits_actual);
	} else
		dbgprintf("vabits_actual : %d (via id_aa64mmfr2_el1)\n",
				l_vabits_actual);

	*vabits_actual = l_vabits_actual;
}

/**
 * get_tcr_el1_t1sz_from_vmcoreinfo_pt_note - Helper for getting TCR_EL1_T1SZ
 * from VMCOREINFO note inside 'kcore'.
 */

int get_tcr_el1_t1sz_from_vmcoreinfo_pt_note(unsigned long *tcr_t1sz)
{
	int fd, ret = 0;

	if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
		fprintf(stderr, "Can't open (%s).\n", "/proc/kcore");
		return EFAILED;
	}

	ret = read_tcr_el1_t1sz_elf_kcore(fd, tcr_t1sz);

	close(fd);
	return ret;
}

/**
 * get_page_offset_helper - Helper for getting PAGE_OFFSET
 */

static int get_page_offset_helper(unsigned long *page_offset)
{
	int ret;
	int vabits_actual = INT_MAX;
	unsigned long tcr_t1sz = UINT64_MAX;

	if (!try_read_tcr_el1_t1sz_from_kcore) {
		/* Since kernel version 5.5.0, 'kcore' contains
		 * a new PT_NOTE which carries the VMCOREINFO
		 * information.
		 * If the same is available, one should prefer the
		 * same to retrieve 'TCR_EL1_T1SZ' value exported by
		 * the kernel as this is now the standard interface
		 * exposed by kernel for sharing machine specific
		 * details with the userland.
		 */
		ret = get_tcr_el1_t1sz_from_vmcoreinfo_pt_note(&tcr_t1sz);
		if (!ret) {
			if (tcr_t1sz != UINT64_MAX) {
				vabits_actual = 64 - tcr_t1sz;
				dbgprintf("vabits_actual : %d (via vmcore)\n",
						vabits_actual);
			}
		}

		try_read_tcr_el1_t1sz_from_kcore = true;
	}

	if (vabits_actual == INT_MAX) {
		/* If we are running on a older kernel,
		 * try to retrieve the 'vabits_actual' value
		 * via other means.
		 */
		ret = get_va_bits();
		if (ret < 0)
			return ret;

		get_vabits_actual(&vabits_actual);
	}

	/* If 'vabits_actual' is still uninitialized,
	 * bail out.
	 */
	if (vabits_actual == INT_MAX)
		return EFAILED;

	/* See arch/arm64/include/asm/memory.h for more details of
	 * the PAGE_OFFSET calculation.
	 */
	if (kernel_version() < KERNEL_VERSION(5, 4, 0))
		*page_offset = ((0xffffffffffffffffUL) -
				((1UL) << (vabits_actual - 1)) + 1);
	else
		*page_offset = (-(1UL << vabits_actual));

	dbgprintf("page_offset : %lx (via vabits_actual)\n", *page_offset);

	return 0;
}

/**
 * get_page_offset - Helper for getting PAGE_OFFSET
 */

int get_page_offset(unsigned long *page_offset)
{
	return get_page_offset_helper(page_offset);
}

/**
 * get_phys_offset_from_vmcoreinfo_pt_note - Helper for getting PHYS_OFFSET
 * from VMCOREINFO note inside 'kcore'.
 */

int get_phys_offset_from_vmcoreinfo_pt_note(unsigned long *phys_offset)
{
	int fd, ret = 0;

	if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
		fprintf(stderr, "Can't open (%s).\n", "/proc/kcore");
		return EFAILED;
	}

	ret = read_phys_offset_elf_kcore(fd, phys_offset);

	close(fd);
	return ret;
}

/**
 * get_phys_base_from_pt_load - Helper for getting PHYS_OFFSET
 * from PT_LOADs inside 'kcore'.
 */

int get_phys_base_from_pt_load(unsigned long *phys_offset)
{
	int i, fd, ret;
	unsigned long page_offset;
	unsigned long long phys_start;
	unsigned long long virt_start;

	ret = get_page_offset(&page_offset);
	if (ret < 0)
		return ret;

	if ((fd = open("/proc/kcore", O_RDONLY)) < 0) {
		fprintf(stderr, "Can't open (%s).\n", "/proc/kcore");
		return EFAILED;
	}

	read_elf(fd);

	/* Note that the following loop starts with i = 1.
	 * This is required to make sure that the following logic
	 * works both for old and newer kernels (with flipped
	 * VA space, i.e. >= 5.4.0)
	 */
	for (i = 1; get_pt_load(i,
		    &phys_start, NULL, &virt_start, NULL);
	 	    i++) {
		if (virt_start != NOT_KV_ADDR
				&& virt_start >= page_offset
				&& phys_start != NOT_PADDR)
			*phys_offset = phys_start -
				(virt_start & ~page_offset);
	}

	close(fd);
	return 0;
}


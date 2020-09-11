#if !defined(COMMON_ARM64_H)
#define COMMON_ARM64_H

int get_page_offset(unsigned long *page_offset);
int get_phys_offset_from_vmcoreinfo_pt_note(unsigned long *phys_offset);
int get_phys_base_from_pt_load(unsigned long *phys_offset);

#endif

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_PKVM_GUEST_RAM_H
#define __LINUX_PKVM_GUEST_RAM_H

#include <linux/types.h>

struct vm_area_struct;

#ifdef CONFIG_PKVM_GUEST_RAM
bool pkvm_guest_ram_is_vma(struct vm_area_struct *vma);
#else
static inline bool pkvm_guest_ram_is_vma(struct vm_area_struct *vma)
{
	return false;
}
#endif

#endif	/* __LINUX_PKVM_GUEST_RAM_H */

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>

#include "arm-smmu-kvm-debugfs.h"

#define TABLE_INDENT "  "
#define tbl_printf(m, fmt, ...) seq_printf(m, TABLE_INDENT fmt, ##__VA_ARGS__)

static int kvm_iommu_debug(pkvm_handle_t drv_id, pkvm_handle_t smmu_id,
	                   enum kvm_iommu_debug_ops op, void *out, size_t out_sz)
{
	struct arm_smccc_res res;

	res = kvm_call_hyp_nvhe_smccc(__pkvm_host_iommu_debug, drv_id, smmu_id, op, out, out_sz);
	return res.a1;
}

static int kvm_smmu_export_dev(pkvm_handle_t hyp_drv_id, pkvm_handle_t smmu_id,
			       struct hyp_arm_smmu_v2_device *smmu)
{
	int ret;

	ret = kvm_share_hyp(smmu, smmu + 1);
	if (ret)
		return ret;

	ret = kvm_iommu_debug(hyp_drv_id, smmu_id, PKVM_IOMMU_DEBUG_EXPORT_DEVICE, smmu,
			      sizeof(*smmu));

	kvm_unshare_hyp(smmu, smmu + 1);
	return ret;
}

static int kvm_smmu_export_state(pkvm_handle_t hyp_drv_id, pkvm_handle_t smmu_id, void *out,
				 size_t out_size)
{
	int ret;

	ret = kvm_share_hyp(out, (u8 *)out + out_size);
	if (ret)
		return ret;

	ret = kvm_iommu_debug(hyp_drv_id, smmu_id, PKVM_IOMMU_DEBUG_EXPORT_STATE, out, out_size);

	kvm_unshare_hyp(out, (u8 *)out + out_size);
	return ret;
}

static void kvm_smmu_dump_cbs(struct seq_file *m, struct hyp_arm_smmu_v2_device *smmu)
{
	int i;
	int cnt_same;

	tbl_printf(m, "    |     cbar |   tcr[0] |   tcr[1] |          ttbr[0] |          ttbr[1] |    sctlr |  mair[0] |  mair[1] | domain_id \n");
	tbl_printf(m, "====|==========|==========|==========|==================|==================|==========|==========|==========|===========\n");

	for (i = 0, cnt_same = 0; i < smmu->num_context_banks; i++) {
		if (i > 0 && memcmp(&smmu->cbs[i], &smmu->cbs[i-1],
				    sizeof(smmu->cbs[i])) == 0) {
			cnt_same++;
			continue;
		} else if (cnt_same) {
			tbl_printf(m, "  : | < repeats %d times >\n", cnt_same);
			cnt_same = 0;
		}

		tbl_printf(m, "%3d |%9x |%9x |%9x |%17llx |%17llx |%9x |%9x |%9x |%10u\n",
			   i,
			   smmu->cbs[i].cbar,
			   smmu->cbs[i].tcr[0],
			   smmu->cbs[i].tcr[1],
			   smmu->cbs[i].ttbr[0],
			   smmu->cbs[i].ttbr[1],
			   smmu->cbs[i].sctlr,
			   smmu->cbs[i].mair[0],
			   smmu->cbs[i].mair[1],
			   smmu->cbs[i].domain_id
			  );
	}

	if (cnt_same)
		tbl_printf(m, "  : | < repeats %d times >\n", cnt_same);
}

static void kvm_smmu_dump_smt(struct seq_file *m, struct smmu_v2_smr *smrs,
			      struct smmu_v2_s2cr *s2crs, u32 num_groups)
{
	int i;
	int cnt_same;

	tbl_printf(m, "    |        SMR          |              S2CR\n");
	tbl_printf(m, "    |------|------|-------|------|-------|---------|-------\n");
	tbl_printf(m, "    | mask |   id | valid | type | cbndx | privcfg | bypass\n");
	tbl_printf(m, "====|======|======|=======|======|=======|=========|=======\n");

	for (i = 0, cnt_same = 0; i < num_groups; i++) {
		if (i > 0 &&
		    memcmp(&smrs[i], &smrs[i-1], sizeof(smrs[i])) == 0 &&
		    memcmp(&s2crs[i], &s2crs[i-1], sizeof(s2crs[i])) == 0) {
			cnt_same++;
			continue;
		} else if (cnt_same) {
			seq_printf(m, "  : | < repeats %d times >\n", cnt_same);
			cnt_same = 0;
		}

		tbl_printf(m, "%3u |%5x |%5x |%6u |%5x |%6u |%8x |%7u\n",
			   i,
			   smrs[i].mask,
			   smrs[i].id,
			   smrs[i].valid,
			   s2crs[i].type,
			   s2crs[i].cbndx,
			   s2crs[i].privcfg,
			   s2crs[i].bypass
			  );
	}

	if (cnt_same)
		tbl_printf(m, "  : | < repeats %d times >\n", cnt_same);
}

static int kvm_smmu_host_device_show(struct seq_file *m, void *unused)
{
	int ret;
	struct dentry *smmu_dentry = m->file->f_path.dentry->d_parent;
	struct dentry *drv_dentry = smmu_dentry->d_parent;
	struct inode *smmu_inode = d_inode(smmu_dentry);
	struct inode *drv_inode = d_inode(drv_dentry);
	pkvm_handle_t hyp_drv_id = (pkvm_handle_t)(uintptr_t)drv_inode->i_private;
	pkvm_handle_t smmu_id = (pkvm_handle_t)(uintptr_t)smmu_inode->i_private;
	struct hyp_arm_smmu_v2_device *smmu;
	size_t smmu_size = sizeof(*smmu);
	int smmu_order = get_order(smmu_size);
	size_t state_size;
	int state_order;
	void *state_pages;
	int i;

	smmu = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, smmu_order);
	if (smmu == NULL) {
		seq_printf(m, "<Out of memory allocating pages for smmu structure>\n");
		return -ENOMEM;
	}

	ret = kvm_smmu_export_dev(hyp_drv_id, smmu_id, smmu);
	if (ret) {
		seq_printf(m, "<Error %d exporting device structure>\n", ret);
		goto exit_with_pages;
	}

	/* Allocate memory for the dynamically allocated state */
	state_size = smmu_shadow_state_size(smmu);
	state_order = get_order(state_size);
	state_pages = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, state_order);
	if (state_pages == NULL) {
		ret = -ENOMEM;
		seq_printf(m, "<Out of memory allocating %d pages for dynamic structures>\n",
			   state_order);
		goto exit_with_pages;
	}

	ret = kvm_smmu_export_state(hyp_drv_id, smmu_id, state_pages, state_size);
	if (ret) {
		seq_printf(m, "<Error %d exporting stream mapping table>\n", ret);
		goto exit_with_pages;
	}

	smmu_shadow_state_from_pages(smmu, state_pages);

	seq_printf(m, "id: %u\n", smmu->id);
	seq_printf(m, "mmio_addr: 0x%llx\n", smmu->mmio_addr);
	seq_printf(m, "base: 0x%px\n", smmu->base);
	seq_printf(m, "mmio_addr_sec: 0x%llx\n", smmu->mmio_addr_sec);
	seq_printf(m, "base_sec: 0x%px\n", smmu->base_sec);
	seq_printf(m, "has_secondary_base: %u\n", smmu->has_secondary_base);
	seq_printf(m, "mmio_size: 0x%lx\n", smmu->mmio_size);
	seq_printf(m, "features: 0x%x\n", smmu->features);
	seq_printf(m, "num_mapping_groups: %u\n", smmu->num_mapping_groups);
	seq_printf(m, "num_context_banks: %u\n", smmu->num_context_banks);
	seq_printf(m, "num_s2_context_banks: %u\n", smmu->num_s2_context_banks);
	seq_printf(m, "numpage: %u\n", smmu->numpage);
	seq_printf(m, "pgshift: %u\n", smmu->pgshift);
	seq_printf(m, "ubs: %u\n", smmu->ubs);
	seq_printf(m, "ias: %u\n", smmu->ias);
	seq_printf(m, "oas: %u\n", smmu->oas);
	seq_printf(m, "sid_bits: %u\n", smmu->sid_bits);
	seq_printf(m, "pgsize_bitmap: %lx\n", smmu->pgsize_bitmap);
	seq_printf(m, "cb_bitmap: %*pbl\n", smmu->num_context_banks, smmu->cb_bitmap);

	seq_printf(m, "cbs:\n");
	kvm_smmu_dump_cbs(m, smmu);

	seq_printf(m, "host_cb_map (host -> actual):\n");
	for (i = 0; i < smmu_num_host_cbs(smmu); i++)
		if (smmu->host_cb_map[i] != ARM_SMMU_INVALID_CB)
			tbl_printf(m, "%u -> %u\n", i, smmu->host_cb_map[i]);

	seq_printf(m, "sme_bitmap: %*pbl\n", smmu->num_mapping_groups, smmu->sme_bitmap);

	seq_printf(m, "Stream mapping table:\n");
	kvm_smmu_dump_smt(m, smmu->smrs, smmu->s2crs, smmu->num_mapping_groups);

	seq_printf(m, "host_sme_map (host -> actual):\n");
	for (i = 0; i < smmu->num_mapping_groups; i++)
		if (smmu->host_sme_map[i] != ARM_SMMU_INVALID_SME)
			tbl_printf(m, "%u -> %u\n", i, smmu->host_sme_map[i]);

exit_with_pages:
	free_pages((unsigned long)state_pages, state_order);
	free_pages((unsigned long)smmu, smmu_order);
	return ret;
}

static int kvm_smmu_host_device_open(struct inode *m, struct file *file)
{
	return single_open(file, kvm_smmu_host_device_show, NULL);
}

static int kvm_smmu_host_device_close(struct inode *m, struct file *file)
{
	return single_release(m, file);
}

static const struct file_operations kvm_smmu_host_device_fops = {
	.open		= kvm_smmu_host_device_open,
	.read		= seq_read,
	.release	= kvm_smmu_host_device_close,
};

void kvm_smmu_host_create_debugfs(pkvm_handle_t hyp_drv_id, struct hyp_arm_smmu_v2_device *smmus,
				  size_t smmu_count)
{
	char dirname[64];
	struct dentry *kvm_debugfs_dir;
	struct dentry *drv_dir;
	struct dentry *smmu_dir;
	int i;

	kvm_debugfs_dir = debugfs_lookup("kvm", NULL);
	if (IS_ERR_OR_NULL(kvm_debugfs_dir))
		return;

	snprintf(dirname, sizeof(dirname), "iommu-drv-%u", hyp_drv_id);
	drv_dir = debugfs_create_dir(dirname, kvm_debugfs_dir);
	if (IS_ERR_OR_NULL(drv_dir))
		return;

	drv_dir->d_inode->i_private = (void *)(uintptr_t)hyp_drv_id;

	for (i = 0; i < smmu_count; i++) {
		snprintf(dirname, sizeof(dirname), "%llx.smmu", smmus[i].mmio_addr);
		smmu_dir = debugfs_create_dir(dirname, drv_dir);
		if (IS_ERR_OR_NULL(drv_dir))
			return;

		smmu_dir->d_inode->i_private = (void *)(uintptr_t)smmus[i].id;

		debugfs_create_file("device", 0400, smmu_dir,  NULL, &kvm_smmu_host_device_fops);
	}
}

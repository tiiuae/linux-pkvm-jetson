obj-$(CONFIG_DWMAC_TEGRA_PKVM) += tegra234-mgbe-pkvm.o
ccflags-$(CONFIG_DWMAC_TEGRA_PKVM) += -Iarch/arm64/kvm/

tegra234-mgbe-pkvm-y := tegra234-mgbe-pkvm-host.o hyp/kvm_nvhe.o

$(obj)/hyp/kvm_nvhe.o: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/hyp $(obj)/hyp/kvm_nvhe.o

clean-files := hyp/hyp.lds hyp/hyp-reloc.S

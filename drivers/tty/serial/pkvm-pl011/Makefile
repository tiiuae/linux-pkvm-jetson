obj-$(CONFIG_SERIAL_PKVM_PL011) += pkvm_pl011.o
ccflags-$(CONFIG_SERIAL_PKVM_PL011) += -Iarch/arm64/kvm/

pkvm_pl011-objs-y += pl011-host.o
pkvm_pl011-objs := $(pkvm_pl011-objs-y)

ifeq ($(CONFIG_SERIAL_PKVM_PL011),m)
$(obj)/hyp/kvm_nvhe.o: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/hyp $(obj)/hyp/kvm_nvhe.o
pkvm_pl011-objs += hyp/kvm_nvhe.o

clean-files := hyp/hyp.lds hyp/hyp-reloc.S
endif

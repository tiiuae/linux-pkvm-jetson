/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM64_KVM_NVHE_SERIAL_H__
#define __ARM64_KVM_NVHE_SERIAL_H__

struct kvm_serial_ops {
        int (*init)(void);
};

/* Basic output functions */
void hyp_puts(const char *s);
void hyp_putx64(u64 x);
void hyp_putc(char c);

/* Enhanced output functions (printf-style support)
 *
 * hyp_printf() supports:
 *   %s   - string
 *   %x   - 32-bit hex
 *   %lx  - 64-bit hex (long)
 *   %llx - 64-bit hex (long long, for phys_addr_t)
 *   %d/%u   - decimal
 *   %ld/%lu - 64-bit decimal (long)
 *   %lld/%llu - 64-bit decimal (long long)
 *   %zu/%zd - size_t/ssize_t (decimal)
 *   %zx  - size_t (hex)
 *   %p   - pointer (hex without prefix)
 *   %c   - character
 *   %%   - literal %
 */
void hyp_dec(u64 val);
void hyp_hex(u64 val);
void hyp_hex32(u32 val);
void hyp_printf(const char *fmt, ...) __printf(1, 2);

/* Driver registration */
int __pkvm_register_serial_driver(void (*driver_cb)(char));

int pkvm_serial_register_ops(struct kvm_serial_ops *ops);

/*
 * Convenience macros for common debug patterns
 */
#define hyp_dbg(fmt, ...) \
	hyp_printf("[hyp-dbg] " fmt "\n", ##__VA_ARGS__)

#define hyp_info(fmt, ...) \
	hyp_printf("[hyp-info] " fmt "\n", ##__VA_ARGS__)

#define hyp_err(fmt, ...) \
	hyp_printf("[hyp-err] " fmt "\n", ##__VA_ARGS__)

#define hyp_warn(fmt, ...) \
	hyp_printf("[hyp-warn] " fmt "\n", ##__VA_ARGS__)

#endif

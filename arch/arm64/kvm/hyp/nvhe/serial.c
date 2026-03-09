// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 */

#include <nvhe/pkvm.h>
#include <nvhe/serial.h>
#include <nvhe/spinlock.h>

static void (*__hyp_putc)(char c);

static inline void __hyp_putx4(unsigned int x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);

	__hyp_putc(x);
}

static inline void __hyp_putx4n(unsigned long x, int n)
{
	int i = n >> 2;

	while (i--)
		__hyp_putx4(x >> (4 * i));

	__hyp_putc('\n');
	__hyp_putc('\r');
}

static inline bool hyp_serial_enabled(void)
{
	/* Paired with __pkvm_register_serial_driver()'s cmpxchg */
	return !!smp_load_acquire(&__hyp_putc);
}

void hyp_puts(const char *s)
{
	if (!hyp_serial_enabled())
		return;

	while (*s)
		__hyp_putc(*s++);

	__hyp_putc('\n');
	__hyp_putc('\r');
}

void hyp_putx64(u64 x)
{
	if (hyp_serial_enabled())
		__hyp_putx4n(x, 64);
}

void hyp_putc(char c)
{
	if (hyp_serial_enabled())
		__hyp_putc(c);
}

int __pkvm_register_serial_driver(void (*cb)(char))
{
	/*
	 * Paired with smp_load_acquire(&__hyp_putc) in
	 * hyp_serial_enabled(). Ensure memory stores hapenning during a pKVM
	 * module init are observed before executing the callback.
	 */
	return cmpxchg_release(&__hyp_putc, NULL, cb) ? -EBUSY : 0;
}

int pkvm_serial_register_ops(struct kvm_serial_ops *ops)
{
	if (!ops || !ops->init)
		return -ENODEV;

	return ops->init();
}

/*
 * Print a 64-bit value in decimal
 */
void hyp_dec(u64 val)
{
	char buf[24];  /* Enough for 2^64-1 = 18446744073709551615 */
	int i = sizeof(buf) - 1;

	if (!hyp_serial_enabled())
		return;

	buf[i] = '\0';

	if (val == 0) {
		__hyp_putc('0');
		return;
	}

	while (val > 0 && i > 0) {
		buf[--i] = '0' + (val % 10);
		val /= 10;
	}

	while (buf[i])
		__hyp_putc(buf[i++]);
}

/*
 * Print a 64-bit value in hexadecimal
 */
void hyp_hex(u64 val)
{
	int i;

	if (!hyp_serial_enabled())
		return;

	for (i = 60; i >= 4 && ((val >> i) & 0xf) == 0; i -= 4);

	for (; i >= 0; i -= 4) {
		u8 digit = (val >> i) & 0xf;
		__hyp_putx4(digit);
	}
}

/*
 * Print a 32-bit value in hexadecimal
 */
void hyp_hex32(u32 val)
{
	int i;

	if (!hyp_serial_enabled())
		return;

	for (i = 28; i >= 4 && ((val >> i) & 0xf) == 0; i -= 4);

	for (; i >= 0; i -= 4) {
		u8 digit = (val >> i) & 0xf;
		__hyp_putx4(digit);
	}
}

/*
 * Printf-like formatted output (simplified, supports limited format specifiers)
 *
 * Supported formats:
 *   %s   - string
 *   %x   - 32-bit hex
 *   %lx  - 64-bit hex (long)
 *   %llx - 64-bit hex (long long, for phys_addr_t)
 *   %d/%u   - decimal
 *   %ld/%lu - 64-bit decimal (long)
 *   %lld/%llu - 64-bit decimal (long long)
 *   %zu/%zd - size_t/ssize_t (decimal)
 *   %zx  - size_t (hex)
 *   %p   - pointer (hex with 0x prefix)
 *   %c   - character
 *   %%   - literal %
 */
void hyp_printf(const char *fmt, ...)
{
	va_list args;
	const char *p;

	if (!hyp_serial_enabled() || !fmt)
		return;

	va_start(args, fmt);

	for (p = fmt; *p; p++) {
		if (*p != '%') {
			if (*p == '\n')
				__hyp_putc('\r');
			__hyp_putc(*p);
			continue;
		}

		/* Format specifier */
		p++;
		switch (*p) {
		case 's': {
			const char *s = va_arg(args, const char *);
			if (s) {
				while (*s)
					__hyp_putc(*s++);
			} else {
				__hyp_putc('(');
				__hyp_putc('n');
				__hyp_putc('u');
				__hyp_putc('l');
				__hyp_putc('l');
				__hyp_putc(')');
			}
			break;
		}
		case 'x': {
			u32 val = va_arg(args, u32);
			hyp_hex32(val);
			break;
		}
		case 'l':
			/* Check for 'll' (long long) or just 'l' (long) */
			if (*(p + 1) == 'l') {
				/* long long (64-bit) */
				p++; /* Skip first 'l' */
				if (*(p + 1) == 'x') {
					u64 val = va_arg(args, u64);
					hyp_hex(val);
					p++; /* Skip the 'x' */
				} else if (*(p + 1) == 'd' || *(p + 1) == 'u') {
					u64 val = va_arg(args, u64);
					hyp_dec(val);
					p++; /* Skip the 'd'/'u' */
				} else {
					__hyp_putc('%');
					__hyp_putc('l');
					__hyp_putc('l');
				}
			} else if (*(p + 1) == 'x') {
				/* long hex - also treat as 64-bit on arm64 */
				u64 val = va_arg(args, u64);
				hyp_hex(val);
				p++; /* Skip the 'x' */
			} else if (*(p + 1) == 'd' || *(p + 1) == 'u') {
				/* long decimal - also treat as 64-bit on arm64 */
				u64 val = va_arg(args, u64);
				hyp_dec(val);
				p++; /* Skip the 'd'/'u' */
			} else {
				__hyp_putc('%');
				__hyp_putc('l');
			}
			break;
		case 'd':
		case 'u': {
			u64 val = va_arg(args, u64);
			hyp_dec(val);
			break;
		}
		case 'c': {
			char c = (char)va_arg(args, int);
			__hyp_putc(c);
			break;
		}
		case 'z':
			/* size_t modifier */
			if (*(p + 1) == 'u' || *(p + 1) == 'd') {
				/* %zu or %zd - size_t is 64-bit on arm64 */
				u64 val = va_arg(args, u64);
				hyp_dec(val);
				p++; /* Skip the 'u'/'d' */
			} else if (*(p + 1) == 'x') {
				/* %zx - size_t in hex */
				u64 val = va_arg(args, u64);
				hyp_hex(val);
				p++; /* Skip the 'x' */
			} else {
				__hyp_putc('%');
				__hyp_putc('z');
			}
			break;
		case 'p': {
			/* Pointer - print as 0x... in hex */
			u64 val = va_arg(args, u64);
			hyp_hex(val);
			break;
		}
		case '%':
			__hyp_putc('%');
			break;
		default:
			__hyp_putc('%');
			__hyp_putc(*p);
			break;
		}
	}

	va_end(args);
}

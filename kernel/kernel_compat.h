#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

// TODO: add keygrab
#define ksu_filp_open_compat filp_open

// TODO: add < 4.14 compat
#define ksu_kernel_read_compat kernel_read
#define ksu_kernel_write_compat kernel_write

#endif

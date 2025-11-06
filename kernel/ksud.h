#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <linux/types.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

void on_post_fs_data(void);

bool ksu_is_safe_mode(void);

extern bool ksu_execveat_hook __read_mostly;
extern int ksu_handle_pre_ksud(const char *filename);
extern int ksu_handle_bprm_ksud(const char *filename, const char *argv1,
				const char *envp, size_t envp_len);

extern u32 ksu_file_sid;

#endif

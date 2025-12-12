#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#include <uapi/asm-generic/errno.h>
#else
#include <asm-generic/errno.h>
#endif


#include "allowlist.h"
#include "apk_sign.h"
#include "app_profile.h"
#include "arch.h"
#include "core_hook.h"
#include "feature.h"
#include "file_wrapper.h"
#include "kernel_compat.h"
#include "klog.h"
#include "ksud.h"
#include "ksu.h"
#include "manager.h"
#include "sucompat.h"
#include "supercalls.h"
#include "throne_tracker.h"
#include "su_mount_ns.h"
#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

// selinux includes
#include <linux/lsm_audit.h>
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

// unity build
#include "tiny_sulog.c"
#include "allowlist.c"
#include "app_profile.c"
#include "apk_sign.c"
#include "sucompat.c"
#include "throne_tracker.c"
#include "core_hook.c"
#include "supercalls.c"
#include "feature.c"
#include "su_mount_ns.c"
#include "ksud.c"
#include "kernel_compat.c"
#include "file_wrapper.c"

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef CONFIG_ARM64
#include "syscall_table_hook.c"
#elif CONFIG_ARM
#include "syscall_table_hook_arm.c"
#endif
#endif

#ifdef CONFIG_KSU_KPROBES_KSUD
#include "kp_ksud.c"
#endif

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
#include "rp_sucompat.c"
#endif

#ifdef CONFIG_KSU_EXTRAS
#include "extras.c"
#endif

struct cred* ksu_cred;

extern void ksu_supercalls_init();

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_cred = prepare_creds();
	if (!ksu_cred) {
		pr_err("prepare cred failed!\n");
	}

	ksu_feature_init();

	ksu_supercalls_init();

	ksu_sucompat_init(); // so the feature is registered

	ksu_core_init();

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	ksu_ksud_init();

	ksu_file_wrapper_init();

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	ksu_syscall_table_hook_init();
#endif

#ifdef CONFIG_KSU_KPROBES_KSUD
	kp_ksud_init();
#endif

#ifdef CONFIG_KSU_EXTRAS
	ksu_avc_spoof_init(); // so the feature is registered
#endif

	return 0;
}

void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_feature_exit();

	if (ksu_cred) {
		put_cred(ksu_cred);
	}
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif


#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */
#include <linux/workqueue.h>

#include "allowlist.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"

#ifdef CONFIG_KSU_KPROBES_KSUD
extern void kp_ksud_init();
#endif

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT
extern void rp_sucompat_init();
#endif 

static struct workqueue_struct *ksu_workqueue;

bool ksu_queue_work(struct work_struct *work)
{
	return queue_work(ksu_workqueue, work);
}

// track backports and other quirks here
// ref: kernel_compat.c, Makefile
// yes looks nasty
#if defined(CONFIG_KSU_KPROBES_KSUD)
	#define FEAT_1 " +kprobes_ksud"
#else
	#define FEAT_1 ""
#endif

#if defined(CONFIG_KSU_KRETPROBES_SUCOMPAT)
	#define FEAT_2 " +kretprobes_sucompat"
#else
	#define FEAT_2 ""
#endif

#if defined(CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED)
	#define FEAT_3 " +throne_always_threaded"
#else
	#define FEAT_3 ""
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && !defined(CONFIG_KSU_LSM_SECURITY_HOOKS)
	#define FEAT_4 " -lsm_hooks"
#else
	#define FEAT_4 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) && defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	#define FEAT_5 " +allowlist_workaround"
#else
	#define FEAT_5 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)) && defined(KSU_HAS_MODERN_EXT4)
	#define FEAT_6 " +ext4_unregister_sysfs"
#else
	#define FEAT_6 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)) && defined(KSU_HAS_PATH_UMOUNT)
	#define FEAT_7 " +path_umount"
#else
	#define FEAT_7 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)) && defined(KSU_COPY_FROM_USER_NOFAULT)
	#define FEAT_8 " +copy_from_user_nofault"
#else
	#define FEAT_8 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)) && defined(KSU_PROBE_USER_READ)
	#define FEAT_9 " +probe_user_read"
#else
	#define FEAT_9 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && defined(KSU_NEW_KERNEL_READ)
	#define FEAT_10 " +new_kernel_read"
#else
	#define FEAT_10 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && defined(KSU_NEW_KERNEL_WRITE)
	#define FEAT_11 " +new_kernel_write"
#else
	#define FEAT_11 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)) && defined(KSU_HAS_SELINUX_INODE)
	#define FEAT_12 " +selinux_inode"
#else
	#define FEAT_12 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)) && defined(KSU_HAS_FOP_READ_ITER)
	#define FEAT_13 " +read_iter"
#else
	#define FEAT_13 ""
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && defined(KSU_HAS_ITERATE_DIR)
	#define FEAT_14 " +iterate_dir"
#else
	#define FEAT_14 ""
#endif

#define EXTRA_FEATURES FEAT_1 FEAT_2 FEAT_3 FEAT_4 FEAT_5 FEAT_6 FEAT_7 FEAT_8 FEAT_9 FEAT_10 FEAT_11 FEAT_12 FEAT_13 FEAT_14

int __init kernelsu_init(void)
{
	pr_info("Initialized on: %s (%s) with ksuver: %s%s\n", UTS_RELEASE, UTS_MACHINE, __stringify(KSU_VERSION), EXTRA_FEATURES);

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_core_init();

	ksu_workqueue = alloc_ordered_workqueue("kernelsu_work_queue", 0);

	ksu_allowlist_init();

	ksu_throne_tracker_init();

#ifdef CONFIG_KSU_KRETPROBES_SUCOMPAT	
	rp_sucompat_init();
#endif
#ifdef CONFIG_KSU_KPROBES_KSUD
	kp_ksud_init();
#endif

	return 0;
}

void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	destroy_workqueue(ksu_workqueue);

}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

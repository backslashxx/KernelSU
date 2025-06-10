#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */

#include "allowlist.h"
#include "core_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"
#include "sucompat.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"

struct cred* ksu_cred;

#ifdef CONFIG_KSU_KPROBES_KSUD
extern void kp_ksud_init();
#endif

extern void ksu_supercalls_init();

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
#if defined(CONFIG_KSU_EXTRAS)
	#define FEAT_3 " +extras"
#else
	#define FEAT_3 ""
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && !defined(CONFIG_KSU_LSM_SECURITY_HOOKS)
	#define FEAT_4 " -lsm_hooks"
#else
	#define FEAT_4 ""
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)) && defined(KSU_HAS_PATH_UMOUNT)
	#define FEAT_5 " +path_umount"
#else
	#define FEAT_5 ""
#endif

#define EXTRA_FEATURES FEAT_1 FEAT_2 FEAT_3 FEAT_4 FEAT_5

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


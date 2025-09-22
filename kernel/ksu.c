#include "kernel_includes.h"

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"
#include "include/uapi/sulog.h"

// includes
#include "include/klog.h"
#include "include/arch.h"
#include "include/ksu.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

// kernel compat
#include "kernel_compat.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"
#include "infra/event_queue.h"
#include "feature/adb_root.h"
#include "feature/kernel_umount.h"
#include "feature/selinux_hide.h"
#include "feature/sucompat.h"
#include "feature/sulog.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "sulog/fd.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

#ifdef CONFIG_KPROBES
#include "downstream/kprobes_common.h"
#endif

#ifdef CONFIG_KALLSYMS
#include "external/chibihash64.h"
#include "downstream/kallsyms_common.h"
#endif

#ifdef CONFIG_ARM64
#include "downstream/arm64_branch_insn.h"
#endif

#include "downstream/slow_avc_audit_defs.h"
#include "downstream/tiny_sulog.h"
#include "downstream/vmap_patch.h"

#ifdef CONFIG_KSU_HOSTSREDIRECT
#include "downstream/ksu_hostsredirect.h"
#endif

// unity build
#include "policy/allowlist.c"
#include "policy/app_profile.c"
#include "policy/feature.c"
#include "manager/apk_sign.c"
#include "manager/pkg_observer.c"
#include "manager/throne_tracker.c"

#include "supercall/perm.c"
#include "supercall/dispatch.c"
#include "supercall/supercall.c"

#include "infra/su_mount_ns.c"
#include "infra/file_wrapper.c"
#include "infra/event_queue.c"

#include "feature/adb_root.c"
#include "feature/kernel_umount.c"
#include "feature/selinux_hide.c"
#include "feature/sucompat.c"
#include "feature/sulog.c"
#include "runtime/ksud.c"

#include "sulog/event.c"
#include "sulog/fd.c"

#include "hook/setuid_hook.c"

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	#include "hook/lsm_hooks_static.c"
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	#include "hook/lsm_hooks_list.c"
	#else
	#include "hook/lsm_hooks_ultralegacy.c"
	#endif
#else
	#include "hook/lsm_hooks_manual.c"
#endif

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef CONFIG_ARM64
	#include "hook/syscall_table_hook_arm64.c"
#elif defined(CONFIG_ARM)
	#include "hook/syscall_table_hook_arm.c"
#endif
#endif /* CONFIG_KSU_TAMPER_SYSCALL_TABLE */

#if defined(CONFIG_KSU_KPROBES_KSUD) && !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#include "hook/kp_ksud.c"
#endif

static int __init kernelsu_init(void)
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
	if (allow_shell)
		pr_alert("shell is allowed at init!");

	ksu_cred = prepare_creds();
	if (!ksu_cred) {
		pr_err("prepare cred failed!\n");
		return -ENOSYS;
	}

	ksu_feature_init();

	ksu_supercalls_init();

	ksu_sucompat_init(); // so the feature is registered

	ksu_kernel_umount_init(); // so the feature is registered

	ksu_selinux_hide_init(); // so the feature is registered

	ksu_core_init();

#if defined(CONFIG_KSU_KPROBES_KSUD) && !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	kp_ksud_init();
#endif

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	ksu_ksud_init();

	ksu_file_wrapper_init();

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	ksu_syscall_table_hook_init();
#endif

	return 0;
}

device_initcall(kernelsu_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

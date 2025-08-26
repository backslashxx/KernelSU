#include "kernel_includes.h"

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"

// includes
#include "include/klog.h"
#include "include/arch.h"
#include "include/ksu.h"

// kernel compat, lite ones
#include "kernel_compat.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"

#include "ksud.h"
#include "core_hook.h"
#include "sucompat.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

// unity build
#include "policy/allowlist.c"
#include "policy/app_profile.c"
#include "policy/feature.c"
#include "manager/apk_sign.c"
#include "manager/throne_tracker.c"
#include "supercall/supercall.c"
#include "infra/su_mount_ns.c"
#include "infra/file_wrapper.c"

#include "ksud.c"	// early boot
#include "core_hook.c"	// lsm
#include "sucompat.c"	// sucomapt, generic hooks

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

// __weak fn's
#include "kernel_compat.c"

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

	return 0;
}

device_initcall(kernelsu_init);

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("weishu");
// MODULE_DESCRIPTION("Android KernelSU");

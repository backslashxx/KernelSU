#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/version.h>

#include "policy/feature.h"
#include "include/klog.h"
#include "runtime/ksud_boot.h"
#include "infra/seccomp_cache.h"

#ifdef CONFIG_ARM64
#include "arm64_branch_insn.h"
#endif

#include "slow_avc_audit_defs.h"

/* changelog
 *
 * 20260430 - intercept ksu sid
 *
 */
// init as disabled by default

void ksu_avc_spoof_enable(void);
void ksu_avc_spoof_disable(void);
static bool ksu_avc_spoof_enabled __read_mostly = false;

static int avc_spoof_feature_get(u64 *value)
{
	*value = ksu_avc_spoof_enabled ? 1 : 0;
	return 0;
}

static int avc_spoof_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_avc_spoof_enabled) {
		pr_info("avc_spoof: no need to change\n");
		return 0;
	}

	ksu_avc_spoof_enabled = enable;

	if (enable)
		ksu_avc_spoof_enable();
	else
		ksu_avc_spoof_disable();

	pr_info("avc_spoof: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_feature_get,
	.set_handler = avc_spoof_feature_set,
};

void ksu_avc_spoof_disable(void)
{
	ksu_avc_spoof_enabled = false;
	pr_info("avc_spoof: slow_avc_audit spoofing disabled!\n");
}

void ksu_avc_spoof_enable(void) 
{
	ksu_avc_spoof_enabled = true;
	pr_info("avc_spoof: slow_avc_audit spoofing enabled!\n");
}

void ksu_avc_spoof_late_init()
{
	ksu_avc_spoof_enable();
}

void __init ksu_avc_spoof_init()
{
	ksu_init_slow_avc_audit_hook();

	if (ksu_register_feature_handler(&avc_spoof_handler))
		pr_err("Failed to register avc spoof feature handler\n");
}

void __exit ksu_avc_spoof_exit()
{
	__builtin_trap();
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}

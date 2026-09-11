#define asmlinkage extern "C"

#define _Bool  char
#define bool  __ksu_bool
#define false __ksu_false
#define true  __ksu_true
#include <linux/types.h>
#include <linux/stddef.h>
#undef false
#undef true
#undef bool
#undef _Bool

// overloaded

asmlinkage void ksu_slow_avc_audit_inline(u32 *tsid);

extern typeof(slow_avc_audit) slow_avc_audit;

void *slow_avc_audit_fn = NULL;

struct selinux_state;

#ifndef __nocfi
#define __nocfi
#endif

static int __nocfi ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

static int __nocfi ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

// now choose what we have
typeof(slow_avc_audit) *ksu_slow_avc_audit_hook = ksu_slow_avc_audit_handler;

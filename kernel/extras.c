#include <linux/security.h>
#include <linux/atomic.h>

#include "klog.h"
#include "ksud.h"
#include "kernel_compat.h"

static u32 su_sid = 0;
static u32 kernel_sid = 0;

// init as disabled by default
static atomic_t disable_spoof = ATOMIC_INIT(1);

int ksu_handle_slow_avc_audit(u32 *tsid)
{
	if (atomic_read(&disable_spoof))
		return 0;

	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (*tsid == su_sid) {
		pr_info("slow_avc_audit: replacing su_sid: %u with kernel_sid: %u\n", su_sid, kernel_sid);
		*tsid = kernel_sid;
	}

	return 0;
}

static int get_sid()
{
	// dont load at all if we cant get sids
	int err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: su_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: su_sid: %u\n", su_sid);

	err = security_secctx_to_secid("u:r:kernel:s0", strlen("u:r:kernel:s0"), &kernel_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: kernel_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: kernel_sid: %u\n", kernel_sid);
	return 0;
}

void avc_spoof_exit(void) 
{
	atomic_set(&disable_spoof, 1);
	pr_info("avc_spoof/init: slow_avc_audit spoofing disabled!\n");
}

void avc_spoof_init(void) 
{
	int ret = get_sid();
	if (ret) {
		pr_info("avc_spoof/init: sid grab fail!\n");
		return;
	}
	
	// once we get the sids, we can now enable the hook handler
	atomic_set(&disable_spoof, 0);
	
	pr_info("avc_spoof/init: slow_avc_audit spoofing enabled!\n");
}

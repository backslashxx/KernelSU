#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h> // signal_struct
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "klog.h" // IWYU pragma: keep


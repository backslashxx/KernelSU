#ifndef __KSU_H_SUPERCALLS
#define __KSU_H_SUPERCALLS

// IOCTL handler types
typedef int (*ksu_ioctl_handler_t)(void __user *arg);
typedef bool (*ksu_perm_check_t)(void);

// IOCTL command mapping
struct ksu_ioctl_cmd_map {
	unsigned int cmd;
	const char *name;
	ksu_ioctl_handler_t handler;
	ksu_perm_check_t perm_check; // Permission check function
};

// Install KSU fd to current process
int ksu_install_fd(void);

void ksu_supercalls_init(void);
void ksu_supercalls_exit(void);

// extensions
#define CHANGE_MANAGER_UID 10006
#define KSU_UMOUNT_GETSIZE 107   // get list size // shit is u8 we cant fit 10k+ on it
#define KSU_UMOUNT_GETLIST 108   // get list
#define GET_SULOG_DUMP 10009     // get sulog dump, max, last 100 escalations
#define GET_SULOG_DUMP_V2 10010     // get sulog dump, timestamped, last 250 escalations
#define CHANGE_KSUVER 10011     // change ksu version
#define CHANGE_SPOOF_UNAME 10012 // spoof uname
#define CHANGE_KSUFLAGS 10013     // change ksuflags, do the bit calc on your own, 0 + 1 + 2 + 4 + 8 blah


#endif // __KSU_H_SUPERCALLS

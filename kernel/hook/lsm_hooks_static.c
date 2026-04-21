#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

// security.c hijack for 6.8+
// however this requires kallsyms
// TODO: refine, try to lessen kallsyms dependence further

/*

https://godbolt.org/z/Eh8vfrdns

__attribute__((noinline)) 
void target_fn() {
    volatile int x = 0;
}

int main() {
    target_fn();
    return 0;
}

target_fn:
        sub     sp, sp, #16
        str     wzr, [sp, 12]
        nop
        add     sp, sp, 16
        ret
main:
        stp     x29, x30, [sp, -16]!
        mov     x29, sp
        bl      target_fn   << hunt for this!
        mov     w0, 0
        ldp     x29, x30, [sp], 16
        ret
*/

// bl is 94 ~ 97
// so we can do this like on x86 where 74 xx to 74 yy
// bl is call+ret equivalent on x86 though

// this is EXPORT_SYMBOL, this is stabler.
extern int vfs_rename(struct renamedata *rd);
static int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);

	return ret;
}

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

// bprm
extern int security_bprm_check(struct linux_binprm *bprm);
static int ksu_bprm_check(struct linux_binprm *bprm)
{
	return security_bprm_check(bprm);
}

// vfs_read, as security_file_permission is a bit spotty to hook!
extern ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
static ssize_t ksu_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);
#endif
#endif

	return vfs_read(file, buf, count, pos);
}

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	extern int do_renameat2(int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags);
	target_callsite = (uintptr_t)&do_renameat2;
	symbol_addr = (uintptr_t)&vfs_rename;
#ifdef CONFIG_KPROBES
	target_callsite = kp_cfi_kallsyms_lookup_name("do_renameat2");
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_rename");
#endif
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_rename);
	pr_info("lsm_hijack: vfs_rename: ret %d \n", ret);
	if (!ret)
		goto rename_hook_done;

	target_callsite = (uintptr_t)&vfs_rename;
	symbol_addr = (uintptr_t)&security_inode_rename;
#ifdef CONFIG_KPROBES
	target_callsite = kp_cfi_kallsyms_lookup_name("vfs_rename");
	symbol_addr = kp_cfi_kallsyms_lookup_name("security_inode_rename");
#endif
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_inode_rename);
	pr_info("lsm_hijack: security_inode_rename: ret %d \n", ret);

rename_hook_done:
	;
	extern long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
	target_callsite = (uintptr_t)&__sys_setresuid;
	symbol_addr = (uintptr_t)&security_task_fix_setuid;
#ifdef CONFIG_KPROBES
	target_callsite = kp_cfi_kallsyms_lookup_name("__sys_setresuid");
	symbol_addr = kp_cfi_kallsyms_lookup_name("security_task_fix_setuid");
#endif
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);

	target_callsite = kallsyms_lookup_name("bprm_execve");
	symbol_addr = (uintptr_t)&security_bprm_check;
#ifdef CONFIG_KPROBES
	target_callsite = kp_cfi_kallsyms_lookup_name("bprm_execve");
	symbol_addr = kp_cfi_kallsyms_lookup_name("security_bprm_check");
#endif
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_bprm_check);
	pr_info("lsm_hijack: security_bprm_check: ret %d \n", ret);

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	extern ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count);
	target_callsite = (uintptr_t)&ksys_read;
	symbol_addr = (uintptr_t)&vfs_read;
#ifdef CONFIG_KPROBES
	target_callsite = kp_cfi_kallsyms_lookup_name("ksys_read");
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_read");
#endif
	ret = arm64_bl_patch(target_callsite, 64 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_read);
	pr_info("lsm_hijack: ksys_read: ret %d \n", ret);
#endif

}

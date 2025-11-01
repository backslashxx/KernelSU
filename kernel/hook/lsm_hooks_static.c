#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KPROBES)
#error "automated LSM hooking on 6.8+ requires kprobes!"
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
static __nocfi int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);

	return ret;
}

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static __nocfi int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

// bprm
extern int security_bprm_check(struct linux_binprm *bprm);
static __nocfi int ksu_bprm_check(struct linux_binprm *bprm)
{
	return security_bprm_check(bprm);
}

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

// rename
	target_callsite = kp_cfi_kallsyms_lookup_name("do_renameat2");
	symbol_addr = kp_cfi_kallsyms_lookup_name("vfs_rename");
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_rename);
	pr_info("lsm_hijack: vfs_rename: ret %d \n", ret);
	if (ret) {
		target_callsite = kp_cfi_kallsyms_lookup_name("vfs_rename");
		symbol_addr = kp_cfi_kallsyms_lookup_name("security_inode_rename");
		ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_inode_rename);
		pr_info("lsm_hijack: security_inode_rename: ret %d \n", ret);
	}

// setuid

	target_callsite = kp_cfi_kallsyms_lookup_name("__sys_setresuid");
	symbol_addr = kp_cfi_kallsyms_lookup_name("security_task_fix_setuid");
	ret = arm64_bl_patch(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);

	target_callsite = kp_cfi_kallsyms_lookup_name("bprm_execve");
	symbol_addr = kp_cfi_kallsyms_lookup_name("security_bprm_check");
	ret = arm64_bl_patch(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_bprm_check);
	pr_info("lsm_hijack: security_bprm_check: ret %d \n", ret);

}

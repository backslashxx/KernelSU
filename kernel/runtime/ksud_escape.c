#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
__attribute__((cold)) static noinline void sys_execve_escape_ksud_internal(void *filename)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (ksu_boot_completed) {
		pr_info("sys_execve: boot completed, remove escape branch\n");
		static_branch_disable(&ksud_escape_key);
		smp_mb();
		return;
	}
#endif

	// see if its init
	if (!is_init(current_cred()))
		return;

	const char ksud_path[] = KSUD_PATH;
	char path[sizeof(ksud_path)];

	// filename is void * char __user *
	const char __user **filename_user = (const char __user **)filename;

	// see if its trying to execute ksud
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return;

	if (likely(!!memcmp(ksud_path, path, sizeof(path))))
		return;

	pr_info("sys_execve: escape init executing %s with pid: %d\n", path, current->pid);
	escape_to_root_forced(); // give this context all permissions
	return;
}

__attribute__((cold)) static noinline void kernel_execve_escape_ksud_internal(void *filename)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (ksu_boot_completed) {
		pr_info("kernel_execve: boot completed, remove escape branch\n");
		static_branch_disable(&ksud_escape_key);
		smp_mb();
		return;
	}
#endif
	// filename is void **
	void **filename_ptr = (void **)filename;

	// see if its init
	if (!is_init(current_cred()))
		return;

	if (!*filename_ptr)
		return;

	if (likely(!!memcmp(*filename_ptr, KSUD_PATH, sizeof(KSUD_PATH))))
		return;

	pr_info("kernel_execve: escape init executing %s with pid: %d\n", *(const char **)filename_ptr, current->pid);
	escape_to_root_forced(); // give this context all permissions
	return;
}
#endif

// UL bprm_set_creds handling
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static uintptr_t selinux_ops_addr;
static int (*orig_bprm_set_creds)(struct linux_binprm *bprm) = NULL;

static void ksu_unregister_bprm_set_creds(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (orig_bprm_set_creds) {
		pr_info("%s: restoring: bprm_set_creds 0x%lx -> 0x%lx\n", __func__, (long)ops->bprm_set_creds, (long)orig_bprm_set_creds);
		ops->bprm_set_creds = orig_bprm_set_creds;
	}
}

static int hook_bprm_set_creds(struct linux_binprm *bprm)
{
	if (ksu_boot_completed)
		goto unreg_bprm_set_creds;

	if (!is_init(current_cred()))
		goto bprm_set_creds;

	if (!bprm->filename)
		goto bprm_set_creds;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto bprm_set_creds;

	struct task_security_struct *old_tsec = current_security();
	struct task_security_struct *new_tsec = bprm->cred->security;

	if (!(old_tsec->exec_sid))
		goto bprm_set_creds;

	// we copy what selinux was doing
	// ref: https://elixir.bootlin.com/linux/v3.0.101/source/security/selinux/hooks.c#L1971

	/* Default to the current task SID. */
	new_tsec->sid = old_tsec->sid;
	new_tsec->osid = old_tsec->sid;

	/* Reset fs, key, and sock SIDs on execve. */
	new_tsec->create_sid = 0;
	new_tsec->keycreate_sid = 0;
	new_tsec->sockcreate_sid = 0;

	new_tsec->sid = old_tsec->exec_sid;
	/* Reset exec SID on execve. */
	new_tsec->exec_sid = 0;

	pr_info("bprm_set_creds: allow init executing %s with pid: %d\n", bprm->filename, current->pid);
	return 0;

unreg_bprm_set_creds:
	stop_machine(ksu_unregister_bprm_set_creds, NULL, NULL);

bprm_set_creds:
	return orig_bprm_set_creds(bprm);


}
#endif

static void ksud_escape_init() { }
static void ksud_escape_exit() { }

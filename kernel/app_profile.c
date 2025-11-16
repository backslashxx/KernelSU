#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 7, 0)
static struct group_info root_groups = { .usage = REFCOUNT_INIT(2) };
#else
static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };
#endif

static void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

static void disable_seccomp()
{

// for < 5.9 lets have free_task do it for us (put_seccomp_filter)
// we risk a double free / double decrement which isn't safe on old kernels
// I'm not even sure if this thing is needed on newer kernels
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	struct task_struct *fake;

	fake = kmalloc(sizeof(*fake), GFP_KERNEL);
	if (!fake) {
		pr_warn("failed to alloc fake task_struct\n");
		return;
	}
#endif

	// Refer to kernel/seccomp.c: seccomp_set_mode_strict
	// When disabling Seccomp, ensure that current->sighand->siglock is held during the operation.
	spin_lock_irq(&current->sighand->siglock);

	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	memcpy(fake, current, sizeof(*fake));
	atomic_set(&current->seccomp.filter_count, 0);
#endif

	current->seccomp.mode = 0;
	current->seccomp.filter = NULL;

	spin_unlock_irq(&current->sighand->siglock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
	// https://github.com/torvalds/linux/commit/bfafe5efa9754ebc991750da0bcca2a6694f3ed3#diff-45eb79a57536d8eccfc1436932f093eb5c0b60d9361c39edb46581ad313e8987R576-R577
	fake->flags |= PF_EXITING;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	// https://github.com/torvalds/linux/commit/0d8315dddd2899f519fe1ca3d4d5cdaf44ea421e#diff-45eb79a57536d8eccfc1436932f093eb5c0b60d9361c39edb46581ad313e8987R556-R558
	fake->sighand = NULL;
#endif

	seccomp_filter_release(fake);
	kfree(fake);
#endif // 5.9
}

static int escape_to_root(bool is_forced)
{
	int ret = 0;
	struct cred *cred;
	struct root_profile profile;
	struct user_struct *new_user;

	cred = prepare_creds();
	if (!cred) {
		pr_warn("prepare_creds failed!\n");
		return -ENOMEM;
	}

	if (!is_forced && cred->euid.val == 0) {
		pr_warn("Already root, don't escape!\n");
		goto out_abort_creds;
	}

	ksu_get_root_profile(cred->uid.val, &profile);

	cred->uid.val = profile.uid;
	cred->suid.val = profile.uid;
	cred->euid.val = profile.uid;
	cred->fsuid.val = profile.uid;

	cred->gid.val = profile.gid;
	cred->fsgid.val = profile.gid;
	cred->sgid.val = profile.gid;
	cred->egid.val = profile.gid;
	cred->securebits = 0;

	BUILD_BUG_ON(sizeof(profile.capabilities.effective) != sizeof(kernel_cap_t));

	/*
	 * Mirror the kernel set*uid path: update cred->user first, then
	 * cred->ucounts, before commit_creds(). commit_creds() moves
	 * RLIMIT_NPROC accounting based on cred->user; if uid changes while
	 * user/ucounts stay stale, the old charge can remain pinned to the
	 * previous UID.
	 * See kernel/sys.c:set_user() and kernel/cred.c:set_cred_ucounts() /
	 * commit_creds():
	 * https://github.com/torvalds/linux/blob/v5.14/kernel/sys.c
	 * https://github.com/torvalds/linux/blob/v5.14/kernel/cred.c
	 */
	new_user = alloc_uid(cred->uid);
	if (!new_user) {
		ret = -ENOMEM;
		goto out_abort_creds;
	}

	free_uid(cred->user);
	cred->user = new_user;

	// v5.14+ added cred->ucounts, so we must refresh it after changing uid/user:
	// https://github.com/torvalds/linux/commit/905ae01c4ae2ae3df05bb141801b1db4b7d83c61#diff-ff6060da281bd9ef3f24e17b77a9b0b5b2ed2d7208bb69b29107bee69732bd31
	// on older kernels, per-UID process accounting lives in user_struct.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (set_cred_ucounts(cred)) {
		goto out_abort_creds;
	}
#endif

	// setup capabilities
	// we need CAP_DAC_READ_SEARCH becuase `/data/adb/ksud` is not accessible for non root process
	// we add it here but don't add it to cap_inhertiable, it would be dropped automaticly after exec!
	u64 cap_for_ksud = profile.capabilities.effective | CAP_DAC_READ_SEARCH;
	memcpy(&cred->cap_effective, &cap_for_ksud, sizeof(cred->cap_effective));
	memcpy(&cred->cap_permitted, &profile.capabilities.effective, sizeof(cred->cap_permitted));
	memcpy(&cred->cap_bset, &profile.capabilities.effective, sizeof(cred->cap_bset));

	setup_groups(&profile, cred);
	setup_selinux(profile.selinux_domain, cred);

	commit_creds(cred);

	disable_seccomp();
	
	setup_mount_ns(profile.namespaces);
	return 0;

out_abort_creds:
	abort_creds(cred);
	return ret;
}

int escape_with_root_profile(void)
{
	return escape_to_root(false);
}

void escape_to_root_forced(void)
{
	// I'm not really sure which permissions are needed
	// its just escape to root but bypasses cred check
	// which we likely already have on contexts where this will be used.
	escape_to_root(true);
}

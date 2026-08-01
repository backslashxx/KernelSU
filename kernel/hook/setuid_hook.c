static __always_inline void ksu_handle_setresuid_3(uid_t new_uid, uid_t old_uid, const struct cred *old)
{
	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

	// Handle kernel umount
	ksu_handle_umount(new_uid, old_uid, old);
	return;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	return;
}

static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);
	
	ksu_handle_setresuid_3(new_uid, old_uid, old);
}

static __always_inline void ksu_handle_setresuid_current(uid_t new_uid, uid_t old_uid)
{
	ksu_handle_setresuid_3(new_uid, old_uid, current_cred());
}

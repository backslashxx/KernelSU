#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, 
	const char *type_page, unsigned long flags, void *data_page)
{
	// 384 is enough 
	char buf[384] = {0};

	// -1 on the size as implicit null termination
	// as we zero init the thing
	char *realpath = d_path(path, buf, sizeof(buf) - 1);
	if (!(realpath && realpath != buf)) 
		return -ENOENT;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	long ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_umount(struct path *path, int flags)
{
	char buf[256] = {0};
	int ret;

	// -1 on the size as implicit null termination
	// as we zero init the thing
	char *usermnt = d_path(path, buf, sizeof(buf) - 1);
	if (!(usermnt && usermnt != buf)) {
		ret = -ENOENT;
		goto out;
	}

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = ksys_umount((char __user *)usermnt, flags);
#else
	ret = (int)sys_umount((char __user *)usermnt, flags);
#endif

	set_fs(old_fs);

	// release ref here! user_path_at increases it
	// then only cleans for itself
out:
	path_put(path); 
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst,
			(__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

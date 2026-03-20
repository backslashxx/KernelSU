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


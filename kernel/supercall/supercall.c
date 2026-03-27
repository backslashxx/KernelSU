static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}

void ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
}

void ksu_supercalls_exit(void) { }

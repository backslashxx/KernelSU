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

static inline int ksu_handle_fd_request(void __user *arg4)
{
	int fd = ksu_install_fd();
	pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(arg4, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	return 0;
}

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

	// when ternary on fmt?
	// cold syscall, we can splurge xD
	if (magic2 == KSU_INSTALL_MAGIC2)
		pr_info("sys_reboot: magic: 0x%x id: 0x%x pid: %d comm: %s \n", magic1, magic2, current->pid, current->comm);
	else
		pr_info("sys_reboot: magic: 0x%x id: %d pid: %d pid: %s \n", magic1, magic2, current->pid, current->comm);

	// arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	// downstream: dereference arg as arg4 so we can be inline to upstream
	void __user *arg4 = (void __user *)*arg;

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		return ksu_handle_fd_request(arg4);
	}

	// grab a copy as we write the pointer on the pointer
	// u64 reply = (u64)*arg;	
	// extensions

	return 0;
}

void __init ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
}

void __exit ksu_supercalls_exit(void) { }

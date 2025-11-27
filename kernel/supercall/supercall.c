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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
	int fd = ksu_install_fd();
	pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	kfree(tw);
}

static int ksu_handle_fd_request(void __user *arg4)
{
	struct ksu_install_fd_tw *tw;

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->outp = (int __user *)arg4;
	tw->cb.func = ksu_install_fd_tw_func;

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("install fd add task_work failed\n");
	}

	return 0;
}
#else
static int ksu_handle_fd_request(void __user *arg4)
{
	int fd = ksu_install_fd();
	pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(arg4, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	return 0;
}
#endif

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{

	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1, magic2);

	// arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	// downstream: dereference arg as arg4 so we can be inline to upstream
	void __user *arg4 = (void __user *)*arg;

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		return ksu_handle_fd_request(arg4);
	}

	// only root is allowed for these commands
	if (current_uid().val != 0)
		return 0;
	
	// extensions
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}

	return 0;
}

void ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
}

void ksu_supercalls_exit(void) { }

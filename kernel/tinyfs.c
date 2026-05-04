#include <linux/fs.h>
#include <linux/mount.h>

static const char tinysu_bin[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00
};

static ssize_t tinyfs_read(struct file *f, char __user *buf, size_t len, loff_t *ppos) {
	return simple_read_from_buffer(buf, len, ppos, tinysu_bin, sizeof(tinysu_bin));
}

static const struct file_operations tinyfs_su_fops = {
	.read = tinyfs_read,
	.llseek = generic_file_llseek,
};

static struct dentry *tinyfs_mount_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags) {
	
	if (!!strcmp(dentry->d_name.name, "su"))
		return ERR_PTR(-ENOENT);	
	
	struct inode *inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = 2;
	inode->i_mode = S_IFREG | 0755;
	inode->i_fop = &tinyfs_su_fops;
	inode->i_size = sizeof(tinysu_bin);

	d_add(dentry, inode);
	return NULL;
}

static const struct inode_operations tinyfs_dir_iops = { .lookup = tinyfs_mount_lookup };

static int tinyfs_fill_super(struct super_block *sb, void *data, int silent) {

	struct inode *root = new_inode(sb);
	if (!root)
		return -ENOMEM;

	root->i_ino = 1;
	root->i_mode = S_IFDIR | 0755;
	root->i_op = &tinyfs_dir_iops;
	root->i_fop = &simple_dir_operations;
	sb->s_root = d_make_root(root);

	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

static struct dentry *tinyfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data) {
	return mount_nodev(fs_type, flags, data, tinyfs_fill_super);
}

static struct file_system_type tinyfs_type = {
	.name = "tinyfs",
	.mount = tinyfs_mount,
	.kill_sb = kill_anon_super,
};

void tinyfs_init()
{
	register_filesystem(&tinyfs_type);
}

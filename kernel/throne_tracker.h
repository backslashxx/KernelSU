#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne();

/*
 * small helper to check if lock is held
 * false - file is stable
 * true - file is being deleted/renamed
 * possibly optional
 *
 */
static bool is_lock_held(const char *path) 
{
	struct path kpath;

	// kern_path returns 0 on success
	if (kern_path(path, 0, &kpath))
		return true;

	// just being defensive
	if (!kpath.dentry) {
		path_put(&kpath);
		return true;
	}

	if (!spin_trylock(&kpath.dentry->d_lock)) {
		pr_info("%s: lock held, bail out!\n", __func__);
		path_put(&kpath);
		return true;
	}
	// we hold it ourselves here!

	spin_unlock(&kpath.dentry->d_lock);
	path_put(&kpath);
	return false;
}

#endif

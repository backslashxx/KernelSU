bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	kuid_t current_uid = current_uid();
	return ksu_get_uid_t(current_uid) == 0;
}

bool manager_or_root(void)
{
	kuid_t current_uid = current_uid();
	return ksu_get_uid_t(current_uid) == 0 || is_manager();
}

bool always_allow(void)
{
	return true;
}

bool allowed_for_su(void)
{
	kuid_t current_uid = current_uid();
	return is_manager() || ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid));
}

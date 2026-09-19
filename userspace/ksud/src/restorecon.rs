use crate::defs;
use anyhow::Result;
use jwalk::{Parallelism::Serial, WalkDir};
use std::path::Path;

use anyhow::{Context, Ok};
use extattr::{Flags as XattrFlags, lsetxattr};

pub const SYSTEM_CON: &str = "u:object_r:system_file:s0";
pub const KSU_CON: &str = "u:object_r:ksu_file:s0";
pub const UNLABEL_CON: &str = "u:object_r:unlabeled:s0";

const SELINUX_XATTR: &str = "security.selinux";

fn has_selinux_mount(mounts: &str) -> bool {
    mounts
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some("selinuxfs"))
}

fn selinux_enabled() -> Result<bool> {
    // A mountpoint directory can exist even when SELinux is disabled. Check
    // the filesystem type, including legacy or nonstandard mount locations.
    // Do not cache this: init may mount selinuxfs later during boot.
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .context("Failed to determine whether SELinux is enabled")?;
    Ok(has_selinux_mount(&mounts))
}

pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    // Disabled SELinux has no labels to restore. Permissive SELinux still
    // needs labels, and all labeling errors must remain fatal when enabled.
    if !selinux_enabled()? {
        return Ok(());
    }

    lsetxattr(&path, SELINUX_XATTR, con, XattrFlags::empty()).with_context(|| {
        format!(
            "Failed to change SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    Ok(())
}

pub fn lgetfilecon<P: AsRef<Path>>(path: P) -> Result<String> {
    let con = extattr::lgetxattr(&path, SELINUX_XATTR).with_context(|| {
        format!(
            "Failed to get SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    let con = String::from_utf8_lossy(&con);
    Ok(con.to_string())
}

pub fn setsyscon<P: AsRef<Path>>(path: P) -> Result<()> {
    lsetfilecon(path, SYSTEM_CON)
}

pub fn restore_syscon<P: AsRef<Path>>(dir: P) -> Result<()> {
    if !selinux_enabled()? {
        return Ok(());
    }

    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            setsyscon(&path)?;
        }
    }
    Ok(())
}

fn restore_syscon_if_unlabeled<P: AsRef<Path>>(dir: P) -> Result<()> {
    for dir_entry in WalkDir::new(dir).parallelism(Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path())
            && let anyhow::Result::Ok(con) = lgetfilecon(&path)
            && (con == UNLABEL_CON || con.is_empty())
        {
            lsetfilecon(&path, SYSTEM_CON)?;
        }
    }
    Ok(())
}

pub fn restorecon() -> Result<()> {
    if !selinux_enabled()? {
        return Ok(());
    }

    lsetfilecon(defs::DAEMON_PATH, KSU_CON)?;
    restore_syscon_if_unlabeled(defs::MODULE_DIR)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::has_selinux_mount;

    #[test]
    fn detects_selinux_by_filesystem_type() {
        for mountpoint in ["/sys/fs/selinux", "/selinux", "/custom/selinux"] {
            let mounts = format!("none {mountpoint} selinuxfs rw,relatime 0 0\n");
            assert!(has_selinux_mount(&mounts));
        }
    }

    #[test]
    fn mountpoint_name_does_not_imply_selinux_is_enabled() {
        assert!(!has_selinux_mount(""));
        assert!(!has_selinux_mount(
            "sysfs /sys sysfs rw 0 0\nnone /sys/fs/selinux tmpfs rw 0 0\n"
        ));
    }
}

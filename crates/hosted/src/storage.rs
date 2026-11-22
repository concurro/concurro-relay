//! Durable private files shared by the registry and claim journal.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::Result;

/// Append a suffix without changing any existing extension.
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// Find the directory to sync even when a file was specified by a bare name.
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Atomically replace a private file and make its new contents durable.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = parent(path);
    fs::create_dir_all(parent)?;
    let temp = with_suffix(path, ".tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Append one complete journal record and sync it before returning.
pub fn append(path: &Path, record: &[u8]) -> Result<()> {
    let parent = parent(path);
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(record)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

//! Generated public circuits shared between sessions, bounded in number.
//!
//! A global `.lock` covers the short steps that open, lease and remove
//! entries. Each entry's `<name>.lock` is held exclusively while generating it
//! and shared while a session uses it; eviction removes only entries nobody
//! holds, least recently used first.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    process::Command,
    task,
    time::{self, Duration},
};

use super::{Runtime, circuit_workspace};

/// Pause between attempts on a lock another process holds.
const POLL: Duration = Duration::from_millis(20);

/// A cached circuit, kept from eviction while held.
#[derive(Debug)]
pub struct Circuit {
    /// The circuit file.
    path: PathBuf,
    /// Shared lock on the entry.
    _lease: File,
}

impl Circuit {
    /// The circuit file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// What a lease attempt found.
enum Lease {
    /// The entry exists and is now leased.
    Ready(Circuit),
    /// Another session is generating the entry.
    Busy,
    /// The entry is missing; the lock is held exclusively to generate it.
    Missing(File),
}

/// Return the prefix circuit for these public lengths, generating it once
/// across sessions and evicting the least recently used beyond the budget.
pub async fn prefix_circuit(
    runtime: &Runtime,
    route: &str,
    partial_len: usize,
    offset: usize,
    credential_len: usize,
) -> Result<Circuit> {
    let cache = runtime.circuit_cache.clone();
    let name = format!("{route}-{partial_len}-{offset}-{credential_len}.txt");
    let budget = runtime
        .limits
        .circuit_cache_mib
        .get()
        .saturating_mul(1 << 20);
    let checked = cache.clone();
    task::spawn_blocking(move || private_directory(&checked)).await??;
    loop {
        // Each blocking step owns the global lock, so it is released only
        // once the step ends, even if this future is dropped.
        let global = exclusive(&cache).await?;
        let (directory, entry) = (cache.clone(), name.clone());
        let lease = task::spawn_blocking(move || {
            let _global = global;
            lease(&directory, &entry)
        })
        .await??;
        let lock = match lease {
            Lease::Ready(circuit) => return Ok(circuit),
            Lease::Busy => {
                time::sleep(POLL).await;
                continue;
            }
            Lease::Missing(lock) => lock,
        };
        generate(runtime, &name, [partial_len, offset, credential_len]).await?;
        let global = exclusive(&cache).await?;
        let (directory, entry) = (cache.clone(), name.clone());
        return task::spawn_blocking(move || {
            let _global = global;
            publish(&directory, &entry, lock, budget)
        })
        .await?;
    }
}

/// Create the cache directory, or accept an existing one only if it is a
/// directory this user owns, removing write access for anyone else.
fn private_directory(path: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let shown = path.display();
    ensure!(
        metadata.is_dir(),
        "circuit cache {shown} is not a directory"
    );
    // SAFETY: geteuid has no preconditions.
    let user = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == user,
        "circuit cache {shown} belongs to another user"
    );
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o022))?;
    }
    Ok(())
}

/// Wait for the cache's global lock.
async fn exclusive(cache: &Path) -> Result<File> {
    let path = cache.join(".lock");
    let file = task::spawn_blocking(move || open_lock(&path)).await??;
    while !try_lock(&file, libc::LOCK_EX)? {
        time::sleep(POLL).await;
    }
    Ok(file)
}

/// Open or create a lock file.
fn open_lock(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
}

/// Apply `operation` to `file` without blocking; false while another holds it.
fn try_lock(file: &File, operation: libc::c_int) -> io::Result<bool> {
    // SAFETY: flock receives a live descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

/// The lock file of entry `name`.
fn lock_path(cache: &Path, name: &str) -> PathBuf {
    cache.join(format!("{name}.lock"))
}

/// Lease entry `name`, under the global lock.
fn lease(cache: &Path, name: &str) -> Result<Lease> {
    let lock = open_lock(&lock_path(cache, name))?;
    if !try_lock(&lock, libc::LOCK_SH)? {
        return Ok(Lease::Busy);
    }
    let path = cache.join(name);
    if path.try_exists()? {
        lock.set_modified(SystemTime::now())?;
        return Ok(Lease::Ready(Circuit { path, _lease: lock }));
    }
    // Nobody leases a missing entry, and taking a lock needs the global one.
    if !try_lock(&lock, libc::LOCK_EX)? {
        return Ok(Lease::Busy);
    }
    Ok(Lease::Missing(lock))
}

/// Removes an unpublished generator output.
struct Unpublished(PathBuf);

impl Drop for Unpublished {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Generate entry `name` from its public lengths, under its exclusive lock.
async fn generate(runtime: &Runtime, name: &str, lengths: [usize; 3]) -> Result<()> {
    let cache = &runtime.circuit_cache;
    let path = cache.join(name);
    let temporary = Unpublished(path.with_extension("tmp"));
    let _ = tokio::fs::remove_file(&temporary.0).await;
    let work = circuit_workspace(runtime, &cache.join("workspace").join(name)).await?;
    let mut child = Command::new(runtime.distefano("build/HandoffPrefix"))
        .arg("generate")
        .args(lengths.map(|length| length.to_string()))
        .arg(&temporary.0)
        .current_dir(work)
        .kill_on_drop(true)
        .spawn()?;
    let status = match time::timeout(
        runtime.benchmark_timeout.max(Duration::from_secs(240)),
        child.wait(),
    )
    .await
    {
        Ok(status) => status?,
        Err(_) => {
            child.start_kill()?;
            child.wait().await?;
            bail!("prefix circuit generation timeout");
        }
    };
    ensure!(
        status.success(),
        "prefix circuit generation failed: {status}"
    );
    tokio::fs::rename(&temporary.0, &path).await?;
    Ok(())
}

/// Lease freshly generated entry `name` and evict beyond `budget` bytes,
/// under the global lock.
fn publish(cache: &Path, name: &str, lock: File, budget: u64) -> Result<Circuit> {
    lock.set_modified(SystemTime::now())?;
    // Nobody else takes this lock without the global one.
    ensure!(
        try_lock(&lock, libc::LOCK_SH)?,
        "circuit cache lease conflict"
    );
    evict(cache, name, budget)?;
    Ok(Circuit {
        path: cache.join(name),
        _lease: lock,
    })
}

/// Remove abandoned entries, and the least recently used published ones
/// beyond `budget` bytes, skipping `keep` and any entry in use.
fn evict(cache: &Path, keep: &str, budget: u64) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(cache)? {
        let entry = entry?;
        let file = entry.file_name();
        let Some(name) = file.to_str().and_then(|file| file.strip_suffix(".lock")) else {
            continue;
        };
        if name.is_empty() || name == keep {
            continue;
        }
        let used = entry.metadata()?.modified()?;
        entries.push((used, name.to_owned(), size(&cache.join(name))?));
    }
    entries.sort();
    // The kept entry counts too.
    let mut total = size(&cache.join(keep))?.unwrap_or(0)
        + entries.iter().filter_map(|entry| entry.2).sum::<u64>();
    for (_, name, published) in entries {
        if published.is_some() && total <= budget {
            continue;
        }
        let lock = open_lock(&lock_path(cache, &name))?;
        if !try_lock(&lock, libc::LOCK_EX)? {
            continue;
        }
        remove(&cache.join(&name))?;
        remove(&cache.join(&name).with_extension("tmp"))?;
        match fs::remove_dir_all(cache.join("workspace").join(&name)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(error).context("remove circuit workspace");
            }
            _ => {}
        }
        remove(&lock_path(cache, &name))?;
        total -= published.unwrap_or(0);
    }
    Ok(())
}

/// The size of a published circuit, if there is one.
fn size(path: &Path) -> Result<Option<u64>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

/// Remove a file that may not exist.
fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(error).with_context(|| format!("remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

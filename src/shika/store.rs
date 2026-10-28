use anyhow::{Result, bail};

// Independent item: never read, write or delete the Loomex auth item.
const SERVICE: &str = "app.shika.loomex.runner.v1";
const ACCOUNT: &str = "protected-state";

pub(super) trait Store: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, bytes: &[u8]) -> Result<()>;
}
pub(super) struct NativeStore;

/// The Keychain item is per OS user, so the lock cannot depend on an ambient
/// HOME or an overridable runner directory. Keep the file open for the whole
/// read, remote request and final protected-state write.
#[cfg(unix)]
fn owner_directory() -> Result<std::path::PathBuf> {
    use anyhow::ensure;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    };
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 65536];
    let mut found = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    ensure!(
        status == 0 && !found.is_null() && !record.pw_dir.is_null(),
        "SHIKA_STORE_UNAVAILABLE"
    );
    let home = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }.to_bytes(),
    ));
    ensure!(home.is_absolute(), "SHIKA_STORE_UNAVAILABLE");
    let meta =
        std::fs::symlink_metadata(&home).map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o022 == 0,
        "SHIKA_STORE_UNAVAILABLE"
    );
    let directory = home.join(".shika-runner-credential-owner");
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => bail!("SHIKA_STORE_UNAVAILABLE"),
    }
    let meta = std::fs::symlink_metadata(&directory)
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "SHIKA_STORE_UNAVAILABLE"
    );
    Ok(directory)
}
#[cfg(unix)]
pub(super) fn acquire_owner() -> Result<std::fs::File> {
    use anyhow::ensure;
    use fs2::FileExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let directory = owner_directory()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("owner.lock"))
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    let meta = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
            && meta.nlink() == 1,
        "SHIKA_STORE_UNAVAILABLE"
    );
    file.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_BUSY"))?;
    Ok(file)
}

// Called while holding acquire_owner. The marker is nonsecret and never
// removed during disconnect. Its presence without protected state fences
// automatic device generation.
#[cfg(unix)]
pub(super) fn enrollment_marker() -> Result<bool> {
    use anyhow::ensure;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let path = owner_directory()?.join("enrollment.marker");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => bail!("SHIKA_STORE_UNAVAILABLE"),
    };
    let meta = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
            && meta.nlink() == 1
            && meta.len() == 0,
        "SHIKA_STORE_UNAVAILABLE"
    );
    Ok(true)
}
#[cfg(unix)]
pub(super) fn ensure_enrollment_marker() -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = owner_directory()?;
    if enrollment_marker()? {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("enrollment.marker"))
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    file.sync_all()
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    std::fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn options() -> security_framework::passwords::PasswordOptions {
    use core_foundation::{base::TCFType, string::CFString};
    use security_framework_sys::item::kSecUseAuthenticationUI;
    unsafe extern "C" {
        static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
    }
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
    #[allow(deprecated)]
    options.query.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
            CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
        )
    });
    options
}
#[cfg(target_os = "macos")]
impl Store for NativeStore {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        match security_framework::passwords::generic_password(options()) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(_) => bail!("SHIKA_STORE_UNAVAILABLE"),
        }
    }
    fn save(&self, bytes: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password_options(bytes, options())
            .map_err(|_| anyhow::anyhow!("SHIKA_STORE_UNAVAILABLE"))
    }
}
#[cfg(not(target_os = "macos"))]
impl Store for NativeStore {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        bail!("SHIKA_STORE_UNAVAILABLE")
    }
    fn save(&self, _: &[u8]) -> Result<()> {
        bail!("SHIKA_STORE_UNAVAILABLE")
    }
}
